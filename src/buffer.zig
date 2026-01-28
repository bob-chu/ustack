const std = @import("std");
const header = @import("header.zig");
const Allocator = std.mem.Allocator;

/// Cluster is a ref-counted fixed-size buffer.
pub const Cluster = struct {
    ref_count: usize,
    pool: *ClusterPool,
    next: ?*Cluster = null,
    data: [header.ClusterSize]u8 align(64),

    pub fn acquire(self: *Cluster) void {
        self.ref_count += 1;
    }

    pub fn release(self: *Cluster) void {
        self.ref_count -= 1;
        if (self.ref_count == 0) {
            self.pool.returnToPool(self);
        }
    }
};

/// ClusterView is a view into a Cluster.
pub const ClusterView = struct {
    cluster: ?*Cluster,
    view: []u8,
};

/// ClusterPool manages a pool of Clusters.
pub const ClusterPool = struct {
    allocator: Allocator,
    free_list: ?*Cluster = null,
    count: usize = 0,

    pub fn init(allocator: Allocator) ClusterPool {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ClusterPool) void {
        var it = self.free_list;
        while (it) |c| {
            const next = c.next;
            self.allocator.destroy(c);
            it = next;
        }
        self.free_list = null;
    }

    pub fn acquire(self: *ClusterPool) !*Cluster {
        if (self.free_list) |c| {
            self.free_list = c.next;
            if (self.count > 0) self.count -= 1;
            c.ref_count = 1;
            return c;
        }

        const c = try self.allocator.create(Cluster);
        c.* = .{
            .ref_count = 1,
            .pool = self,
            .next = null,
            .data = undefined,
        };
        return c;
    }

    pub fn returnToPool(self: *ClusterPool, cluster: *Cluster) void {
        cluster.next = self.free_list;
        self.free_list = cluster;
        self.count += 1;
    }
};

/// Pool is a simple generic object pool.
pub fn Pool(comptime T: type) type {
    return struct {
        const Self = @This();
        allocator: Allocator,
        free_list: ?*T = null,
        count: usize = 0,
        capacity: usize,

        pub fn init(allocator: Allocator, capacity: usize) Self {
            return .{
                .allocator = allocator,
                .capacity = capacity,
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.free_list;
            while (it) |node| {
                const next = node.next;
                self.allocator.destroy(node);
                it = next;
            }
            self.free_list = null;
        }

        pub fn acquire(self: *Self) !*T {
            if (self.free_list) |node| {
                self.free_list = node.next;
                self.count -= 1;
                node.next = null;
                node.prev = null;
                return node;
            }
            const node = try self.allocator.create(T);
            node.next = null;
            node.prev = null;
            return node;
        }

        pub fn release(self: *Self, node: *T) void {
            if (self.count >= self.capacity) {
                self.allocator.destroy(node);
                return;
            }
            node.next = self.free_list;
            self.free_list = node;
            self.count += 1;
        }
    };
}

/// BufferPool manages a pool of raw buffers.
pub const BufferPool = struct {
    allocator: Allocator,
    buffer_size: usize,
    capacity: usize,
    free_list: std.ArrayList([]u8),

    pub fn init(allocator: Allocator, buffer_size: usize, capacity: usize) BufferPool {
        return .{
            .allocator = allocator,
            .buffer_size = buffer_size,
            .capacity = capacity,
            .free_list = std.ArrayList([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *BufferPool) void {
        for (self.free_list.items) |buf| {
            self.allocator.free(buf);
        }
        self.free_list.deinit();
    }

    pub fn acquire(self: *BufferPool) ![]u8 {
        if (self.free_list.popOrNull()) |buf| {
            return buf;
        }
        return try self.allocator.alloc(u8, self.buffer_size);
    }

    pub fn release(self: *BufferPool, buf: []u8) void {
        if (self.free_list.items.len >= self.capacity) {
            self.allocator.free(buf);
            return;
        }
        self.free_list.append(buf) catch {
            self.allocator.free(buf);
        };
    }
};

/// View is a slice of a buffer.
pub const View = []u8;

/// VectorisedView is a vectorised version of View using non contiguous memory.
pub const VectorisedView = struct {
    views: []ClusterView,
    size: usize,
    allocator: ?Allocator = null,
    view_pool: ?*BufferPool = null,
    original_views: []ClusterView = &[_]ClusterView{},

    pub fn init(size: usize, views: []ClusterView) VectorisedView {
        return .{
            .views = views,
            .size = size,
        };
    }

    pub fn empty() VectorisedView {
        return .{ .views = &[_]ClusterView{}, .size = 0 };
    }

    pub fn fromSlice(data: []const u8, allocator: Allocator, pool: *ClusterPool) !VectorisedView {
        const num_clusters = (data.len + header.ClusterSize - 1) / header.ClusterSize;
        const views = try allocator.alloc(ClusterView, num_clusters);
        errdefer allocator.free(views);

        var remaining = data.len;
        var offset: usize = 0;
        var i: usize = 0;
        while (remaining > 0) : (i += 1) {
            const cluster = try pool.acquire();
            const to_copy = @min(remaining, header.ClusterSize);
            @memcpy(cluster.data[0..to_copy], data[offset .. offset + to_copy]);
            views[i] = .{ .cluster = cluster, .view = cluster.data[0..to_copy] };
            remaining -= to_copy;
            offset += to_copy;
        }

        return .{
            .views = views,
            .original_views = views,
            .size = data.len,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *VectorisedView) void {
        for (self.views) |cv| {
            if (cv.cluster) |c| c.release();
        }
        const ov = self.original_views;
        if (self.view_pool) |pool| {
            pool.release(std.mem.sliceAsBytes(ov));
        } else if (self.allocator) |alloc| {
            if (ov.len > 0) alloc.free(ov);
        }
        self.* = undefined;
    }

    pub fn capLength(self: *VectorisedView, length: usize) void {
        if (self.size <= length) return;
        self.size = length;
        var remaining = length;
        for (self.views, 0..) |*v, i| {
            if (v.view.len >= remaining) {
                if (remaining == 0) {
                    self.views = self.views[0..i];
                } else {
                    v.view = v.view[0..remaining];
                    self.views = self.views[0 .. i + 1];
                }
                return;
            }
            remaining -= v.view.len;
        }
    }

    pub fn trimFront(self: *VectorisedView, count: usize) void {
        var remaining = count;
        while (remaining > 0 and self.views.len > 0) {
            if (remaining < self.views[0].view.len) {
                self.size -= remaining;
                self.views[0].view = self.views[0].view[remaining..];
                return;
            }
            remaining -= self.views[0].view.len;
            self.removeFirst();
        }
    }

    pub fn first(self: VectorisedView) ?[]u8 {
        if (self.views.len == 0) return null;
        return self.views[0].view;
    }

    pub fn removeFirst(self: *VectorisedView) void {
        if (self.views.len == 0) return;
        if (self.views[0].cluster) |c| c.release();
        self.size -= self.views[0].view.len;
        self.views = self.views[1..];
    }

    pub fn toView(self: VectorisedView, allocator: Allocator) ![]u8 {
        const out = try allocator.alloc(u8, self.size);
        var offset: usize = 0;
        for (self.views) |v| {
            @memcpy(out[offset .. offset + v.view.len], v.view);
            offset += v.view.len;
        }
        return out;
    }

    pub fn clone(self: VectorisedView, allocator: Allocator) !VectorisedView {
        const new_views = try allocator.alloc(ClusterView, self.views.len);
        @memcpy(new_views, self.views);
        for (new_views) |cv| {
            if (cv.cluster) |c| c.acquire();
        }
        return .{
            .views = new_views,
            .original_views = new_views,
            .size = self.size,
            .allocator = allocator,
        };
    }

    pub fn cloneInPool(self: VectorisedView, pool: *BufferPool) !VectorisedView {
        const view_mem = try pool.acquire();
        const original_views = @as([]ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(ClusterView, view_mem))));
        if (self.views.len > original_views.len) {
            pool.release(view_mem);
            return error.OutOfMemory;
        }
        const new_views = original_views[0..self.views.len];
        @memcpy(new_views, self.views);
        for (new_views) |cv| {
            if (cv.cluster) |c| c.acquire();
        }
        return .{
            .views = new_views,
            .original_views = original_views,
            .size = self.size,
            .view_pool = pool,
        };
    }
};

pub const Prependable = struct {
    buf: []u8,
    usedIdx: usize,

    pub fn init(buf: []u8) Prependable {
        return .{ .buf = buf, .usedIdx = buf.len };
    }

    pub fn initFull(buf: []u8) Prependable {
        return .{ .buf = buf, .usedIdx = 0 };
    }

    pub fn view(self: Prependable) []u8 {
        return self.buf[self.usedIdx..];
    }

    pub fn usedLength(self: Prependable) usize {
        return self.buf.len - self.usedIdx;
    }

    pub fn prepend(self: *Prependable, size: usize) ?[]u8 {
        if (size > self.usedIdx) return null;
        self.usedIdx -= size;
        return self.buf[self.usedIdx .. self.usedIdx + size];
    }
};

test "Cluster single-threaded refcounting" {
    const allocator = std.testing.allocator;
    var pool = ClusterPool.init(allocator);
    defer pool.deinit();

    const cluster = try pool.acquire();
    try std.testing.expectEqual(@as(usize, 1), cluster.ref_count);

    cluster.acquire();
    try std.testing.expectEqual(@as(usize, 2), cluster.ref_count);

    cluster.release();
    try std.testing.expectEqual(@as(usize, 1), cluster.ref_count);

    cluster.release();
    try std.testing.expectEqual(@as(usize, 1), pool.count);
}

test "ClusterPool single-threaded usage" {
    const allocator = std.testing.allocator;
    var pool = ClusterPool.init(allocator);
    defer pool.deinit();

    const c1 = try pool.acquire();
    const c2 = try pool.acquire();
    try std.testing.expectEqual(@as(usize, 0), pool.count);

    c1.release();
    try std.testing.expectEqual(@as(usize, 1), pool.count);

    c2.release();
    try std.testing.expectEqual(@as(usize, 2), pool.count);

    const c3 = try pool.acquire();
    try std.testing.expectEqual(@as(usize, 1), pool.count);
    c3.release();
}

test "BufferPool single-threaded usage" {
    const allocator = std.testing.allocator;
    var pool = BufferPool.init(allocator, 1024, 2);
    defer pool.deinit();

    const b1 = try pool.acquire();
    const b2 = try pool.acquire();
    const b3 = try pool.acquire();

    try std.testing.expectEqual(@as(usize, 0), pool.free_list.items.len);

    pool.release(b1);
    try std.testing.expectEqual(@as(usize, 1), pool.free_list.items.len);

    pool.release(b2);
    try std.testing.expectEqual(@as(usize, 2), pool.free_list.items.len);

    pool.release(b3); // Exceeds capacity, should be freed
    try std.testing.expectEqual(@as(usize, 2), pool.free_list.items.len);
}

