const std = @import("std");
const header = @import("header.zig");
const Allocator = std.mem.Allocator;

/// Cluster is a ref-counted fixed-size buffer.
pub const Cluster = struct {
    ref_count: std.atomic.Value(usize),
    pool: *ClusterPool,
    next: ?*Cluster = null,
    data: [header.ClusterSize]u8 align(64),

    pub fn acquire(self: *Cluster) void {
        _ = self.ref_count.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Cluster) void {
        if (self.ref_count.fetchSub(1, .release) == 1) {
            self.ref_count.fence(.acquire);
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
    mutex: std.Thread.Mutex = .{},
    count: usize = 0,

    pub fn init(allocator: Allocator) ClusterPool {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ClusterPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.free_list;
        while (it) |c| {
            const next = c.next;
            self.allocator.destroy(c);
            it = next;
        }
        self.free_list = null;
    }

    pub fn acquire(self: *ClusterPool) !*Cluster {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list) |c| {
            self.free_list = c.next;
            if (self.count > 0) self.count -= 1;
            c.ref_count.store(1, .monotonic);
            return c;
        }

        const c = try self.allocator.create(Cluster);
        c.* = .{
            .ref_count = std.atomic.Value(usize).init(1),
            .pool = self,
            .next = null,
            .data = undefined,
        };
        return c;
    }

    pub fn returnToPool(self: *ClusterPool, cluster: *Cluster) void {
        self.mutex.lock();
        defer self.mutex.unlock();
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
        mutex: std.Thread.Mutex = .{},
        count: usize = 0,
        capacity: usize,

        pub fn init(allocator: Allocator, capacity: usize) Self {
            return .{
                .allocator = allocator,
                .capacity = capacity,
            };
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            var it = self.free_list;
            while (it) |node| {
                const next = node.next;
                self.allocator.destroy(node);
                it = next;
            }
            self.free_list = null;
        }

        pub fn acquire(self: *Self) !*T {
            self.mutex.lock();
            defer self.mutex.unlock();
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
            self.mutex.lock();
            defer self.mutex.unlock();
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
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: Allocator, buffer_size: usize, capacity: usize) BufferPool {
        return .{
            .allocator = allocator,
            .buffer_size = buffer_size,
            .capacity = capacity,
            .free_list = std.ArrayList([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *BufferPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.free_list.items) |buf| {
            self.allocator.free(buf);
        }
        self.free_list.deinit();
    }

    pub fn acquire(self: *BufferPool) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.free_list.popOrNull()) |buf| {
            return buf;
        }
        return try self.allocator.alloc(u8, self.buffer_size);
    }

    pub fn release(self: *BufferPool, buf: []u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
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
