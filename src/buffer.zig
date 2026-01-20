const std = @import("std");
const Allocator = std.mem.Allocator;

/// View is a slice of a buffer, with convenience methods.
pub const View = []u8;

/// VectorisedView is a vectorised version of View using non contiguous memory.
pub const VectorisedView = struct {
    views: []View,
    size: usize,
    allocator: ?Allocator = null,

    pub fn init(size: usize, views: []View) VectorisedView {
        return .{
            .views = views,
            .size = size,
        };
    }

    pub fn deinit(self: *VectorisedView) void {
        if (self.allocator) |alloc| {
            for (self.views) |v| {
                alloc.free(v);
            }
            alloc.free(self.views);
        }
        self.* = undefined;
    }

    /// TrimFront removes the first "count" bytes of the vectorised view.
    pub fn trimFront(self: *VectorisedView, count: usize) void {
        var remaining = count;
        while (remaining > 0 and self.views.len > 0) {
            if (remaining < self.views[0].len) {
                self.size -= remaining;
                self.views[0] = self.views[0][remaining..];
                return;
            }
            remaining -= self.views[0].len;
            self.removeFirst();
        }
    }

    /// CapLength irreversibly reduces the length of the vectorised view.
    pub fn capLength(self: *VectorisedView, length: usize) void {
        if (self.size < length) return;

        self.size = length;
        var remaining = length;
        for (self.views, 0..) |*v, i| {
            if (v.len >= remaining) {
                if (remaining == 0) {
                    self.views = self.views[0..i];
                } else {
                    v.* = v.*[0..remaining];
                    self.views = self.views[0 .. i + 1];
                }
                return;
            }
            remaining -= v.len;
        }
    }

    /// First returns the first view of the vectorised view.
    pub fn first(self: VectorisedView) ?View {
        if (self.views.len == 0) return null;
        return self.views[0];
    }

    /// RemoveFirst removes the first view of the vectorised view.
    pub fn removeFirst(self: *VectorisedView) void {
        if (self.views.len == 0) return;
        self.size -= self.views[0].len;
        self.views = self.views[1..];
    }

    /// ToView returns a single view containing the content of the vectorised view.
    /// Caller owns the returned memory.
    pub fn toView(self: VectorisedView, allocator: Allocator) !View {
        const out = try allocator.alloc(u8, self.size);
        var offset: usize = 0;
        for (self.views) |v| {
            @memcpy(out[offset .. offset + v.len], v);
            offset += v.len;
        }
        return out;
    }

    pub fn append(self: *VectorisedView, other: VectorisedView, allocator: Allocator) !void {
        const new_views = try allocator.alloc(View, self.views.len + other.views.len);
        @memcpy(new_views[0..self.views.len], self.views);
        @memcpy(new_views[self.views.len..], other.views);
        
        if (self.allocator) |alloc| {
            alloc.free(self.views);
        }
        
        self.views = new_views;
        self.allocator = allocator;
        self.size += other.size;
    }

    pub fn clone(self: VectorisedView, allocator: Allocator) !VectorisedView {
        const new_views = try allocator.alloc(View, self.views.len);
        errdefer allocator.free(new_views);
        
        var i: usize = 0;
        while (i < self.views.len) : (i += 1) {
            new_views[i] = try allocator.alloc(u8, self.views[i].len);
            @memcpy(new_views[i], self.views[i]);
        }
        
        return .{
            .views = new_views,
            .size = self.size,
            .allocator = allocator,
        };
    }
};

/// Prependable is a buffer that grows backwards.
pub const Prependable = struct {
    buf: View,
    usedIdx: usize,

    pub fn init(buf: View) Prependable {
        return .{
            .buf = buf,
            .usedIdx = buf.len,
        };
    }

    pub fn initFull(buf: View) Prependable {
        return .{
            .buf = buf,
            .usedIdx = 0,
        };
    }

    pub fn view(self: Prependable) View {
        return self.buf[self.usedIdx..];
    }

    pub fn usedLength(self: Prependable) usize {
        return self.buf.len - self.usedIdx;
    }

    pub fn availableLength(self: Prependable) usize {
        return self.usedIdx;
    }

    pub fn trimBack(self: *Prependable, size: usize) void {
        self.buf = self.buf[0 .. self.buf.len - size];
    }

    pub fn prepend(self: *Prependable, size: usize) ?[]u8 {
        if (size > self.usedIdx) return null;
        self.usedIdx -= size;
        return self.buf[self.usedIdx .. self.usedIdx + size];
    }
};

test "VectorisedView basic" {
    const allocator = std.testing.allocator;
    const v1 = try allocator.alloc(u8, 5);
    defer allocator.free(v1);
    @memcpy(@constCast(v1), "hello");

    const v2 = try allocator.alloc(u8, 5);
    defer allocator.free(v2);
    @memcpy(@constCast(v2), "world");

    const views = try allocator.alloc(View, 2);
    defer allocator.free(views);
    views[0] = v1;
    views[1] = v2;

    var vv = VectorisedView.init(10, views);
    try std.testing.expectEqual(@as(usize, 10), vv.size);
    
    vv.trimFront(3);
    try std.testing.expectEqual(@as(usize, 7), vv.size);
    try std.testing.expectEqual(@as(usize, 2), vv.views[0].len);
    try std.testing.expectEqualStrings("lo", vv.views[0]);

    vv.trimFront(3);
    try std.testing.expectEqual(@as(usize, 4), vv.size);
    try std.testing.expectEqual(@as(usize, 1), vv.views.len);
    try std.testing.expectEqualStrings("orld", vv.views[0]);
}

test "Prependable basic" {
    var buf: [100]u8 = undefined;
    var p = Prependable.init(&buf);

    try std.testing.expectEqual(@as(usize, 0), p.usedLength());
    try std.testing.expectEqual(@as(usize, 100), p.availableLength());

    const h = p.prepend(5).?;
    @memcpy(h, "hello");
    
    try std.testing.expectEqual(@as(usize, 5), p.usedLength());
    try std.testing.expectEqualStrings("hello", p.view());

    const w = p.prepend(6).?;
    @memcpy(w, " world");
    try std.testing.expectEqualStrings(" worldhello", p.view());
}
