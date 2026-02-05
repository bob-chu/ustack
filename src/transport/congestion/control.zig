const std = @import("std");

pub const BBR = @import("bbr.zig").BBR;
pub const Cubic = @import("cubic.zig").Cubic;

pub const CongestionControl = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        onAck: *const fn (ptr: *anyopaque, bytes_acked: u32) void,
        onLoss: *const fn (ptr: *anyopaque) void,
        onRetransmit: *const fn (ptr: *anyopaque) void,
        getCwnd: *const fn (ptr: *anyopaque) u32,
        getSsthresh: *const fn (ptr: *anyopaque) u32,
        setMss: ?*const fn (ptr: *anyopaque, mss: u32) void = null,
        reset: ?*const fn (ptr: *anyopaque, mss: u32) void = null,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn onAck(self: CongestionControl, bytes_acked: u32) void {
        self.vtable.onAck(self.ptr, bytes_acked);
    }

    pub fn onLoss(self: CongestionControl) void {
        self.vtable.onLoss(self.ptr);
    }

    pub fn onRetransmit(self: CongestionControl) void {
        self.vtable.onRetransmit(self.ptr);
    }

    pub fn getCwnd(self: CongestionControl) u32 {
        return self.vtable.getCwnd(self.ptr);
    }

    pub fn getSsthresh(self: CongestionControl) u32 {
        return self.vtable.getSsthresh(self.ptr);
    }

    pub fn setMss(self: CongestionControl, mss: u32) void {
        if (self.vtable.setMss) |f| f(self.ptr, mss);
    }

    pub fn reset(self: CongestionControl, mss: u32) !void {
        if (self.vtable.reset) |f| {
            f(self.ptr, mss);
        } else {
            return error.NotSupported;
        }
    }

    pub fn deinit(self: CongestionControl) void {
        self.vtable.deinit(self.ptr);
    }
};

pub const NewReno = struct {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, mss: u32) !CongestionControl {
        const self = try allocator.create(NewReno);
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .allocator = allocator,
        };
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = CongestionControl.VTable{
        .onAck = onAck,
        .onLoss = onLoss,
        .onRetransmit = onRetransmit,
        .getCwnd = getCwnd,
        .getSsthresh = getSsthresh,
        .setMss = setMss,
        .reset = reset,
        .deinit = deinit,
    };

    fn reset(ptr: *anyopaque, mss: u32) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .allocator = self.allocator,
        };
    }

    fn setMss(ptr: *anyopaque, mss: u32) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        const ratio = @as(f64, @floatFromInt(self.cwnd)) / @as(f64, @floatFromInt(self.mss));
        self.mss = mss;
        self.cwnd = @as(u32, @intFromFloat(ratio * @as(f64, @floatFromInt(mss))));
    }

    fn onAck(ptr: *anyopaque, bytes_acked: u32) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        if (self.cwnd < self.ssthresh) {
            self.cwnd += bytes_acked;
        } else {
            const incr = (@as(u64, self.mss) * bytes_acked) / self.cwnd;
            self.cwnd += @as(u32, @intCast(@max(1, incr)));
        }
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.mss;
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.ssthresh + 3 * self.mss;
    }

    fn getCwnd(ptr: *anyopaque) u32 {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        return self.cwnd;
    }

    fn getSsthresh(ptr: *anyopaque) u32 {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        return self.ssthresh;
    }

    fn deinit(ptr: *anyopaque) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        self.allocator.destroy(self);
    }
};
