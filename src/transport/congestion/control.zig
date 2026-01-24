const std = @import("std");

pub const CongestionControl = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        onAck: *const fn (ptr: *anyopaque, bytes_acked: u32) void,
        onLoss: *const fn (ptr: *anyopaque) void,
        onRetransmit: *const fn (ptr: *anyopaque) void,
        getCwnd: *const fn (ptr: *anyopaque) u32,
        getSsthresh: *const fn (ptr: *anyopaque) u32,
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
            .cwnd = mss,
            .ssthresh = 65535,
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
        .deinit = deinit,
    };

    fn onAck(ptr: *anyopaque, bytes_acked: u32) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        _ = bytes_acked;
        // Simplified: we treat every ACK as full MSS for growth
        if (self.cwnd < self.ssthresh) {
            // Slow Start
            self.cwnd += self.mss;
        } else {
            // Congestion Avoidance
            self.cwnd += self.mss / self.cwnd;
        }
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.mss;
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        // Fast Recovery entry
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
