const std = @import("std");
const CongestionControl = @import("control.zig").CongestionControl;

pub const BBR = struct {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    allocator: std.mem.Allocator,
    
    // Simplified BBR state
    min_rtt: u32,
    bottleneck_bw: u64,
    pacing_rate: u64,

    pub fn init(allocator: std.mem.Allocator, mss: u32) !CongestionControl {
        const self = try allocator.create(BBR);
        self.* = .{
            .cwnd = mss,
            .ssthresh = 65535,
            .mss = mss,
            .allocator = allocator,
            .min_rtt = 0,
            .bottleneck_bw = 0,
            .pacing_rate = 0,
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
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        _ = bytes_acked;
        // Simplified BBR logic: grow window if bandwidth allows
        self.cwnd += self.mss;
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        // BBR reduces window based on estimated bandwidth, not just loss
        self.cwnd = @max(self.cwnd / 2, 4 * self.mss);
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        // Fast recovery
        self.cwnd = self.cwnd / 2;
    }

    fn getCwnd(ptr: *anyopaque) u32 {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        return self.cwnd;
    }

    fn getSsthresh(ptr: *anyopaque) u32 {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        return self.ssthresh;
    }

    fn deinit(ptr: *anyopaque) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        self.allocator.destroy(self);
    }
};
