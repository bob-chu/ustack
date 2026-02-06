const std = @import("std");
const CongestionControl = @import("control.zig").CongestionControl;

pub const BBR = struct {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    allocator: std.mem.Allocator,

    // Simplified BBR-like state
    min_rtt: u64 = 0,
    max_bw: u64 = 0,
    last_ack_time: i64 = 0,

    // Gain values
    const CWND_GAIN: f64 = 2.0;

    pub fn init(allocator: std.mem.Allocator, mss: u32) !CongestionControl {
        const self = try allocator.create(BBR);
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
        .reset = reset,
        .deinit = deinit,
        .setMss = setMss,
    };

    fn reset(ptr: *anyopaque, mss: u32) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .allocator = self.allocator,
        };
    }

    fn setMss(ptr: *anyopaque, mss: u32) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        const ratio = @as(f64, @floatFromInt(self.cwnd)) / @as(f64, @floatFromInt(self.mss));
        self.mss = mss;
        self.cwnd = @as(u32, @intFromFloat(ratio * @as(f64, @floatFromInt(mss))));
    }

    fn onAck(ptr: *anyopaque, bytes_acked: u32) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        const now = std.time.milliTimestamp();

        // Standard slow start growth
        if (self.cwnd < self.ssthresh) {
            self.cwnd += bytes_acked;
        } else {
            // Very simplified congestion avoidance for this "BBR" skeleton
            const incr = (@as(u64, self.mss) * bytes_acked) / self.cwnd;
            self.cwnd += @as(u32, @intCast(@max(1, incr)));
        }

        self.last_ack_time = now;

        // Cap cwnd
        if (self.cwnd > 64 * 1024 * 1024) self.cwnd = 64 * 1024 * 1024;
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.mss;
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.ssthresh;
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
