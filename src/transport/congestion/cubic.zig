const std = @import("std");
const CongestionControl = @import("control.zig").CongestionControl;

pub const Cubic = struct {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,

    // CUBIC specific variables
    w_max: u32,
    k: f64,
    epoch_start: i64,
    origin_point: u32,

    // TCP-friendly reno tracking
    reno_cwnd: u32,

    allocator: std.mem.Allocator,

    const C: f64 = 0.4;
    const BETA: f64 = 0.7;

    pub fn init(allocator: std.mem.Allocator, mss: u32) !CongestionControl {
        const self = try allocator.create(Cubic);
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .w_max = 0,
            .k = 0,
            .epoch_start = 0,
            .origin_point = 0,
            .reno_cwnd = 0,
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
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .w_max = 0,
            .k = 0,
            .epoch_start = 0,
            .origin_point = 0,
            .reno_cwnd = 0,
            .allocator = self.allocator,
        };
    }

    fn setMss(ptr: *anyopaque, mss: u32) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        const ratio = @as(f64, @floatFromInt(self.cwnd)) / @as(f64, @floatFromInt(self.mss));
        self.mss = mss;
        self.cwnd = @as(u32, @intFromFloat(ratio * @as(f64, @floatFromInt(mss))));
        if (self.reno_cwnd > 0) {
            const r_ratio = @as(f64, @floatFromInt(self.reno_cwnd)) / @as(f64, @floatFromInt(self.mss));
            self.reno_cwnd = @as(u32, @intFromFloat(r_ratio * @as(f64, @floatFromInt(mss))));
        }
    }

    fn cubicUpdate(self: *Cubic, bytes_acked: u32) void {
        const now = std.time.milliTimestamp();
        if (self.epoch_start == 0) {
            self.epoch_start = now;
            if (self.cwnd < self.w_max) {
                // K = cubic_root(W_max * (1 - beta) / C)
                const w_diff = @as(f64, @floatFromInt(self.w_max - self.origin_point)) / @as(f64, @floatFromInt(self.mss));
                self.k = std.math.pow(f64, w_diff / C, 1.0 / 3.0);
            } else {
                self.k = 0;
            }
        }

        const t = @as(f64, @floatFromInt(now - self.epoch_start)) / 1000.0;
        const offset = t - self.k;
        const target = (C * offset * offset * offset * @as(f64, @floatFromInt(self.mss))) + @as(f64, @floatFromInt(self.w_max));

        // TCP Friendly Reno growth
        if (self.reno_cwnd == 0) self.reno_cwnd = self.cwnd;
        const reno_incr = (@as(u64, self.mss) * bytes_acked) / self.reno_cwnd;
        self.reno_cwnd += @as(u32, @intCast(@max(1, reno_incr)));

        if (target > @as(f64, @floatFromInt(self.cwnd))) {
            const diff_val = target - @as(f64, @floatFromInt(self.cwnd));
            const incr_f = (diff_val / @as(f64, @floatFromInt(self.cwnd))) * @as(f64, @floatFromInt(self.mss));
            const incr = if (incr_f > 1000000.0) @as(u32, 1000000) else @as(u32, @intFromFloat(@max(1.0, incr_f)));
            self.cwnd = self.cwnd +% incr;
        } else if (target < @as(f64, @floatFromInt(self.cwnd))) {
            // If we are below target, we should still grow slowly or at least match Reno
        }

        // Ensure TCP friendliness
        if (self.cwnd < self.reno_cwnd) {
            self.cwnd = self.reno_cwnd;
        }
    }

    fn onAck(ptr: *anyopaque, bytes_acked: u32) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));

        if (self.cwnd < self.ssthresh) {
            // Slow start: grow by bytes acked
            self.cwnd += bytes_acked;
        } else {
            // Congestion avoidance (CUBIC mode)
            self.cubicUpdate(bytes_acked);
        }

        if (self.cwnd > 0x7FFFFFFF) self.cwnd = 0x7FFFFFFF;
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        self.epoch_start = 0;
        self.w_max = self.cwnd;
        self.ssthresh = @max(@as(u32, @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * BETA)), 2 * self.mss);
        self.cwnd = self.mss;
        self.reno_cwnd = self.cwnd;
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        self.epoch_start = 0;
        self.w_max = self.cwnd;
        self.ssthresh = @max(@as(u32, @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * BETA)), 2 * self.mss);
        self.cwnd = self.ssthresh;
        self.origin_point = self.cwnd;
        self.reno_cwnd = self.cwnd;
    }

    fn getCwnd(ptr: *anyopaque) u32 {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        return self.cwnd;
    }

    fn getSsthresh(ptr: *anyopaque) u32 {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        return self.ssthresh;
    }

    fn deinit(ptr: *anyopaque) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        self.allocator.destroy(self);
    }
};
