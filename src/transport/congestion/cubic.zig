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

    allocator: std.mem.Allocator,

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

    fn cubicUpdate(self: *Cubic) void {
        const now = std.time.milliTimestamp();
        if (self.epoch_start == 0) {
            self.epoch_start = now;
            if (self.cwnd < self.w_max) {
                self.k = std.math.pow(f64, @as(f64, @floatFromInt(self.w_max - self.cwnd)) / 0.4, 1.0 / 3.0); // C = 0.4
                self.origin_point = self.w_max;
            } else {
                self.k = 0;
                self.origin_point = self.cwnd;
            }
        }

        const t = @as(f64, @floatFromInt(now - self.epoch_start)) / 1000.0 + self.k;
        const target = 0.4 * (t - self.k) * (t - self.k) * (t - self.k) * @as(f64, @floatFromInt(self.mss)) + @as(f64, @floatFromInt(self.origin_point));

        if (target > @as(f64, @floatFromInt(self.cwnd))) {
            const diff_val = target - @as(f64, @floatFromInt(self.cwnd));
            const incr_f = (diff_val / @as(f64, @floatFromInt(self.cwnd))) * @as(f64, @floatFromInt(self.mss));
            const incr = if (incr_f > 1000000.0) @as(u32, 1000000) else @as(u32, @intFromFloat(@max(1.0, incr_f)));
            self.cwnd = self.cwnd +% incr;
        }
    }

    fn onAck(ptr: *anyopaque, bytes_acked: u32) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        _ = bytes_acked;

        if (self.cwnd < self.ssthresh) {
            // Slow start
            self.cwnd = self.cwnd +% self.mss;
        } else {
            // Congestion avoidance (CUBIC mode)
            self.cubicUpdate();
        }
        // Cap cwnd to 2GB to prevent weird behavior and overflow issues
        if (self.cwnd > 0x7FFFFFFF) self.cwnd = 0x7FFFFFFF;
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        self.epoch_start = 0;
        if (self.cwnd < self.w_max) {
            self.w_max = @as(u32, @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * (2.0 - 0.7) / 2.0)); // Fast convergence
        } else {
            self.w_max = self.cwnd;
        }
        self.ssthresh = @max(@as(u32, @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * 0.7)), 2 * self.mss);
        self.cwnd = self.mss;
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        self.epoch_start = 0;
        self.w_max = self.cwnd;
        self.ssthresh = @max(@as(u32, @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * 0.7)), 2 * self.mss);
        self.cwnd = self.ssthresh;
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
