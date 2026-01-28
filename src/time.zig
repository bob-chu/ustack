const std = @import("std");

pub const TimerCallback = *const fn (ctx: *anyopaque) void;

pub const Timer = struct {
    expiration: i64, // Absolute time in ms
    callback: TimerCallback,
    context: *anyopaque,
    active: bool = false,

    // Linked list node for priority queue
    next: ?*Timer = null,

    pub fn init(callback: TimerCallback, context: *anyopaque) Timer {
        return .{
            .expiration = 0,
            .callback = callback,
            .context = context,
        };
    }
};

pub const TimerQueue = struct {
    head: ?*Timer = null,

    pub fn schedule(self: *TimerQueue, timer: *Timer, delay_ms: i64) void {
        const now = std.time.milliTimestamp();
        const expiration = now + delay_ms;

        // If already active, remove first (simplified: assume caller handles re-schedule or we implement remove)
        if (timer.active) {
            self.removeInternal(timer);
        }

        timer.expiration = expiration;
        timer.active = true;
        self.insertInternal(timer);
    }

    pub fn cancel(self: *TimerQueue, timer: *Timer) void {
        if (timer.active) {
            self.removeInternal(timer);
            timer.active = false;
        }
    }

    /// Process expired timers. Returns the delay until the next timer in ms, or null if empty.
    pub fn tick(self: *TimerQueue) ?i64 {
        const now = std.time.milliTimestamp();

        while (true) {
            const head = self.head;

            if (head) |timer| {
                if (timer.expiration <= now) {
                    // Pop expired timer
                    self.head = timer.next;
                    timer.next = null;
                    timer.active = false;

                    // Execute callback
                    timer.callback(timer.context);
                    continue;
                } else {
                    // Next timer is in future
                    const remaining = timer.expiration - now;
                    return remaining;
                }
            } else {
                return null;
            }
        }
    }

    fn insertInternal(self: *TimerQueue, timer: *Timer) void {
        var current = &self.head;
        while (current.*) |node| {
            if (timer.expiration < node.expiration) {
                break;
            }
            current = &node.next;
        }
        timer.next = current.*;
        current.* = timer;
    }

    fn removeInternal(self: *TimerQueue, timer: *Timer) void {
        var current = &self.head;
        while (current.*) |node| {
            if (node == timer) {
                current.* = node.next;
                node.next = null;
                return;
            }
            current = &node.next;
        }
    }
};

test "TimerQueue basic" {
    var q = TimerQueue{};
    var fired = false;

    const Ctx = struct { fired: *bool };
    var ctx = Ctx{ .fired = &fired };

    const cb = struct {
        fn run(ptr: *anyopaque) void {
            const c = @as(*Ctx, @ptrCast(@alignCast(ptr)));
            c.fired.* = true;
        }
    }.run;

    var t = Timer.init(cb, &ctx);

    q.schedule(&t, 50); // 50ms delay

    // Immediate tick, should not fire
    var next = q.tick();
    try std.testing.expect(next != null);
    try std.testing.expect(next.? > 0);
    try std.testing.expect(!fired);

    std.time.sleep(60 * std.time.ns_per_ms);

    // Tick after sleep, should fire
    next = q.tick();
    try std.testing.expect(fired);
}
