const std = @import("std");

pub const TimerCallback = *const fn (ctx: *anyopaque) void;

pub const Timer = struct {
    // Callback
    callback: TimerCallback,
    context: *anyopaque,

    // Timing
    expire_tick: u64 = 0, // Absolute tick when timer fires
    delay_ms: u32 = 0, // Original delay (for reschedule)

    // Intrusive doubly-linked list (O(1) removal)
    next: ?*Timer = null,
    prev: ?*Timer = null,

    // Wheel location (for O(1) cancel without search)
    level: u8 = 0, // Which wheel (0-3)
    slot: u8 = 0, // Which slot (0-255)
    active: bool = false,

    pub fn init(callback: TimerCallback, context: *anyopaque) Timer {
        return .{
            .callback = callback,
            .context = context,
        };
    }
};

pub const TickResult = struct {
    expired_count: u32 = 0,
    cascaded_count: u32 = 0,
    next_expiration: ?u64 = null,
};

pub const TimerWheel = struct {
    const LEVELS = 4;
    const SLOTS_PER_LEVEL = 256;
    const SLOT_MASK = 255;
    const BITS_PER_LEVEL = 8;

    wheels: [LEVELS][SLOTS_PER_LEVEL]Slot = [_][SLOTS_PER_LEVEL]Slot{[_]Slot{.{}} ** SLOTS_PER_LEVEL} ** LEVELS,
    slot_masks: [LEVELS]SlotMask = [_]SlotMask{.{}} ** LEVELS,
    current_tick: u64 = 0,

    const Slot = struct {
        head: ?*Timer = null,
        tail: ?*Timer = null,
        count: u32 = 0,

        pub fn append(self: *Slot, timer: *Timer) void {
            timer.next = null;
            timer.prev = self.tail;
            if (self.tail) |t| {
                t.next = timer;
            } else {
                self.head = timer;
            }
            self.tail = timer;
            self.count += 1;
        }

        pub fn remove(self: *Slot, timer: *Timer) void {
            if (timer.prev) |p| {
                p.next = timer.next;
            } else {
                self.head = timer.next;
            }
            if (timer.next) |n| {
                n.prev = timer.prev;
            } else {
                self.tail = timer.prev;
            }
            timer.next = null;
            timer.prev = null;
            self.count -= 1;
        }

        pub fn popFirst(self: *Slot) ?*Timer {
            const first = self.head orelse return null;
            self.remove(first);
            return first;
        }

        pub fn isEmpty(self: Slot) bool {
            return self.count == 0;
        }
    };

    const SlotMask = struct {
        bits: [4]u64 = [_]u64{0} ** 4,

        pub fn set(self: *SlotMask, slot: u8) void {
            self.bits[slot >> 6] |= (@as(u64, 1) << @intCast(slot & 63));
        }

        pub fn unset(self: *SlotMask, slot: u8) void {
            self.bits[slot >> 6] &= ~(@as(u64, 1) << @intCast(slot & 63));
        }

        pub fn findNext(self: SlotMask, start_slot: u8) ?u8 {
            var i: usize = start_slot >> 6;
            const bit_offset: u6 = @intCast(start_slot & 63);

            // Check first u64 with bit offset
            var first_bits = self.bits[i];
            // Mask out bits before start_slot
            first_bits &= (@as(u64, 0xFFFFFFFFFFFFFFFF) << bit_offset);

            if (first_bits != 0) {
                return @intCast((i << 6) + @ctz(first_bits));
            }

            // Check remaining u64s
            var checked: usize = 1;
            while (checked < 4) : (checked += 1) {
                i = (i + 1) % 4;
                if (self.bits[i] != 0) {
                    return @intCast((i << 6) + @ctz(self.bits[i]));
                }
            }
            return null;
        }

        pub fn isEmpty(self: SlotMask) bool {
            return self.bits[0] == 0 and self.bits[1] == 0 and self.bits[2] == 0 and self.bits[3] == 0;
        }
    };

    pub fn init() TimerWheel {
        return .{};
    }

    pub fn schedule(self: *TimerWheel, timer: *Timer, delay_ms: u64) void {
        if (timer.active) {
            self.cancel(timer);
        }

        const safe_delay = @max(delay_ms, 1);
        const expire_tick = self.current_tick + safe_delay;
        timer.expire_tick = expire_tick;
        timer.delay_ms = @intCast(@min(delay_ms, std.math.maxInt(u32)));

        const level, const slot = self.calculateLevelAndSlot(expire_tick);
        timer.level = @intCast(level);
        timer.slot = @intCast(slot);
        timer.active = true;

        self.wheels[level][slot].append(timer);
        self.slot_masks[level].set(@intCast(slot));
    }

    pub fn cancel(self: *TimerWheel, timer: *Timer) void {
        if (!timer.active) return;

        const level = timer.level;
        const slot = timer.slot;
        self.wheels[level][slot].remove(timer);
        if (self.wheels[level][slot].isEmpty()) {
            self.slot_masks[level].unset(slot);
        }

        timer.active = false;
    }

    pub fn tick(self: *TimerWheel) TickResult {
        var result = TickResult{};

        // 1. Advance time
        self.current_tick += 1;

        // 2. Cascade from higher levels if a wheel completed rotation
        var cascade_level: usize = 1;
        var temp_tick = self.current_tick;
        while (cascade_level < LEVELS) : (cascade_level += 1) {
            if ((temp_tick & (@as(u64, SLOTS_PER_LEVEL) - 1)) != 0) break;
            temp_tick >>= BITS_PER_LEVEL;
            result.cascaded_count += self.cascade(cascade_level);
        }

        // 3. Process Level 0 expired timers
        const slot_idx: u8 = @intCast(self.current_tick & SLOT_MASK);
        while (self.wheels[0][slot_idx].popFirst()) |timer| {
            if (self.wheels[0][slot_idx].isEmpty()) {
                self.slot_masks[0].unset(slot_idx);
            }
            timer.active = false;
            timer.callback(timer.context);
            result.expired_count += 1;
        }

        result.next_expiration = self.nextExpiration();
        return result;
    }

    pub fn tickTo(self: *TimerWheel, target_tick: u64) TickResult {
        var total_result = TickResult{};
        while (self.current_tick < target_tick) {
            const next_rel = self.nextExpiration() orelse {
                self.current_tick = target_tick;
                break;
            };

            const jump = @min(next_rel, target_tick - self.current_tick);
            if (jump > 1) {
                // Jump to just before the next interesting tick
                self.current_tick += (jump - 1);
            }

            const res = self.tick();
            total_result.expired_count += res.expired_count;
            total_result.cascaded_count += res.cascaded_count;
        }
        total_result.next_expiration = self.nextExpiration();
        return total_result;
    }

    pub fn nextExpiration(self: TimerWheel) ?u64 {
        const next_proc_tick = self.current_tick + 1;
        
        var level: usize = 0;
        while (level < LEVELS) : (level += 1) {
            const level_shift: u6 = @intCast(level * BITS_PER_LEVEL);
            const current_slot: u8 = @intCast((next_proc_tick >> level_shift) & SLOT_MASK);
            
            if (self.slot_masks[level].findNext(current_slot)) |next_slot| {
                if (level == 0) {
                    const diff: u64 = if (next_slot >= current_slot)
                        @as(u64, next_slot) - @as(u64, current_slot)
                    else
                        @as(u64, SLOTS_PER_LEVEL) - @as(u64, current_slot) + @as(u64, next_slot);
                    // +1 because next_proc_tick is already current_tick + 1
                    return diff + 1;
                } else {
                    const abs_slot_idx_at_level = next_proc_tick >> level_shift;
                    const rotation_base_slot = abs_slot_idx_at_level & ~@as(u64, SLOT_MASK);
                    var next_abs_slot = rotation_base_slot + next_slot;
                    
                    var next_tick = next_abs_slot << level_shift;
                    if (next_tick < next_proc_tick) {
                        next_abs_slot += SLOTS_PER_LEVEL;
                        next_tick = next_abs_slot << level_shift;
                    }
                    
                    return next_tick - self.current_tick;
                }
            }
        }

        return null;
    }

    fn cascade(self: *TimerWheel, level: usize) u32 {
        const level_shift: u6 = @intCast(level * BITS_PER_LEVEL);
        const slot_idx: u8 = @intCast((self.current_tick >> level_shift) & SLOT_MASK);
        var cascaded: u32 = 0;

        while (self.wheels[level][slot_idx].popFirst()) |timer| {
            if (self.wheels[level][slot_idx].isEmpty()) {
                self.slot_masks[level].unset(slot_idx);
            }

            const new_level, const new_slot = self.calculateLevelAndSlot(timer.expire_tick);

            timer.level = @intCast(new_level);
            timer.slot = @intCast(new_slot);
            self.wheels[new_level][new_slot].append(timer);
            self.slot_masks[new_level].set(@intCast(new_slot));

            cascaded += 1;
        }

        return cascaded;
    }

    fn calculateLevelAndSlot(self: TimerWheel, expire_tick: u64) struct { usize, usize } {
        const diff = if (expire_tick > self.current_tick) expire_tick - self.current_tick else 1;

        var level: usize = 0;
        var temp_diff = diff;
        while (level < LEVELS - 1 and temp_diff >= SLOTS_PER_LEVEL) : (level += 1) {
            temp_diff >>= BITS_PER_LEVEL;
        }

        const level_shift: u6 = @intCast(level * BITS_PER_LEVEL);
        const slot = expire_tick >> level_shift & SLOT_MASK;
        return .{ level, @intCast(slot) };
    }

    pub fn currentTick(self: TimerWheel) u64 {
        return self.current_tick;
    }

    pub fn hasPendingTimers(self: TimerWheel) bool {
        for (self.slot_masks) |mask| {
            if (!mask.isEmpty()) return true;
        }
        return false;
    }
};

pub const TimerQueue = TimerWheel;

test "TimerWheel basic operations" {
    var wheel = TimerWheel.init();
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
    wheel.schedule(&t, 5);

    _ = wheel.tick(); // 1
    try std.testing.expect(!fired);
    _ = wheel.tick(); // 2
    try std.testing.expect(!fired);
    _ = wheel.tick(); // 3
    try std.testing.expect(!fired);
    _ = wheel.tick(); // 4
    try std.testing.expect(!fired);
    _ = wheel.tick(); // 5
    try std.testing.expect(fired);
}

test "TimerWheel nextExpiration" {
    var wheel = TimerWheel.init();
    const cb = struct {
        fn run(_: *anyopaque) void {}
    }.run;

    var t1 = Timer.init(cb, undefined);
    wheel.schedule(&t1, 10);
    try std.testing.expectEqual(@as(?u64, 10), wheel.nextExpiration());

    var t2 = Timer.init(cb, undefined);
    wheel.schedule(&t2, 5);
    try std.testing.expectEqual(@as(?u64, 5), wheel.nextExpiration());

    var t3 = Timer.init(cb, undefined);
    wheel.schedule(&t3, 1000); // Should be in Level 1
    
    _ = wheel.tickTo(wheel.current_tick + 5);
    try std.testing.expectEqual(@as(?u64, 5), wheel.nextExpiration());
    
    _ = wheel.tickTo(wheel.current_tick + 5);
    // At current_tick = 10. t3 is at 1000. next_proc_tick = 11.
    // L1: current_slot = (11 >> 8) = 0. next_slot = (1000 >> 8) = 3.
    // S = 0 + ( (3 + 256 - 0) % 256 ) = 3.
    // abs_tick = 3 << 8 = 768.
    // return 768 - 10 = 758.
    // Wait, 1000 - 10 = 990?
    // Ah! Slot 3 covers 768..1023. It cascades at 768.
    // So nextExpiration returns the distance to CASCADE, not necessarily to fire if fire is later in the slot?
    // But L0 distance is exact.
    // L1 distance to cascade is what nextExpiration for L1 should return.
    try std.testing.expectEqual(@as(?u64, 758), wheel.nextExpiration());
}

test "TimerWheel cascading" {
    var wheel = TimerWheel.init();
    var fired_count: u32 = 0;
    const Ctx = struct { count: *u32 };
    var ctx = Ctx{ .count = &fired_count };
    const cb = struct {
        fn run(ptr: *anyopaque) void {
            const c = @as(*Ctx, @ptrCast(@alignCast(ptr)));
            c.count.* += 1;
        }
    }.run;

    var t1 = Timer.init(cb, &ctx);
    wheel.schedule(&t1, 300); // Level 1, Slot 1

    _ = wheel.tickTo(wheel.current_tick + 299);
    try std.testing.expectEqual(@as(u32, 0), fired_count);

    _ = wheel.tick(); // 300
    try std.testing.expectEqual(@as(u32, 1), fired_count);
}
