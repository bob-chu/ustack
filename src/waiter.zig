const std = @import("std");
const Mutex = std.Thread.Mutex;

pub const EventMask = u16;

pub const EventIn: EventMask = 0x01; // POLLIN
pub const EventPri: EventMask = 0x02; // POLLPRI
pub const EventOut: EventMask = 0x04; // POLLOUT
pub const EventErr: EventMask = 0x08; // POLLERR
pub const EventHUp: EventMask = 0x10; // POLLHUP

const allEvents: EventMask = 0x1f;

pub fn eventMaskFromLinux(e: u32) EventMask {
    return @as(EventMask, @truncate(e)) & allEvents;
}

pub fn toLinux(e: EventMask) u32 {
    return @as(u32, e);
}

pub const Entry = struct {
    context: ?*anyopaque = null,
    upcall_ctx: ?*anyopaque = null,
    callback: ?*const fn (e: *Entry) void = null,
    mask: EventMask = 0,
    next: ?*Entry = null,
    prev: ?*Entry = null,
    queue: ?*Queue = null,
    is_queued: bool = false,
    active: bool = false,

    pub fn init(context: ?*anyopaque, callback: ?*const fn (e: *Entry) void) Entry {
        return .{
            .context = context,
            .callback = callback,
        };
    }

    pub fn initWithUpcall(context: ?*anyopaque, upcall_ctx: ?*anyopaque, callback: ?*const fn (e: *Entry) void) Entry {
        return .{
            .context = context,
            .upcall_ctx = upcall_ctx,
            .callback = callback,
        };
    }
};

pub const Queue = struct {
    next: ?*Queue = null,
    prev: ?*Queue = null,
    head: ?*Entry = null,
    tail: ?*Entry = null,
    ready_mask: EventMask = 0,

    pub fn eventRegister(self: *Queue, e: *Entry, mask: EventMask) void {
        if (e.active) {
            if (e.queue == self) {
                // Optimization: if already in this queue, just update mask
                e.mask = mask;
                return;
            }
            // If in another queue, we MUST unregister first to avoid list corruption.
            if (e.queue) |q| q.eventUnregister(e);
        }

        e.mask = mask;
        e.active = true;
        e.queue = self;
        e.next = null;
        e.prev = self.tail;

        if (self.tail) |tail| {
            tail.next = e;
        } else {
            self.head = e;
        }
        self.tail = e;
    }

    pub fn eventUnregister(self: *Queue, e: *Entry) void {
        if (!e.active or e.queue != self) return;

        if (e.prev) |prev| {
            prev.next = e.next;
        } else {
            self.head = e.next;
        }

        if (e.next) |next| {
            next.prev = e.prev;
        } else {
            self.tail = e.prev;
        }

        e.next = null;
        e.prev = null;
        e.active = false;
        e.queue = null;
    }

    pub fn notify(self: *Queue, mask: EventMask) void {
        self.ready_mask |= mask;

        // Use a snapshot of entries to avoid issues with entries being
        // added or removed during the notification loop.
        // Increased size to 16k to handle high connection counts (e.g. 10k connections).
        // Stack usage: 16384 * 8 bytes = 128 KB.
        var snapshot: [16384]*Entry = undefined;
        var count: usize = 0;

        var current = self.head;
        while (current) |e| {
            if (count >= 16384) break;
            snapshot[count] = e;
            count += 1;
            current = e.next;
        }

        for (snapshot[0..count]) |e| {
            // Check if the entry is still active and in the same queue.
            // With Pool zeroing fix, this is safe against reuse.
            if (!e.active or e.queue != self) continue;

            if ((mask & e.mask) != 0) {
                if (e.callback) |cb| {
                    cb(e);
                }
            }
        }
    }

    pub fn clear(self: *Queue, mask: EventMask) void {
        self.ready_mask &= ~mask;
    }

    pub fn interests(self: *Queue) EventMask {
        var ret: EventMask = 0;
        var current = self.head;
        while (current) |e| {
            ret |= e.mask;
            current = e.next;
        }
        return ret;
    }

    pub fn events(self: *Queue) EventMask {
        return self.ready_mask;
    }

    pub fn isEmpty(self: *Queue) bool {
        return self.head == null;
    }
};

test "Queue basic" {
    var q = Queue{};
    var e1 = Entry.init(null, null);
    var e2 = Entry.init(null, null);

    q.eventRegister(&e1, EventIn);
    q.eventRegister(&e2, EventOut);

    try std.testing.expectEqual(EventIn | EventOut, q.interests());
    try std.testing.expect(!q.isEmpty());

    q.eventUnregister(&e1);
    try std.testing.expectEqual(EventOut, q.interests());

    q.eventUnregister(&e2);
    try std.testing.expect(q.isEmpty());
}

test "Queue notify" {
    const Context = struct {
        notified: bool = false,
    };
    var ctx = Context{};
    const callback = struct {
        fn cb(e: *Entry) void {
            const c = @as(*Context, @ptrCast(@alignCast(e.context.?)));
            c.notified = true;
        }
    }.cb;

    var q = Queue{};
    var e = Entry.init(&ctx, callback);
    q.eventRegister(&e, EventIn);

    q.notify(EventOut);
    try std.testing.expect(!ctx.notified);

    q.notify(EventIn);
    try std.testing.expect(ctx.notified);
}

test "Queue notify high concurrency" {
    var q = Queue{};
    const count = 10000;
    var entries = try std.testing.allocator.alloc(Entry, count);
    defer std.testing.allocator.free(entries);

    for (0..count) |i| {
        entries[i] = Entry.init(null, null);
        q.eventRegister(&entries[i], EventIn);
    }

    // This should not crash and should handle all entries (if snapshot is large enough)
    q.notify(EventIn);
}
