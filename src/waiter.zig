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
    callback: ?*const fn (e: *Entry) void = null,
    mask: EventMask = 0,
    next: ?*Entry = null,
    prev: ?*Entry = null,

    pub fn init(context: ?*anyopaque, callback: ?*const fn (e: *Entry) void) Entry {
        return .{
            .context = context,
            .callback = callback,
        };
    }
};

pub const Queue = struct {
    head: ?*Entry = null,
    tail: ?*Entry = null,
    mutex: Mutex = .{},
    ready_mask: EventMask = 0,

    pub fn eventRegister(self: *Queue, e: *Entry, mask: EventMask) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        e.mask = mask;
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
        self.mutex.lock();
        defer self.mutex.unlock();

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
    }

    pub fn notify(self: *Queue, mask: EventMask) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ready_mask |= mask;

        var current = self.head;
        while (current) |e| {
            const next = e.next;
            if ((mask & e.mask) != 0) {
                if (e.callback) |cb| {
                    cb(e);
                }
            }
            current = next;
        }
    }

    pub fn clear(self: *Queue, mask: EventMask) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ready_mask &= ~mask;
    }

    pub fn interests(self: *Queue) EventMask {
        self.mutex.lock();
        defer self.mutex.unlock();

        var ret: EventMask = 0;
        var current = self.head;
        while (current) |e| {
            ret |= e.mask;
            current = e.next;
        }
        return ret;
    }

    pub fn events(self: *Queue) EventMask {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ready_mask;
    }

    pub fn isEmpty(self: *Queue) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
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
