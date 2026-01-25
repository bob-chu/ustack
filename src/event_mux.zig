const std = @import("std");
const waiter = @import("waiter.zig");

/// EventMultiplexer acts as a bridge between ustack's user-space events
pub const EventMultiplexer = struct {
    ready_queue: ReadyQueue,
    signal_fd: std.posix.fd_t,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*EventMultiplexer {
        const self = try allocator.create(EventMultiplexer);

        // Create an eventfd (or pipe as fallback) to signal the kernel loop
        // EFD_NONBLOCK is usually 0x800 on Linux.
        const efd = try std.posix.eventfd(0, 0x800);

        self.* = .{
            .ready_queue = ReadyQueue.init(allocator),
            .signal_fd = efd,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *EventMultiplexer) void {
        std.posix.close(self.signal_fd);
        self.ready_queue.deinit();
        self.allocator.destroy(self);
    }

    /// Returns the file descriptor that libev/epoll should watch for READ events.
    pub fn fd(self: *EventMultiplexer) std.posix.fd_t {
        return self.signal_fd;
    }

    /// The "Soupcall" - This is registered on a socket's wait_queue.
    /// It gets triggered by the stack when data arrives or space opens up.
    pub fn upcall(entry: *waiter.Entry) void {
        const self = @as(*EventMultiplexer, @ptrCast(@alignCast(entry.upcall_ctx.?)));
        if (self.ready_queue.push(entry) catch false) {
            const val: u64 = 1;
            _ = std.posix.write(self.signal_fd, std.mem.asBytes(&val)) catch {};
        }
    }

    /// Drains the signal and returns all ready entries.
    /// Should be called by the libev callback when the signal_fd is readable.
    pub fn pollReady(self: *EventMultiplexer) ![]*waiter.Entry {
        // Clear the eventfd
        var val: u64 = 0;
        _ = std.posix.read(self.signal_fd, std.mem.asBytes(&val)) catch {};

        return self.ready_queue.popAll();
    }
};

/// A simple thread-safe queue to track ready sockets.
const ReadyQueue = struct {
    mutex: std.Thread.Mutex = .{},
    list: std.ArrayList(*waiter.Entry),

    pub fn init(allocator: std.mem.Allocator) ReadyQueue {
        return .{
            .list = std.ArrayList(*waiter.Entry).init(allocator),
        };
    }

    pub fn deinit(self: *ReadyQueue) void {
        self.list.deinit();
    }

    pub fn push(self: *ReadyQueue, entry: *waiter.Entry) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Deduplicate: Don't add if already in queue
        for (self.list.items) |item| {
            if (item == entry) return false;
        }

        try self.list.append(entry);
        return true;
    }

    pub fn popAll(self: *ReadyQueue) ![]*waiter.Entry {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.list.items.len == 0) return &[_]*waiter.Entry{};

        const results = try self.list.toOwnedSlice();
        return results;
    }
};

test "EventMultiplexer basic" {
    const allocator = std.testing.allocator;
    const mux = try EventMultiplexer.init(allocator);
    defer mux.deinit();

    var entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall);

    // Trigger upcall
    EventMultiplexer.upcall(&entry);

    // Verify ready
    const ready = try mux.pollReady();
    defer allocator.free(ready);

    try std.testing.expectEqual(@as(usize, 1), ready.len);
    try std.testing.expectEqual(&entry, ready[0]);

    // Verify eventfd was cleared (pollReady again should be empty)
    const ready2 = try mux.pollReady();
    defer allocator.free(ready2);
    try std.testing.expectEqual(@as(usize, 0), ready2.len);
}

test "ReadyQueue deduplication" {
    const allocator = std.testing.allocator;
    var q = ReadyQueue.init(allocator);
    defer q.deinit();

    var entry = waiter.Entry.init(null, null);

    _ = try q.push(&entry);
    _ = try q.push(&entry); // Duplicate

    const ready = try q.popAll();
    defer allocator.free(ready);

    try std.testing.expectEqual(@as(usize, 1), ready.len);
}
