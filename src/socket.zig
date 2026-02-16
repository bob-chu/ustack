const std = @import("std");
const stack = @import("stack.zig");
const tcpip = @import("tcpip.zig");
const waiter = @import("waiter.zig");
const buffer = @import("buffer.zig");
const event_mux = @import("event_mux.zig");

pub const Socket = struct {
    endpoint: tcpip.Endpoint,
    wait_queue: *waiter.Queue,
    wait_entry: waiter.Entry,
    allocator: std.mem.Allocator,
    handler: ?Handler = null,
    owns_wait_queue: bool = false,
    closed: bool = false,

    pub const Handler = struct {
        mux: *event_mux.EventMultiplexer,
        ctx: ?*anyopaque,
        func: *const fn (ctx: ?*anyopaque, sock: *Socket, events: waiter.EventMask) void,
    };

    pub fn create(s: *stack.Stack, domain: enum { inet, inet6 }, sock_type: enum { stream, dgram }, protocol: enum { tcp, udp }) !*Socket {
        const net_proto: tcpip.NetworkProtocolNumber = switch (domain) {
            .inet => 0x0800,
            .inet6 => 0x86dd,
        };

        _ = sock_type;
        const trans_proto_id: tcpip.TransportProtocolNumber = switch (protocol) {
            .tcp => 6,
            .udp => 17,
        };

        const trans_proto = s.transport_protocols.get(trans_proto_id) orelse return tcpip.Error.UnknownProtocol;

        const wq = try s.allocator.create(waiter.Queue);
        wq.* = .{};

        const ep = try trans_proto.newEndpoint(s, net_proto, wq);
        errdefer {
            s.allocator.destroy(wq);
        }

        const self = try s.allocator.create(Socket);
        self.* = .{
            .endpoint = ep,
            .wait_queue = wq,
            .wait_entry = undefined,
            .allocator = s.allocator,
            .owns_wait_queue = true,
        };

        return self;
    }

    pub fn setHandler(self: *Socket, mux: *event_mux.EventMultiplexer, ctx: ?*anyopaque, func: *const fn (ctx: ?*anyopaque, sock: *Socket, events: waiter.EventMask) void) void {
        if (self.handler != null) {
            self.wait_queue.eventUnregister(&self.wait_entry);
        }
        self.handler = .{ .mux = mux, .ctx = ctx, .func = func };
        self.wait_entry = waiter.Entry.initWithUpcall(self, mux, event_mux.EventMultiplexer.upcall);
        self.wait_queue.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventErr | waiter.EventHUp);
    }

    pub fn dispatch(entry: *waiter.Entry) void {
        const self = @as(*Socket, @ptrCast(@alignCast(entry.context.?)));
        if (self.closed) return;
        if (self.handler) |h| {
            const events = self.wait_queue.events();
            h.func(h.ctx, self, events);
        }
    }

    pub fn bind(self: *Socket, addr: tcpip.FullAddress) !void {
        return self.endpoint.bind(addr);
    }

    pub fn listen(self: *Socket, backlog: i32) !void {
        return self.endpoint.listen(backlog);
    }

    pub fn accept(self: *Socket) !*Socket {
        const res = try self.endpoint.accept();
        const accepted = try self.allocator.create(Socket);
        accepted.* = .{
            .endpoint = res.ep,
            .wait_queue = res.wq,
            .wait_entry = undefined,
            .allocator = self.allocator,
            .owns_wait_queue = false,
        };
        return accepted;
    }

    pub fn connect(self: *Socket, addr: tcpip.FullAddress) !void {
        return self.endpoint.connect(addr);
    }

    pub fn read(self: *Socket, buf: []u8) !usize {
        var iov = [1][]u8{buf};
        var uio = buffer.Uio.init(&iov);
        return self.readv(&uio);
    }

    pub fn readFrom(self: *Socket, buf: []u8, addr: ?*tcpip.FullAddress) !usize {
        var iov = [1][]u8{buf};
        var uio = buffer.Uio.init(&iov);
        return self.readvFrom(&uio, addr);
    }

    pub fn readv(self: *Socket, uio: *buffer.Uio) !usize {
        return self.endpoint.readv(uio, null);
    }

    pub fn readvFrom(self: *Socket, uio: *buffer.Uio, addr: ?*tcpip.FullAddress) !usize {
        return self.endpoint.readv(uio, addr);
    }

    pub fn recvVio(self: *Socket) !buffer.VectorisedView {
        return self.endpoint.read(null);
    }

    pub fn write(self: *Socket, buf: []const u8) !usize {
        const p = SimplePayload{ .data = buf };
        return self.endpoint.write(p.payloader(), .{});
    }

    pub fn sendTo(self: *Socket, buf: []const u8, addr: tcpip.FullAddress) !usize {
        const p = SimplePayload{ .data = buf };
        return self.endpoint.write(p.payloader(), .{ .to = &addr });
    }

    pub fn writev(self: *Socket, uio: *buffer.Uio) !usize {
        return self.endpoint.writev(uio, .{});
    }

    pub fn writeZeroCopy(self: *Socket, data: []u8, cb: buffer.ConsumptionCallback) !usize {
        return self.endpoint.writeZeroCopy(data, cb, .{});
    }

    pub fn close(self: *Socket) void {
        if (self.closed) return;
        self.closed = true;
        if (self.handler != null) {
            self.wait_queue.eventUnregister(&self.wait_entry);
        }
        self.endpoint.close();
    }

    pub fn deinit(self: *Socket) void {
        self.close();
        self.endpoint.decRef();
        if (self.owns_wait_queue) {
            self.allocator.destroy(self.wait_queue);
        }
        self.allocator.destroy(self);
    }

    pub fn setOption(self: *Socket, opt: anytype) !void {
        return self.endpoint.setOption(opt);
    }

    pub fn shutdown(self: *Socket, how: i32) !void {
        return self.endpoint.shutdown(@as(u8, @intCast(how)));
    }
};

test "TCP Socket Shim Echo" {
    const allocator = std.testing.allocator;
    const main = @import("main.zig");
    const loopback = @import("drivers/loopback.zig");

    var s = try main.init(allocator);
    defer s.deinit();

    var lo = loopback.Loopback.init(allocator);
    lo.address = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 1 } };
    lo.pool = &s.cluster_pool;
    try s.createNIC(1, lo.linkEndpoint());

    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 0, 0, 1 } }, .prefix_len = 24 } });
    try s.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 10, 0, 0, 0 } }, .prefix = 24 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = 65536 });
    try s.addLinkAddress(.{ .v4 = .{ 10, 0, 0, 1 } }, lo.address);

    const mux = try event_mux.EventMultiplexer.init(allocator);
    defer mux.deinit();

    const server_sock = try Socket.create(&s, .inet, .stream, .tcp);
    defer server_sock.deinit();
    try server_sock.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 8080 });
    try server_sock.listen(10);

    const client_sock = try Socket.create(&s, .inet, .stream, .tcp);
    defer client_sock.deinit();
    try client_sock.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 0 });

    _ = client_sock.connect(.{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 8080 }) catch |err| {
        if (err != tcpip.Error.WouldBlock) return err;
    };

    // Handshake
    for (0..20) |_| {
        lo.tick();
        _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 10);
    }

    const accepted_sock = try server_sock.accept();
    defer accepted_sock.deinit();

    // Write from client
    _ = try client_sock.write("hello");

    // Process packets
    for (0..10) |_| {
        lo.tick();
        _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 10);
    }

    // Read on server
    var buf: [16]u8 = undefined;
    const n = try accepted_sock.read(&buf);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualStrings("hello", buf[0..n]);

    // Write back from server
    _ = try accepted_sock.write("world!");

    // Process packets
    for (0..10) |_| {
        lo.tick();
        _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 10);
    }

    // Read on client
    const n2 = try client_sock.read(&buf);
    try std.testing.expectEqual(@as(usize, 6), n2);
    try std.testing.expectEqualStrings("world!", buf[0..n2]);

    // Test writev
    var iov = [_][]u8{ @constCast("vectored "), @constCast("write") };
    var uio = buffer.Uio.init(&iov);
    _ = try client_sock.writev(&uio);

    for (0..10) |_| {
        lo.tick();
        _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 10);
    }

    var buf2: [32]u8 = undefined;
    const n3 = try accepted_sock.read(&buf2);
    try std.testing.expectEqual(@as(usize, 14), n3);
    try std.testing.expectEqualStrings("vectored write", buf2[0..n3]);

    // Test recvVio
    _ = try client_sock.write("zero-copy read");
    for (0..10) |_| {
        lo.tick();
        _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 10);
    }
    var vio = try accepted_sock.recvVio();
    defer vio.deinit();
    try std.testing.expectEqual(@as(usize, 14), vio.size);
    try std.testing.expectEqualStrings("zero-copy read", vio.first().?);

    // Test writeZeroCopy
    const zc_data = try allocator.alloc(u8, 15);
    @memcpy(zc_data, "zero-copy write");
    const Context = struct {
        allocator: std.mem.Allocator,
        data: []u8,
        fn run(ptr: *anyopaque, size: usize) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = size;
            self.allocator.free(self.data);
        }
    };
    var ctx = Context{ .allocator = allocator, .data = zc_data };
    _ = try client_sock.writeZeroCopy(zc_data, .{ .ptr = &ctx, .run = Context.run });

    for (0..10) |_| {
        lo.tick();
        _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 10);
    }

    const n4 = try accepted_sock.read(&buf);
    try std.testing.expectEqual(@as(usize, 15), n4);
    try std.testing.expectEqualStrings("zero-copy write", buf[0..n4]);

    // Final cleanup: tick until empty to avoid leaks in loopback queue
    while (lo.queue.first != null) {
        lo.tick();
        _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 10);
    }
}

pub const SimplePayload = struct {
    data: []const u8,

    pub fn payloader(self: *const SimplePayload) tcpip.Payloader {
        return .{
            .ptr = @constCast(self),
            .vtable = &.{
                .fullPayload = fullPayload,
                .viewPayload = null,
            },
        };
    }

    fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
        const self = @as(*const SimplePayload, @ptrCast(@alignCast(ptr)));
        return self.data;
    }
};
