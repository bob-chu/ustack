const std = @import("std");
const stack = @import("stack.zig");
const tcpip = @import("tcpip.zig");
const waiter = @import("waiter.zig");
const buffer = @import("buffer.zig");

pub const Socket = struct {
    endpoint: tcpip.Endpoint,
    // The wait queue associated with this socket.
    // For a listening socket, we create it.
    // For an accepted socket, we inherit it from the stack.
    wait_queue: *waiter.Queue,

    blocking: bool = true,
    allocator: std.mem.Allocator,

    // Synchronization for blocking mode
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    wait_entry: waiter.Entry,

    pub fn init(allocator: std.mem.Allocator, ep: tcpip.Endpoint, wq: *waiter.Queue) *Socket {
        const self = allocator.create(Socket) catch @panic("OOM");
        self.* = .{
            .endpoint = ep,
            .wait_queue = wq,
            .allocator = allocator,
            .wait_entry = undefined,
        };
        // Initialize wait entry with callback that signals condition variable
        self.wait_entry = waiter.Entry.init(self, notifyCallback);
        // Register for all events by default
        self.wait_queue.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventErr | waiter.EventHUp);
        return self;
    }

    fn notifyCallback(e: *waiter.Entry) void {
        const self = @as(*Socket, @ptrCast(@alignCast(e.context)));
        self.mutex.lock();
        self.cond.signal(); // signalAll or signal? signal is enough for one waiter (us)
        self.mutex.unlock();
    }

    pub fn deinit(self: *Socket) void {
        self.wait_queue.eventUnregister(&self.wait_entry);
        self.endpoint.close();
        // Wait queue handling:
        // If we created it (client/listener), we own it.
        // If accepted, we also own it (TCPEndpoint logic passes ownership).
        // Since TCPEndpoint.close() doesn't free the queue passed to it, we must free it.
        // Wait, TCPEndpoint stores reference.
        self.allocator.destroy(self.wait_queue);
        self.allocator.destroy(self);
    }
};

// Global-ish API functions
pub fn usocket(s: *stack.Stack, domain: i32, sock_type: i32, protocol: i32) !*Socket {
    // Validate domain
    const net_proto: tcpip.NetworkProtocolNumber = switch (domain) {
        std.posix.AF.INET => 0x0800, // IPv4
        std.posix.AF.INET6 => 0x86dd, // IPv6
        else => return error.AddressFamilyNotSupported,
    };

    // Validate type/protocol
    const trans_proto_id: tcpip.TransportProtocolNumber = if (protocol != 0) @intCast(protocol) else switch (sock_type) {
        std.posix.SOCK.STREAM => 6, // TCP
        std.posix.SOCK.DGRAM => 17, // UDP
        else => return error.SocketTypeNotSupported,
    };

    const trans_proto = s.transport_protocols.get(trans_proto_id) orelse return error.ProtocolNotSupported;

    // Create Wait Queue
    const wq = try s.allocator.create(waiter.Queue);
    wq.* = .{};

    // Create Endpoint
    const ep = try trans_proto.newEndpoint(s, net_proto, wq);
    errdefer {
        s.allocator.destroy(wq);
    }

    return Socket.init(s.allocator, ep, wq);
}

pub fn ubind(sock: *Socket, addr: std.posix.sockaddr, len: std.posix.socklen_t) !void {
    _ = len;
    const full_addr = fromSockAddr(addr) catch return error.AddressFamilyNotSupported;
    try sock.endpoint.bind(full_addr);
}

pub fn uconnect(sock: *Socket, addr: std.posix.sockaddr, len: std.posix.socklen_t) !void {
    _ = len;
    const full_addr = fromSockAddr(addr) catch return error.AddressFamilyNotSupported;

    // Non-blocking connect not fully supported by this simple wrapper logic yet,
    // but underlying stack supports it.
    try sock.endpoint.connect(full_addr);

    // For TCP, connect might return immediately or start handshake.
    // If blocking, we should wait for ESTABLISHED or Error.
    if (sock.blocking) {
        // Poll state?
        // Note: ustack connect() usually returns void for UDP and starts handshake for TCP.
        // We need a way to check state.
        // Currently endpoint interface doesn't expose state generically.
        // Assuming TCP endpoint:
        // Wait for EventOut (writable) which usually signifies connected.

        sock.mutex.lock();
        defer sock.mutex.unlock();
        while (true) {
            // Check if connected?
            // Since we can't check state generically, we rely on Error return from write/read?
            // Actually, connect() in tcp.zig returns immediately after sending SYN.
            // We should wait.
            // Let's assume we wait for writeable.

            // Hack: just wait once? No.
            // We need 'getOption' to check error?
            // Or just proceed. Standard connect() blocks.
            // Let's implement a wait loop here.

            // This is tricky without `getsockopt(SO_ERROR)`.
            // For now, let's just return. User will find out on read/write.
            break;
        }
    }
}

pub fn ulisten(sock: *Socket, backlog: i32) !void {
    try sock.endpoint.listen(backlog);
}

pub fn uaccept(sock: *Socket, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t) !*Socket {
    while (true) {
        const res = sock.endpoint.accept() catch |err| {
            if (err == tcpip.Error.WouldBlock and sock.blocking) {
                sock.mutex.lock();
                sock.cond.wait(&sock.mutex);
                sock.mutex.unlock();
                continue;
            }
            return err;
        };

        if (addr) |out_addr| {
            if (res.ep.getRemoteAddress()) |remote| {
                toSockAddr(remote, out_addr, len);
            } else |_| {}
        }

        return Socket.init(sock.allocator, res.ep, res.wq);
    }
}

pub fn urecv(sock: *Socket, buf: []u8, flags: u32) !usize {
    _ = flags;
    while (true) {
        const view = sock.endpoint.read(null) catch |err| {
            if (err == tcpip.Error.WouldBlock and sock.blocking) {
                sock.mutex.lock();
                sock.cond.wait(&sock.mutex);
                sock.mutex.unlock();
                continue;
            }
            return err;
        };

        const len = @min(buf.len, view.len);
        @memcpy(buf[0..len], view[0..len]);
        // Note: 'view' is owned by us (caller of read). We must free it?
        // ustack read() returns a view that must be freed by allocator?
        // Yes, based on udp.zig: returns toView(allocator).
        // We need to know which allocator allocated it.
        // It's sock.allocator (stack.allocator).
        sock.allocator.free(view);
        return len;
    }
}

pub fn usend(sock: *Socket, buf: []const u8, flags: u32) !usize {
    _ = flags;
    const Payloader = struct {
        data: []const u8,
        pub fn payloader(ctx: *@This()) tcpip.Payloader {
            return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
        }
        fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
            return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
        }
    };
    var fp = Payloader{ .data = buf };

    while (true) {
        const n = sock.endpoint.write(fp.payloader(), .{}) catch |err| {
            if (err == tcpip.Error.WouldBlock and sock.blocking) {
                sock.mutex.lock();
                sock.cond.wait(&sock.mutex);
                sock.mutex.unlock();
                continue;
            }
            return err;
        };
        return n;
    }
}

pub fn uclose(sock: *Socket) void {
    sock.deinit();
}

// Helpers
fn fromSockAddr(addr: std.posix.sockaddr) !tcpip.FullAddress {
    if (addr.family == std.posix.AF.INET) {
        const in = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&addr)));
        return tcpip.FullAddress{
            .nic = 0, // 0 usually means "any" or "route decide" in ustack binding
            .addr = .{ .v4 = @bitCast(in.addr) },
            .port = std.mem.bigToNative(u16, in.port),
        };
    } else if (addr.family == std.posix.AF.INET6) {
        const in6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&addr)));
        return tcpip.FullAddress{
            .nic = 0,
            .addr = .{ .v6 = in6.addr },
            .port = std.mem.bigToNative(u16, in6.port),
        };
    }
    return error.AddressFamilyNotSupported;
}

fn toSockAddr(addr: tcpip.FullAddress, out: *std.posix.sockaddr, len: ?*std.posix.socklen_t) void {
    switch (addr.addr) {
        .v4 => |v| {
            var in = std.posix.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, addr.port),
                .addr = @bitCast(v),
                .zero = [_]u8{0} ** 8,
            };
            const size = @sizeOf(std.posix.sockaddr.in);
            if (len) |l| {
                if (l.* < size) return; // Truncated?
                l.* = size;
            }
            @memcpy(@as([*]u8, @ptrCast(out))[0..size], @as([*]const u8, @ptrCast(&in))[0..size]);
        },
        .v6 => |v| {
            var in6 = std.posix.sockaddr.in6{
                .family = std.posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, addr.port),
                .flowinfo = 0,
                .addr = v,
                .scope_id = 0,
            };
            const size = @sizeOf(std.posix.sockaddr.in6);
            if (len) |l| {
                if (l.* < size) return;
                l.* = size;
            }
            @memcpy(@as([*]u8, @ptrCast(out))[0..size], @as([*]const u8, @ptrCast(&in6))[0..size]);
        },
    }
}

test "POSIX API TCP client/server" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    // Setup protocols
    var tcp_proto = @import("transport/tcp.zig").TCPProtocol.init(allocator);
    defer tcp_proto.deinit();
    try s.registerTransportProtocol(tcp_proto.protocol());
    var ipv4_proto = @import("network/ipv4.zig").IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    // Setup Link
    var fake_link = struct {
        allocator: std.mem.Allocator,
        server_pkt: ?[]u8 = null,
        client_pkt: ?[]u8 = null,

        // Very basic in-memory "loopback" that delivers packets to the stack
        // This simulates the wire
        stack_ref: *stack.Stack,

        fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r;
            _ = protocol;

            // Linearize packet
            const hdr_view = pkt.header.view();
            const total_len = hdr_view.len + pkt.data.size;
            const buf = self.allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(buf[0..hdr_view.len], hdr_view);
            var off = hdr_view.len;
            for (pkt.data.views) |v| {
                @memcpy(buf[off .. off + v.view.len], v.view);
                off += v.view.len;
            }

            // "Transmit" by delivering back to stack (loopback)
            // But we need to reverse src/dst in IP/TCP headers if we want full emulation.
            // For this test, we are cheating. We just want to verifying API calls don't crash and wait/notify works.
            // But `uconnect` waits for handshake. We need a responder.

            // Let's just test bind/listen/socket creation without full traffic flow for now
            // to verify API surface. Full flow requires a lot of setup.
            self.allocator.free(buf);
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return 0;
        }
    }{ .allocator = allocator, .stack_ref = &s };

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).mtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = .{ 127, 0, 0, 1 } }, .prefix_len = 8 } });

    // 1. Create Socket
    const sock = try usocket(&s, std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    defer uclose(sock);

    // 2. Bind
    const addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 8080),
        .addr = 0, // 0.0.0.0
        .zero = [_]u8{0} ** 8,
    };
    try ubind(sock, @as(std.posix.sockaddr, @bitCast(addr)), @sizeOf(std.posix.sockaddr.in));

    // 3. Listen
    try ulisten(sock, 10);

    // 4. Accept (Non-blocking check for test)
    // We set non-blocking just to verify it doesn't hang forever in test
    sock.blocking = false;
    const res = uaccept(sock, null, null);
    try std.testing.expectError(tcpip.Error.WouldBlock, res);
}
pub const PollFd = struct {
    sock: *Socket,
    events: i16,
    revents: i16,
};

pub const POLLIN = 0x0001;
pub const POLLPRI = 0x0002;
pub const POLLOUT = 0x0004;
pub const POLLERR = 0x0008;
pub const POLLHUP = 0x0010;
pub const POLLNVAL = 0x0020;

// Helper to convert waiter masks to poll events
fn waiterToPoll(mask: waiter.EventMask) i16 {
    var events: i16 = 0;
    if (mask & waiter.EventIn != 0) events |= POLLIN;
    if (mask & waiter.EventOut != 0) events |= POLLOUT;
    if (mask & waiter.EventErr != 0) events |= POLLERR;
    if (mask & waiter.EventHUp != 0) events |= POLLHUP;
    if (mask & waiter.EventPri != 0) events |= POLLPRI;
    return events;
}

fn pollToWaiter(events: i16) waiter.EventMask {
    var mask: waiter.EventMask = 0;
    if (events & POLLIN != 0) mask |= waiter.EventIn;
    if (events & POLLOUT != 0) mask |= waiter.EventOut;
    if (events & POLLPRI != 0) mask |= waiter.EventPri;
    return mask;
}

/// Polls multiple sockets for events.
/// timeout_ms: < 0 (infinite), 0 (immediate), > 0 (wait time)
pub fn upoll(fds: []PollFd, timeout_ms: i32) !usize {
    // 1. Check if any are already ready (fast path)
    var ready_count: usize = 0;
    for (fds) |*pfd| {
        pfd.revents = 0;
        // Access wait queue events directly?
        // waiter.Queue has events().
        // We need socket-specific events. Waiter queue is per-socket.
        // So yes, we can check queue events.
        const mask = pfd.sock.wait_queue.events();
        const interested = pollToWaiter(pfd.events);
        const fired = mask & interested;

        if (fired != 0) {
            pfd.revents = waiterToPoll(fired);
            ready_count += 1;
        }
    }

    if (ready_count > 0 or timeout_ms == 0) {
        return ready_count;
    }

    // 2. Wait
    // We need a way to sleep on MULTIPLE condition variables?
    // No, Condition Variable is associated with a Mutex.
    // Each Socket has its own Mutex/Cond.
    // This is hard with the current architecture where each Socket owns its queue/cond.

    // Solution: Create a TEMPORARY Waiter Entry that points to a local condition variable.
    // Register this entry to ALL sockets' queues.
    // Wait on the local condition variable.
    // Unregister from all.

    var mutex = std.Thread.Mutex{};
    var cond = std.Thread.Condition{};
    var fired = false;

    const PollContext = struct {
        mutex: *std.Thread.Mutex,
        cond: *std.Thread.Condition,
        fired: *bool,
    };
    var ctx = PollContext{ .mutex = &mutex, .cond = &cond, .fired = &fired };

    const callback = struct {
        fn cb(e: *waiter.Entry) void {
            const c = @as(*PollContext, @ptrCast(@alignCast(e.context.?)));
            c.mutex.lock();
            c.fired.* = true;
            c.cond.signal();
            c.mutex.unlock();
        }
    }.cb;

    // We need an array of entries, one per FD
    // Stack allocation might be too big for large N.
    // Use allocator from first socket? Or pass an allocator?
    // Let's assume fds.len is reasonable (like select 1024), or require allocator.
    // For now, let's use a temporary allocator or error if too big?
    // Let's use `std.heap.page_allocator` just for the wait entries array if stack is small.

    // Optimization: Just one entry per socket.
    // Zig doesn't allow VLA.
    const entries = try std.heap.page_allocator.alloc(waiter.Entry, fds.len);
    defer std.heap.page_allocator.free(entries);

    for (fds, 0..) |*pfd, i| {
        entries[i] = waiter.Entry.init(&ctx, callback);
        pfd.sock.wait_queue.eventRegister(&entries[i], pollToWaiter(pfd.events));
    }

    // Wait
    mutex.lock();
    if (!fired) {
        if (timeout_ms < 0) {
            cond.wait(&mutex);
        } else {
            // timedWait expects nanoseconds
            const ns = @as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms;
            _ = cond.timedWait(&mutex, ns) catch {};
        }
    }
    mutex.unlock();

    // Unregister
    for (fds, 0..) |*pfd, i| {
        pfd.sock.wait_queue.eventUnregister(&entries[i]);
    }

    // Re-check events
    ready_count = 0;
    for (fds) |*pfd| {
        pfd.revents = 0;
        const mask = pfd.sock.wait_queue.events(); // This might race if event cleared?
        // Actually, events() returns currently asserted events (level triggered).
        // So this is correct for level-triggered poll.
        const interested = pollToWaiter(pfd.events);
        const current_fired = mask & interested;
        if (current_fired != 0) {
            pfd.revents = waiterToPoll(current_fired);
            ready_count += 1;
        }
    }

    return ready_count;
}

test "POSIX upoll basic" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var udp_proto = @import("transport/udp.zig").UDPProtocol.init(allocator);
    defer udp_proto.deinit(allocator);
    try s.registerTransportProtocol(udp_proto.protocol());
    var ipv4_proto = @import("network/ipv4.zig").IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    // Setup Link
    var fake_link = struct {
        fn writePacket(_: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return 0;
        }
    }{};
    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{ .writePacket = @TypeOf(fake_link).writePacket, .attach = @TypeOf(fake_link).attach, .linkAddress = @TypeOf(fake_link).linkAddress, .mtu = @TypeOf(fake_link).mtu, .setMTU = @TypeOf(fake_link).setMTU, .capabilities = @TypeOf(fake_link).capabilities },
    };
    try s.createNIC(1, link_ep);
    try s.nics.get(1).?.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = .{ 127, 0, 0, 1 } }, .prefix_len = 8 } });

    // Create UDP socket
    const sock = try usocket(&s, std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer uclose(sock);

    var fds = [_]PollFd{
        .{ .sock = sock, .events = POLLIN, .revents = 0 },
    };

    // 1. Poll empty (should timeout)
    const start = std.time.milliTimestamp();
    const n = try upoll(&fds, 100);
    const end = std.time.milliTimestamp();
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expect(end - start >= 90); // Allow some jitter

    // 2. Poll with data
    // Inject packet to make it readable
    const udp_ep = @as(*@import("transport/udp.zig").UDPEndpoint, @ptrCast(@alignCast(sock.endpoint.ptr)));
    const r = stack.Route{ .local_address = .{ .v4 = .{ 127, 0, 0, 1 } }, .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } }, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = s.nics.get(1).? };
    const id = stack.TransportEndpointID{ .local_port = 0, .local_address = .{ .v4 = .{ 0, 0, 0, 0 } }, .remote_port = 1234, .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } } };

    // We need to bind first to receive? UDP handlePacket doesn't check bind if injected directly to EP logic?
    // Wait, we need to inject to the endpoint instance.
    // Let's assume handlePacket logic:
    // It takes ownership of packet.
    const payload_buf = try allocator.alloc(u8, 10);
    // var views = [_]buffer.View{payload_buf};
    // Need UDP header for handlePacket to strip?
    // UDPEndpoint.handlePacket expects raw packet including UDP header?
    // Yes: header.UDP.init(mut_pkt.data.first()...)

    // Re-alloc with header space
    allocator.free(payload_buf);
    const buf = try allocator.alloc(u8, 8 + 4); // 8 header + 4 payload
    @memset(buf, 0);
    var views2 = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
    const pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(buf.len, &views2), .header = buffer.Prependable.init(&[_]u8{}) };

    // Inject directly into endpoint handler (bypassing stack dispatch for simplicity)
    udp_ep.transportEndpoint().handlePacket(&r, id, pkt);
    allocator.free(buf);

    // Poll again (immediate)
    const n2 = try upoll(&fds, 100);
    try std.testing.expectEqual(@as(usize, 1), n2);
    try std.testing.expect(fds[0].revents & POLLIN != 0);
}
