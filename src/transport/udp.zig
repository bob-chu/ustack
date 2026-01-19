const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");

pub const ProtocolNumber = 17;

pub const UDPProtocol = struct {
    pub fn init() UDPProtocol {
        return .{};
    }

    pub fn protocol(self: *UDPProtocol) stack.TransportProtocol {
        return .{
            .ptr = self,
            .vtable = &.{
                .number = number,
                .newEndpoint = newEndpoint,
                .parsePorts = parsePorts,
            },
        };
    }

    fn number(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        _ = ptr; _ = net_proto;
        const ep = s.allocator.create(UDPEndpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = UDPEndpoint.init(s, wait_queue);
        return ep.endpoint();
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        const h = header.UDP.init(v);
        return .{ .src = h.sourcePort(), .dst = h.destinationPort() };
    }
};

pub const UDPEndpoint = struct {
    pub const Packet = struct {
        data: buffer.VectorisedView,
        sender_addr: tcpip.FullAddress,
    };

    stack: *stack.Stack,
    waiter_queue: *waiter.Queue,
    rcv_list: std.TailQueue(Packet),
    mutex: std.Thread.Mutex = .{},
    
    local_addr: ?tcpip.FullAddress = null,
    remote_addr: ?tcpip.FullAddress = null,
    route: ?stack.Route = null,

    pub fn init(s: *stack.Stack, wq: *waiter.Queue) UDPEndpoint {
        return .{
            .stack = s,
            .waiter_queue = wq,
            .rcv_list = .{},
        };
    }

    pub fn transportEndpoint(self: *UDPEndpoint) stack.TransportEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .handlePacket = handlePacket,
                .close = close_internal,
            },
        };
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;

        const h = header.UDP.init(mut_pkt.data.first() orelse return);
        mut_pkt.data.trimFront(header.UDPMinimumSize);

        const node = self.stack.allocator.create(std.TailQueue(Packet).Node) catch return;
        node.data = .{
            .data = mut_pkt.data, // Need to clone if we want to keep it
            .sender_addr = .{
                .nic = r.nic.id,
                .addr = id.remote_address,
                .port = h.sourcePort(),
            },
        };

        self.mutex.lock();
        const was_empty = self.rcv_list.first == null;
        self.rcv_list.append(node);
        self.mutex.unlock();

        if (was_empty) {
            self.waiter_queue.notify(waiter.EventIn);
        }
    }

    pub fn endpoint(self: *UDPEndpoint) tcpip.Endpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .close = close_external,
                .read = read,
                .write = write_external,
                .connect = connect,
                .shutdown = shutdown,
                .listen = listen,
                .accept = accept,
                .bind = bind,
                .getLocalAddress = getLocalAddress,
                .getRemoteAddress = getRemoteAddress,
            },
        };
    }

    fn close_internal(ptr: *anyopaque) void {
        close_external(ptr);
    }

    fn close_external(ptr: *anyopaque) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        while (self.rcv_list.popFirst()) |node| {
            self.stack.allocator.destroy(node);
        }
        self.mutex.unlock();
        self.stack.allocator.destroy(self);
    }

    fn read(ptr: *anyopaque, addr: ?*tcpip.FullAddress) tcpip.Error!buffer.View {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();

        const node = self.rcv_list.popFirst() orelse return tcpip.Error.WouldBlock;
        defer self.stack.allocator.destroy(node);

        if (addr) |a| {
            a.* = node.data.sender_addr;
        }

        // For simplicity, we return a merged view of the data.
        // VectorisedView might need a way to return ownership or stay alive.
        return node.data.data.toView(self.stack.allocator) catch return tcpip.Error.NoBufferSpace;
    }

    fn write_external(ptr: *anyopaque, p: tcpip.Payloader, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        const data_buf = try p.fullPayload();
        
        var views = [_]buffer.View{data_buf};
        const data = buffer.VectorisedView.init(data_buf.len, &views);

        if (opts.to) |to| {
            const local_addr = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
            
            const net_proto: u16 = switch (to.addr) {
                .v4 => 0x0800,
                .v6 => 0x86dd,
            };
            var r = try self.stack.findRoute(to.nic, local_addr.addr, to.addr, net_proto);
            
            // For UDP, we often need the remote link address if it's not in cache
            if (self.stack.link_addr_cache.get(to.addr)) |link_addr| {
                r.remote_link_address = link_addr;
            }

            try self.write(&r, data);
        } else if (self.remote_addr) |to| {
            const local_addr = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
            
            const net_proto: u16 = switch (to.addr) {
                .v4 => 0x0800,
                .v6 => 0x86dd,
            };
            var r = try self.stack.findRoute(to.nic, local_addr.addr, to.addr, net_proto);
            
            if (self.stack.link_addr_cache.get(to.addr)) |link_addr| {
                r.remote_link_address = link_addr;
            }

            try self.write(&r, data);
        } else {
            return tcpip.Error.DestinationRequired;
        }
        
        return data_buf.len;
    }

    fn connect(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.remote_addr = addr;
        return;
    }

    fn bind(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.local_addr = addr;
        
        const id = stack.TransportEndpointID{
            .local_port = addr.port,
            .local_address = addr.addr,
            .remote_port = 0,
            .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } },
        };
        try self.stack.registerTransportEndpoint(id, self.transportEndpoint());
        
        return;
    }

    fn shutdown(ptr: *anyopaque, flags: u8) tcpip.Error!void {
        _ = ptr; _ = flags;
        return;
    }

    fn listen(ptr: *anyopaque, backlog: i32) tcpip.Error!void {
        _ = ptr; _ = backlog;
        return tcpip.Error.UnknownProtocol;
    }

    fn accept(ptr: *anyopaque) tcpip.Error!struct { ep: tcpip.Endpoint, wq: *waiter.Queue } {
        _ = ptr;
        return tcpip.Error.UnknownProtocol;
    }

    fn getLocalAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        _ = ptr;
        return tcpip.Error.UnknownProtocol;
    }

    fn getRemoteAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        _ = ptr;
        return tcpip.Error.UnknownProtocol;
    }
};

test "UDP handlePacket" {
    std.debug.print("Running UDP handlePacket test...\n", .{});
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var wq = waiter.Queue{};
    var ep = try allocator.create(UDPEndpoint);
    ep.* = UDPEndpoint.init(&s, &wq);
    defer ep.transportEndpoint().close();

    var fake_ep = struct {
        fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            _ = ptr; _ = r; _ = protocol; _ = pkt; return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
            _ = ptr; _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress { _ = ptr; return [_]u8{0} ** 6; }
        fn mtu(ptr: *anyopaque) u32 { _ = ptr; return 1500; }
        fn setMTU(ptr: *anyopaque, m: u32) void { _ = ptr; _ = m; }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities { _ = ptr; return stack.CapabilityNone; }
    }{};

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_ep,
        .vtable = &.{
            .writePacket = @TypeOf(fake_ep).writePacket,
            .attach = @TypeOf(fake_ep).attach,
            .linkAddress = @TypeOf(fake_ep).linkAddress,
            .mtu = @TypeOf(fake_ep).mtu,
            .setMTU = @TypeOf(fake_ep).setMTU,
            .capabilities = @TypeOf(fake_ep).capabilities,
        },
    };

    const nic = try s.allocator.create(stack.NIC);
    defer s.allocator.destroy(nic);
    nic.* = stack.NIC.init(&s, 1, "test0", link_ep, false);
    defer nic.deinit();

    const r = stack.Route{
        .local_address = .{ .v4 = .{ 127, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } },
        .local_link_address = .{ 0, 0, 0, 0, 0, 0 },
        .net_proto = 0x0800,
        .nic = nic,
    };

    var udp_data = [_]u8{0} ** 12;
    _ = header.UDP.init(&udp_data);
    std.mem.writeIntBig(u16, udp_data[0..2], 1234);
    std.mem.writeIntBig(u16, udp_data[2..4], 80);
    std.mem.writeIntBig(u16, udp_data[4..6], 12);

    var views = [_]buffer.View{&udp_data};
    const pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(12, &views),
        .header = undefined,
    };

    const id = stack.TransportEndpointID{
        .local_port = 80,
        .local_address = r.local_address,
        .remote_port = 1234,
        .remote_address = r.remote_address,
    };

    ep.transportEndpoint().handlePacket(&r, id, pkt);

    try std.testing.expect(ep.rcv_list.first != null);
    const p = ep.rcv_list.first.?.data;
    try std.testing.expectEqual(@as(u16, 1234), p.sender_addr.port);
    try std.testing.expectEqual(@as(usize, 4), p.data.size);
}

