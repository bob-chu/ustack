const std = @import("std");
const tcpip = @import("tcpip.zig");
const buffer = @import("buffer.zig");
const header = @import("header.zig");
const waiter = @import("waiter.zig");
const time = @import("time.zig");

pub const LinkEndpointCapabilities = u32;
pub const CapabilityNone: LinkEndpointCapabilities = 0;
pub const CapabilityLoopback: LinkEndpointCapabilities = 1 << 0;
pub const CapabilityResolutionRequired: LinkEndpointCapabilities = 1 << 1;

pub const LinkEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        writePacket: *const fn (ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void,
        attach: *const fn (ptr: *anyopaque, dispatcher: *NetworkDispatcher) void,
        linkAddress: *const fn (ptr: *anyopaque) tcpip.LinkAddress,
        mtu: *const fn (ptr: *anyopaque) u32,
        setMTU: *const fn (ptr: *anyopaque, mtu: u32) void,
        capabilities: *const fn (ptr: *anyopaque) LinkEndpointCapabilities,
    };

    pub fn writePacket(self: LinkEndpoint, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        return self.vtable.writePacket(self.ptr, r, protocol, pkt);
    }

    pub fn attach(self: LinkEndpoint, dispatcher: *NetworkDispatcher) void {
        return self.vtable.attach(self.ptr, dispatcher);
    }

    pub fn linkAddress(self: LinkEndpoint) tcpip.LinkAddress {
        return self.vtable.linkAddress(self.ptr);
    }

    pub fn mtu(self: LinkEndpoint) u32 {
        return self.vtable.mtu(self.ptr);
    }

    pub fn setMTU(self: LinkEndpoint, m: u32) void {
        self.vtable.setMTU(self.ptr, m);
    }

    pub fn capabilities(self: LinkEndpoint) LinkEndpointCapabilities {
        return self.vtable.capabilities(self.ptr);
    }
};

pub const NetworkDispatcher = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        deliverNetworkPacket: *const fn (ptr: *anyopaque, remote: tcpip.LinkAddress, local: tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void,
    };

    pub fn deliverNetworkPacket(self: NetworkDispatcher, remote: tcpip.LinkAddress, local: tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        return self.vtable.deliverNetworkPacket(self.ptr, remote, local, protocol, pkt);
    }
};

pub const NetworkEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        writePacket: *const fn (ptr: *anyopaque, r: *const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void,
        handlePacket: *const fn (ptr: *anyopaque, r: *const Route, pkt: tcpip.PacketBuffer) void,
        mtu: *const fn (ptr: *anyopaque) u32,
    };

    pub fn writePacket(self: NetworkEndpoint, r: *const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        return self.vtable.writePacket(self.ptr, r, protocol, pkt);
    }

    pub fn handlePacket(self: NetworkEndpoint, r: *const Route, pkt: tcpip.PacketBuffer) void {
        return self.vtable.handlePacket(self.ptr, r, pkt);
    }

    pub fn mtu(self: NetworkEndpoint) u32 {
        return self.vtable.mtu(self.ptr);
    }
};

pub const NetworkProtocol = struct {
    pub const AddressPair = struct { src: tcpip.Address, dst: tcpip.Address };

    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        number: *const fn (ptr: *anyopaque) tcpip.NetworkProtocolNumber,
        newEndpoint: *const fn (ptr: *anyopaque, nic: *NIC, addr: tcpip.AddressWithPrefix, dispatcher: TransportDispatcher) tcpip.Error!NetworkEndpoint,
        linkAddressRequest: *const fn (ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *NIC) tcpip.Error!void,
        parseAddresses: *const fn (ptr: *anyopaque, pkt: tcpip.PacketBuffer) AddressPair,
    };

    pub fn number(self: NetworkProtocol) tcpip.NetworkProtocolNumber {
        return self.vtable.number(self.ptr);
    }

    pub fn newEndpoint(self: NetworkProtocol, nic: *NIC, addr: tcpip.AddressWithPrefix, dispatcher: TransportDispatcher) tcpip.Error!NetworkEndpoint {
        return self.vtable.newEndpoint(self.ptr, nic, addr, dispatcher);
    }

    pub fn linkAddressRequest(self: NetworkProtocol, addr: tcpip.Address, local_addr: tcpip.Address, nic: *NIC) tcpip.Error!void {
        return self.vtable.linkAddressRequest(self.ptr, addr, local_addr, nic);
    }

    pub fn parseAddresses(self: NetworkProtocol, pkt: tcpip.PacketBuffer) AddressPair {
        return self.vtable.parseAddresses(self.ptr, pkt);
    }
};

pub const TransportEndpointID = struct {
    local_port: u16,
    local_address: tcpip.Address,
    remote_port: u16,
    remote_address: tcpip.Address,
};

pub const TransportEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        handlePacket: *const fn (ptr: *anyopaque, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void,
        close: *const fn (ptr: *anyopaque) void,
    };

    pub fn handlePacket(self: TransportEndpoint, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        return self.vtable.handlePacket(self.ptr, r, id, pkt);
    }

    pub fn close(self: TransportEndpoint) void {
        return self.vtable.close(self.ptr);
    }
};

pub const TransportProtocol = struct {
    pub const PortPair = struct { src: u16, dst: u16 };

    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        number: *const fn (ptr: *anyopaque) tcpip.TransportProtocolNumber,
        newEndpoint: *const fn (ptr: *anyopaque, stack: *Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint,
        parsePorts: *const fn (ptr: *anyopaque, pkt: tcpip.PacketBuffer) PortPair,
    };

    pub fn number(self: TransportProtocol) tcpip.TransportProtocolNumber {
        return self.vtable.number(self.ptr);
    }

    pub fn newEndpoint(self: TransportProtocol, s: *Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        return self.vtable.newEndpoint(self.ptr, s, net_proto, wait_queue);
    }

    pub fn parsePorts(self: TransportProtocol, pkt: tcpip.PacketBuffer) PortPair {
        return self.vtable.parsePorts(self.ptr, pkt);
    }
};

pub const TransportDispatcher = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        deliverTransportPacket: *const fn (ptr: *anyopaque, r: *const Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) void,
    };

    pub fn deliverTransportPacket(self: TransportDispatcher, r: *const Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) void {
        return self.vtable.deliverTransportPacket(self.ptr, r, protocol, pkt);
    }
};

pub const NIC = struct {
    stack: *Stack,
    id: tcpip.NICID,
    name: []const u8,
    linkEP: LinkEndpoint,
    loopback: bool,
    addresses: std.ArrayList(tcpip.ProtocolAddress),
    network_endpoints: std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkEndpoint),

    pub fn init(stack_ptr: *Stack, id: tcpip.NICID, name: []const u8, ep: LinkEndpoint, loopback: bool) NIC {
        return .{
            .stack = stack_ptr,
            .id = id,
            .name = name,
            .linkEP = ep,
            .loopback = loopback,
            .addresses = std.ArrayList(tcpip.ProtocolAddress).init(stack_ptr.allocator),
            .network_endpoints = std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkEndpoint).init(stack_ptr.allocator),
        };
    }

    pub fn deinit(self: *NIC) void {
        self.addresses.deinit();
        self.network_endpoints.deinit();
    }

    pub fn addAddress(self: *NIC, addr: tcpip.ProtocolAddress) !void {
        try self.addresses.append(addr);
        if (self.stack.network_protocols.get(addr.protocol)) |proto| {
            // Only create endpoint if protocol is registered (e.g. ARP doesn't need endpoint here?)
            // Wait, ARP is a network protocol.
            // But usually we just add addresses for IPv4/IPv6.
            // If proto.newEndpoint fails, we might want to know.
            const ep = try proto.newEndpoint(self, addr.address_with_prefix, self.stack.transportDispatcher());
            try self.network_endpoints.put(addr.protocol, ep);
        }
    }

    pub fn hasAddress(self: *NIC, addr: tcpip.Address) bool {
        for (self.addresses.items) |pa| {
            if (pa.address_with_prefix.address.eq(addr)) return true;
        }
        return false;
    }

    pub fn attach(self: *NIC) void {
        const dispatcher = NetworkDispatcher{
            .ptr = self,
            .vtable = &.{
                .deliverNetworkPacket = deliverNetworkPacket,
            },
        };
        self.linkEP.attach(@constCast(&dispatcher));
    }

    fn deliverNetworkPacket(ptr: *anyopaque, remote: tcpip.LinkAddress, local: tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        const self = @as(*NIC, @ptrCast(@alignCast(ptr)));
        const proto = self.stack.network_protocols.get(protocol) orelse return;
        const ep = self.network_endpoints.get(protocol) orelse return;
        
        const addrs = proto.parseAddresses(pkt);
        
        // Construct a route for the delivery
        const r = Route{
            .local_address = addrs.dst,
            .remote_address = addrs.src,
            .local_link_address = local,
            .remote_link_address = remote,
            .net_proto = protocol,
            .nic = self,
        };
        
        ep.handlePacket(&r, pkt);
    }
};

pub const Route = struct {
    remote_address: tcpip.Address,
    local_address: tcpip.Address,
    local_link_address: tcpip.LinkAddress,
    remote_link_address: ?tcpip.LinkAddress = null,
    next_hop: ?tcpip.Address = null,
    net_proto: tcpip.NetworkProtocolNumber,
    nic: *NIC,

    pub fn writePacket(self: *Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        if (self.remote_link_address == null) {
            if (self.nic.stack.link_addr_cache.get(self.remote_address)) |link_addr| {
                self.remote_link_address = link_addr;
            } else {
                // Trigger ARP resolution
                // This is a bit complex for a synchronous call, but let's try.
                var it = self.nic.stack.network_protocols.valueIterator();
                while (it.next()) |proto| {
                    proto.linkAddressRequest(self.remote_address, self.local_address, self.nic) catch {};
                }
                return tcpip.Error.WouldBlock;
            }
        }
        return self.nic.linkEP.writePacket(self, protocol, pkt);
    }
};

pub const Stack = struct {
    allocator: std.mem.Allocator,
    nics: std.AutoHashMap(tcpip.NICID, *NIC),
    endpoints: std.AutoHashMap(TransportEndpointID, TransportEndpoint),
    link_addr_cache: std.AutoHashMap(tcpip.Address, tcpip.LinkAddress),
    transport_protocols: std.AutoHashMap(tcpip.TransportProtocolNumber, TransportProtocol),
    network_protocols: std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkProtocol),
    timer_queue: time.TimerQueue,

    pub fn init(allocator: std.mem.Allocator) !Stack {
        return .{
            .allocator = allocator,
            .nics = std.AutoHashMap(tcpip.NICID, *NIC).init(allocator),
            .endpoints = std.AutoHashMap(TransportEndpointID, TransportEndpoint).init(allocator),
            .link_addr_cache = std.AutoHashMap(tcpip.Address, tcpip.LinkAddress).init(allocator),
            .transport_protocols = std.AutoHashMap(tcpip.TransportProtocolNumber, TransportProtocol).init(allocator),
            .network_protocols = std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkProtocol).init(allocator),
            .timer_queue = .{},
        };
    }

    pub fn deinit(self: *Stack) void {
        var nic_it = self.nics.valueIterator();
        while (nic_it.next()) |nic| {
            nic.*.deinit();
            self.allocator.destroy(nic.*);
        }
        self.nics.deinit();
        self.endpoints.deinit();
        self.link_addr_cache.deinit();
        self.transport_protocols.deinit();
        self.network_protocols.deinit();
    }

    pub fn registerNetworkProtocol(self: *Stack, proto: NetworkProtocol) !void {
        try self.network_protocols.put(proto.number(), proto);
    }

    pub fn registerTransportProtocol(self: *Stack, proto: TransportProtocol) !void {
        try self.transport_protocols.put(proto.number(), proto);
    }

    pub fn addLinkAddress(self: *Stack, addr: tcpip.Address, link_addr: tcpip.LinkAddress) !void {
        try self.link_addr_cache.put(addr, link_addr);
    }

    pub fn registerTransportEndpoint(self: *Stack, id: TransportEndpointID, ep: TransportEndpoint) !void {
        try self.endpoints.put(id, ep);
    }

    pub fn findRoute(self: *Stack, nic_id: tcpip.NICID, local_addr: tcpip.Address, remote_addr: tcpip.Address, net_proto: tcpip.NetworkProtocolNumber) !Route {
        const nic = self.nics.get(nic_id) orelse return tcpip.Error.UnknownNICID;
        // In a real stack, we would check if net_proto matches the address family
        return Route{
            .local_address = local_addr,
            .remote_address = remote_addr,
            .local_link_address = nic.linkEP.linkAddress(),
            .net_proto = net_proto,
            .nic = nic,
        };
    }

    pub fn createNIC(self: *Stack, id: tcpip.NICID, ep: LinkEndpoint) !void {
        const nic = try self.allocator.create(NIC);
        nic.* = NIC.init(self, id, "", ep, false);
        try self.nics.put(id, nic);
        nic.attach();
    }

    pub fn transportDispatcher(self: *Stack) TransportDispatcher {
        return .{
            .ptr = self,
            .vtable = &.{
                .deliverTransportPacket = deliverTransportPacket,
            },
        };
    }

    pub fn deliverTransportPacket(ptr: *anyopaque, r: *const Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) void {
        const self = @as(*Stack, @ptrCast(@alignCast(ptr)));
        const proto = self.transport_protocols.get(protocol) orelse return;
        const ports = proto.parsePorts(pkt);
        
        const id = TransportEndpointID{
            .local_port = ports.dst,
            .local_address = r.local_address,
            .remote_port = ports.src,
            .remote_address = r.remote_address,
        };
        
        if (self.endpoints.get(id)) |ep| {
            ep.handlePacket(r, id, pkt);
        }
    }
};

test "Stack NIC creation" {
    const FakeLinkEndpoint = struct {
        address: [6]u8 = [_]u8{ 1, 2, 3, 4, 5, 6 },
        mtu_val: u32 = 1500,

        fn writePacket(ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            _ = ptr; _ = r; _ = protocol; _ = pkt;
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *NetworkDispatcher) void {
            _ = ptr; _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return self.address;
        }
        fn mtu(ptr: *anyopaque) u32 { 
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return self.mtu_val; 
        }
        fn setMTU(ptr: *anyopaque, m: u32) void { 
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            self.mtu_val = m;
        }
        fn capabilities(ptr: *anyopaque) LinkEndpointCapabilities { _ = ptr; return CapabilityNone; }
    };

    var fake_ep = FakeLinkEndpoint{};
    const ep = LinkEndpoint{
        .ptr = &fake_ep,
        .vtable = &.{
            .writePacket = FakeLinkEndpoint.writePacket,
            .attach = FakeLinkEndpoint.attach,
            .linkAddress = FakeLinkEndpoint.linkAddress,
            .mtu = FakeLinkEndpoint.mtu,
            .setMTU = FakeLinkEndpoint.setMTU,
            .capabilities = FakeLinkEndpoint.capabilities,
        },
    };

    var s = try Stack.init(std.testing.allocator);
    defer s.deinit();

    try s.createNIC(1, ep);
    try std.testing.expect(s.nics.contains(1));
}

test "Stack Transport Demux" {
    const FakeTransportEndpoint = struct {
        notified: bool = false,
        stack: *Stack,

        fn handlePacket(ptr: *anyopaque, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r; _ = id; _ = pkt;
            self.notified = true;
        }
        fn close(ptr: *anyopaque) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            self.stack.allocator.destroy(self);
        }
    };

    const FakeTransportProtocol = struct {
        fn number(ptr: *anyopaque) tcpip.TransportProtocolNumber { _ = ptr; return 17; }
        fn newEndpoint(ptr: *anyopaque, s: *Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
            _ = ptr; _ = s; _ = net_proto; _ = wait_queue;
            return tcpip.Error.NotPermitted;
        }
        fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) TransportProtocol.PortPair {
            _ = ptr; _ = pkt;
            return .{ .src = 1234, .dst = 80 };
        }
    };

    var s = try Stack.init(std.testing.allocator);
    defer s.deinit();

    var fake_proto_ptr = FakeTransportProtocol{};
    const proto = TransportProtocol{
        .ptr = &fake_proto_ptr,
        .vtable = &.{
            .number = FakeTransportProtocol.number,
            .newEndpoint = FakeTransportProtocol.newEndpoint,
            .parsePorts = FakeTransportProtocol.parsePorts,
        },
    };
    try s.registerTransportProtocol(proto);

    var fake_ep = try s.allocator.create(FakeTransportEndpoint);
    fake_ep.* = .{ .stack = &s };
    const ep = TransportEndpoint{
        .ptr = fake_ep,
        .vtable = &.{
            .handlePacket = FakeTransportEndpoint.handlePacket,
            .close = FakeTransportEndpoint.close,
        },
    };

    const id = TransportEndpointID{
        .local_port = 80,
        .local_address = .{ .v4 = .{ 127, 0, 0, 1 } },
        .remote_port = 1234,
        .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } },
    };
    try s.registerTransportEndpoint(id, ep);

    const r = Route{
        .local_address = .{ .v4 = .{ 127, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } },
        .local_link_address = .{ 0, 0, 0, 0, 0, 0 },
        .net_proto = 0x0800,
        .nic = undefined, // Not used in this test
    };

    Stack.deliverTransportPacket(&s, &r, 17, .{
        .data = .{ .views = &[_]buffer.View{}, .size = 0 },
        .header = undefined,
    });

    try std.testing.expect(fake_ep.notified);
    ep.close();
}

test "Jumbo Frames" {
    const FakeLinkEndpoint = struct {
        address: [6]u8 = [_]u8{ 1, 2, 3, 4, 5, 6 },
        mtu_val: u32 = 1500,
        last_pkt_size: usize = 0,

        fn writePacket(ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r; _ = protocol;
            self.last_pkt_size = pkt.data.size + pkt.header.usedLength();
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *NetworkDispatcher) void {
            _ = ptr; _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return self.address;
        }
        fn mtu(ptr: *anyopaque) u32 { 
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return self.mtu_val; 
        }
        fn setMTU(ptr: *anyopaque, m: u32) void { 
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            self.mtu_val = m;
        }
        fn capabilities(ptr: *anyopaque) LinkEndpointCapabilities { _ = ptr; return CapabilityNone; }
    };

    var fake_ep = FakeLinkEndpoint{};
    const ep = LinkEndpoint{
        .ptr = &fake_ep,
        .vtable = &.{
            .writePacket = FakeLinkEndpoint.writePacket,
            .attach = FakeLinkEndpoint.attach,
            .linkAddress = FakeLinkEndpoint.linkAddress,
            .mtu = FakeLinkEndpoint.mtu,
            .setMTU = FakeLinkEndpoint.setMTU,
            .capabilities = FakeLinkEndpoint.capabilities,
        },
    };

    var s = try Stack.init(std.testing.allocator);
    defer s.deinit();

    // Set Jumbo Frame MTU
    ep.setMTU(9000);
    try std.testing.expectEqual(@as(u32, 9000), ep.mtu());

    try s.createNIC(1, ep);
    
    // In a real scenario, we would use IPv4/IPv6 endpoints to send data.
    // Here we can verify that the LinkEndpoint accepts the setting.
    // To verify full stack support, we should try sending a large packet via IPv4.
    // However, IPv4Endpoint logic for fragmentation checks against NIC MTU.
    // Since we don't have IPv4 registered in this test context easily without more setup,
    // we rely on the fact that IPv4Endpoint calls nic.linkEP.mtu().
}
