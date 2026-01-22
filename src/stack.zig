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
        close: ?*const fn (ptr: *anyopaque) void = null,
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

    pub fn close(self: NetworkEndpoint) void {
        if (self.vtable.close) |f| f(self.ptr);
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

    pub fn hash(self: TransportEndpointID) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&self.local_port));
        switch (self.local_address) {
            .v4 => |v| h.update(&v),
            .v6 => |v| h.update(&v),
        }
        h.update(std.mem.asBytes(&self.remote_port));
        switch (self.remote_address) {
            .v4 => |v| h.update(&v),
            .v6 => |v| h.update(&v),
        }
        return h.final();
    }

    pub fn eq(self: TransportEndpointID, other: TransportEndpointID) bool {
        return self.local_port == other.local_port and
            self.local_address.eq(other.local_address) and
            self.remote_port == other.remote_port and
            self.remote_address.eq(other.remote_address);
    }
};

pub const TransportEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        handlePacket: *const fn (ptr: *anyopaque, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void,
        close: *const fn (ptr: *anyopaque) void,
        incRef: *const fn (ptr: *anyopaque) void,
        decRef: *const fn (ptr: *anyopaque) void,
    };

    pub fn handlePacket(self: TransportEndpoint, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        return self.vtable.handlePacket(self.ptr, r, id, pkt);
    }

    pub fn close(self: TransportEndpoint) void {
        return self.vtable.close(self.ptr);
    }

    pub fn incRef(self: TransportEndpoint) void {
        return self.vtable.incRef(self.ptr);
    }

    pub fn decRef(self: TransportEndpoint) void {
        return self.vtable.decRef(self.ptr);
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
        handlePacket: ?*const fn (ptr: *anyopaque, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void = null,
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
    dispatcher: NetworkDispatcher = undefined,

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
        var it = self.network_endpoints.valueIterator();
        while (it.next()) |ep| {
            ep.close();
        }
        self.addresses.deinit();
        self.network_endpoints.deinit();
    }

    pub fn addAddress(self: *NIC, addr: tcpip.ProtocolAddress) !void {
        try self.addresses.append(addr);
        if (self.stack.network_protocols.get(addr.protocol)) |proto| {
            const ep = try proto.newEndpoint(self, addr.address_with_prefix, self.stack.transportDispatcher());
            if (self.network_endpoints.get(addr.protocol)) |old_ep| {
                old_ep.close();
            }
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
        self.dispatcher = NetworkDispatcher{
            .ptr = self,
            .vtable = &.{
                .deliverNetworkPacket = deliverNetworkPacket,
            },
        };
        self.linkEP.attach(&self.dispatcher);
    }

    fn deliverNetworkPacket(ptr: *anyopaque, remote: tcpip.LinkAddress, local: tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        const self = @as(*NIC, @ptrCast(@alignCast(ptr)));
        // std.debug.print("NIC: Received packet proto=0x{x} remote={any} local={any}\n", .{protocol, remote, local});
        
        self.stack.mutex.lock();
        const proto_opt = self.stack.network_protocols.get(protocol);
        self.stack.mutex.unlock();
        
        const proto = proto_opt orelse return;
        const ep = self.network_endpoints.get(protocol) orelse return;
        
        const addrs = proto.parseAddresses(pkt);
        
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
    route_entry: ?*const RouteEntry = null,

    pub fn writePacket(self: *Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        // Determine next hop (gateway if route has one, otherwise destination)
        const next_hop = if (self.route_entry) |entry| entry.gateway else self.remote_address;

        if (self.remote_link_address == null) {
            self.nic.stack.mutex.lock();
            const link_addr_opt = self.nic.stack.link_addr_cache.get(next_hop);
            self.nic.stack.mutex.unlock();
 
            if (link_addr_opt) |link_addr| {
                self.remote_link_address = link_addr;
            } else {
                self.nic.stack.mutex.lock();
                var it = self.nic.stack.network_protocols.valueIterator();
                while (it.next()) |proto| {
                    proto.linkAddressRequest(next_hop, self.local_address, self.nic) catch {};
                }
                self.nic.stack.mutex.unlock();
                return tcpip.Error.WouldBlock;
            }
        }
         
        const net_ep = self.nic.network_endpoints.get(self.net_proto) orelse return tcpip.Error.NoRoute;
        return net_ep.writePacket(self, protocol, pkt);
    }
};

// Route entry in the routing table (gVisor-style routing)
pub const RouteEntry = struct {
    destination: tcpip.Subnet,
    gateway: tcpip.Address,
    nic: tcpip.NICID,
    mtu: u32,
};

// Route table with longest-prefix matching
const RouteTable = struct {
    routes: std.ArrayList(RouteEntry),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) RouteTable {
        return .{
            .routes = std.ArrayList(RouteEntry).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *RouteTable) void {
        self.routes.deinit();
    }

    // Add a route to the table (inserted in prefix-length order)
    pub fn addRoute(self: *RouteTable, route: RouteEntry) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Find insertion point (sorted by prefix length, longest first)
        var i: usize = 0;
        for (self.routes.items) |r| {
            if (r.destination.gt(route.destination.prefix)) {
                break;
            }
            i += 1;
        }

        try self.routes.insert(i, route);
    }

    // Remove routes matching a predicate
    pub fn removeRoutes(self: *RouteTable, match: *const fn (route: RouteEntry) bool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        var i: usize = 0;
        while (i < self.routes.items.len) {
            if (match(self.routes.items[i])) {
                _ = self.routes.swapRemove(i);
                count += 1;
            } else {
                i += 1;
            }
        }
        return count;
    }

    // Find best matching route using longest-prefix matching
    pub fn findRoute(self: *RouteTable, dest: tcpip.Address, _: tcpip.NICID) ?*RouteEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        var best_route: ?*RouteEntry = null;
        for (self.routes.items) |*route_entry| {
            // Check if destination matches this route
            if (route_entry.destination.contains(dest)) {
                // Check NIC match if specified
                if (best_route == null or route_entry.destination.gt(best_route.?.destination.prefix)) {
                    best_route = route_entry;
                }
            }
        }

        // Return best route (or null if no match)
        return best_route;
    }

    // Get all routes
    pub fn getRoutes(self: *RouteTable) []const RouteEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.routes.items;
    }
};

pub const TransportTable = struct {
    const num_shards = 256;
    
    shards: [num_shards]Shard,

    const Shard = struct {
        mutex: std.Thread.Mutex = .{},
        endpoints: std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80),
    };

    const TransportContext = struct {
        pub fn hash(_: TransportContext, key: TransportEndpointID) u64 {
            return key.hash();
        }
        pub fn eql(_: TransportContext, a: TransportEndpointID, b: TransportEndpointID) bool {
            return a.eq(b);
        }
    };

    pub fn init(allocator: std.mem.Allocator) TransportTable {
        var self: TransportTable = undefined;
        for (&self.shards) |*shard| {
            shard.* = .{
                .endpoints = std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80).init(allocator),
            };
        }
        return self;
    }

    pub fn deinit(self: *TransportTable) void {
        for (&self.shards) |*shard| {
            shard.endpoints.deinit();
        }
    }

    fn getShard(self: *TransportTable, id: TransportEndpointID) *Shard {
        return &self.shards[id.hash() % num_shards];
    }

    pub fn put(self: *TransportTable, id: TransportEndpointID, ep: TransportEndpoint) !void {
        const shard = self.getShard(id);
        shard.mutex.lock();
        defer shard.mutex.unlock();
        try shard.endpoints.put(id, ep);
    }

    pub fn remove(self: *TransportTable, id: TransportEndpointID) bool {
        const shard = self.getShard(id);
        shard.mutex.lock();
        defer shard.mutex.unlock();
        return shard.endpoints.remove(id);
    }

    pub fn get(self: *TransportTable, id: TransportEndpointID) ?TransportEndpoint {
        const shard = self.getShard(id);
        shard.mutex.lock();
        defer shard.mutex.unlock();
        const ep = shard.endpoints.get(id);
        if (ep) |e| e.incRef();
        return ep;
    }
};

pub const Stack = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    nics: std.AutoHashMap(tcpip.NICID, *NIC),
    endpoints: TransportTable,
    link_addr_cache: std.AutoHashMap(tcpip.Address, tcpip.LinkAddress),
    transport_protocols: std.AutoHashMap(tcpip.TransportProtocolNumber, TransportProtocol),
    network_protocols: std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkProtocol),
    route_table: RouteTable,
    timer_queue: time.TimerQueue,

    pub fn init(allocator: std.mem.Allocator) !Stack {
        return .{
            .allocator = allocator,
            .nics = std.AutoHashMap(tcpip.NICID, *NIC).init(allocator),
            .endpoints = TransportTable.init(allocator),
            .link_addr_cache = std.AutoHashMap(tcpip.Address, tcpip.LinkAddress).init(allocator),
            .transport_protocols = std.AutoHashMap(tcpip.TransportProtocolNumber, TransportProtocol).init(allocator),
            .network_protocols = std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkProtocol).init(allocator),
            .route_table = RouteTable.init(allocator),
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
        self.route_table.deinit();
    }

    pub fn registerNetworkProtocol(self: *Stack, proto: NetworkProtocol) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.network_protocols.put(proto.number(), proto);
    }

    pub fn registerTransportProtocol(self: *Stack, proto: TransportProtocol) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.transport_protocols.put(proto.number(), proto);
    }

    pub fn addLinkAddress(self: *Stack, addr: tcpip.Address, link_addr: tcpip.LinkAddress) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.link_addr_cache.put(addr, link_addr);
    }

    pub fn registerTransportEndpoint(self: *Stack, id: TransportEndpointID, ep: TransportEndpoint) !void {
        try self.endpoints.put(id, ep);
    }

    pub fn unregisterTransportEndpoint(self: *Stack, id: TransportEndpointID) void {
        _ = self.endpoints.remove(id);
    }

    // Find route using longest-prefix matching in routing table
    pub fn findRoute(self: *Stack, nic_id: tcpip.NICID, local_addr: tcpip.Address, remote_addr: tcpip.Address, net_proto: tcpip.NetworkProtocolNumber) !Route {
        if (nic_id != 0) {
            self.mutex.lock();
            const nic_opt = self.nics.get(nic_id);
            self.mutex.unlock();
             
            const nic = nic_opt orelse return tcpip.Error.UnknownNICID;
            
            return Route{
                .local_address = local_addr,
                .remote_address = remote_addr,
                .local_link_address = nic.linkEP.linkAddress(),
                .net_proto = net_proto,
                .nic = nic,
                .route_entry = null,
            };
        }

        // Find route in routing table (longest-prefix matching)
        const route_entry = self.route_table.findRoute(remote_addr, nic_id) orelse return tcpip.Error.NoRoute;
        
        self.mutex.lock();
        const nic_opt = self.nics.get(route_entry.nic);
        self.mutex.unlock();
         
        const nic = nic_opt orelse return tcpip.Error.UnknownNICID;
        
        return Route{
            .local_address = local_addr,
            .remote_address = remote_addr,
            .local_link_address = nic.linkEP.linkAddress(),
            .net_proto = net_proto,
            .nic = nic,
            .next_hop = route_entry.gateway,
            .route_entry = route_entry,
        };
    }

    // Add a route to the routing table
    pub fn addRoute(self: *Stack, route: RouteEntry) !void {
        try self.route_table.addRoute(route);
    }

    // Set entire route table (replaces existing)
    pub fn setRouteTable(self: *Stack, routes: []const RouteEntry) !void {
        self.route_table.mutex.lock();
        self.route_table.routes.clearRetainingCapacity();
        for (routes) |route| {
            try self.route_table.routes.append(route);
        }
        self.route_table.mutex.unlock();
    }

    // Remove routes matching a predicate
    pub fn removeRoutes(self: *Stack, match: *const fn (route: RouteEntry) bool) usize {
        return self.route_table.removeRoutes(match);
    }

    // Get all routes
    pub fn getRouteTable(self: *Stack) []const RouteEntry {
        return self.route_table.getRoutes();
    }

    pub fn createNIC(self: *Stack, id: tcpip.NICID, ep: LinkEndpoint) !void {
        const nic = try self.allocator.create(NIC);
        nic.* = NIC.init(self, id, "", ep, false);
        
        self.mutex.lock();
        try self.nics.put(id, nic);
        self.mutex.unlock();
        
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
        
        self.mutex.lock();
        const proto_opt = self.transport_protocols.get(protocol);
        self.mutex.unlock();
        
        const proto = proto_opt orelse return;
        const ports = proto.parsePorts(pkt);
        
        const id = TransportEndpointID{
            .local_port = ports.dst,
            .local_address = r.local_address,
            .remote_port = ports.src,
            .remote_address = r.remote_address,
        };
        
        const ep_opt = self.endpoints.get(id);

        if (ep_opt) |ep| {
            ep.handlePacket(r, id, pkt);
            ep.decRef();
        } else {
            // Try global handler first (for ICMP, etc)
            if (proto.vtable.handlePacket) |handle| {
                handle(proto.ptr, r, id, pkt);
                return;
            }

            // Try wildcard match for listeners
            const listener_id = TransportEndpointID{
                .local_port = ports.dst,
                .local_address = r.local_address,
                .remote_port = 0,
                .remote_address = switch (r.local_address) {
                    .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                    .v6 => .{ .v6 = [_]u8{0} ** 16 },
                },
            };
            
            const listener_opt = self.endpoints.get(listener_id);
            
            if (listener_opt) |ep| {
                ep.handlePacket(r, id, pkt);
                ep.decRef();
            } else {
                // Try INADDR_ANY (0.0.0.0 / ::)
                const any_addr = switch (r.local_address) {
                    .v4 => tcpip.Address{ .v4 = .{ 0, 0, 0, 0 } },
                    .v6 => tcpip.Address{ .v6 = [_]u8{0} ** 16 },
                };
                
                const any_id = TransportEndpointID{
                    .local_port = ports.dst,
                    .local_address = any_addr,
                    .remote_port = 0,
                    .remote_address = switch (r.local_address) {
                        .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                        .v6 => .{ .v6 = [_]u8{0} ** 16 },
                    },
                };
                
                if (self.endpoints.get(any_id)) |ep| {
                    ep.handlePacket(r, id, pkt);
                    ep.decRef();
                } else {
                    if (protocol == 17) {
                         std.debug.print("Stack: No endpoint for UDP port {}. Looked for exact: {}, listener: {}, any: {}\n", .{ports.dst, id.hash(), listener_id.hash(), any_id.hash()});
                         // print ids
                         std.debug.print("Exact: local={any}:{} remote={any}:{}\n", .{id.local_address, id.local_port, id.remote_address, id.remote_port});
                         std.debug.print("Any: local={any}:{} remote={any}:{}\n", .{any_id.local_address, any_id.local_port, any_id.remote_address, any_id.remote_port});
                    }
                }
            }
        }
    }
};
