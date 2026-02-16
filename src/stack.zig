const std = @import("std");
const tcpip = @import("tcpip.zig");
const buffer = @import("buffer.zig");
const header = @import("header.zig");
const waiter = @import("waiter.zig");
const time = @import("time.zig");
const log = @import("log.zig").scoped(.stack);
const stats = @import("stats.zig");

pub const LinkEndpointCapabilities = u32;
pub const CapabilityNone: LinkEndpointCapabilities = 0;
pub const CapabilityLoopback: LinkEndpointCapabilities = 1 << 0;
pub const CapabilityResolutionRequired: LinkEndpointCapabilities = 1 << 1;

pub const LinkEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        writePacket: *const fn (ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void,
        writePackets: ?*const fn (ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void = null,
        flush: ?*const fn (ptr: *anyopaque) void = null,
        attach: *const fn (ptr: *anyopaque, dispatcher: *NetworkDispatcher) void,
        linkAddress: *const fn (ptr: *anyopaque) tcpip.LinkAddress,
        mtu: *const fn (ptr: *anyopaque) u32,
        setMTU: *const fn (ptr: *anyopaque, mtu: u32) void,
        capabilities: *const fn (ptr: *anyopaque) LinkEndpointCapabilities,
        close: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn writePacket(self: LinkEndpoint, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        return self.vtable.writePacket(self.ptr, r, protocol, pkt);
    }

    pub fn writePackets(self: LinkEndpoint, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        if (self.vtable.writePackets) |f| {
            return f(self.ptr, r, protocol, packets);
        }
        for (packets) |p| {
            try self.vtable.writePacket(self.ptr, r, protocol, p);
        }
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
    pub fn close(self: LinkEndpoint) void {
        if (self.vtable.close) |f| f(self.ptr);
    }
    pub fn flush(self: LinkEndpoint) void {
        if (self.vtable.flush) |f| f(self.ptr);
    }
};

pub const NetworkDispatcher = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        deliverNetworkPacket: *const fn (ptr: *anyopaque, remote: *const tcpip.LinkAddress, local: *const tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void,
    };

    pub fn deliverNetworkPacket(self: NetworkDispatcher, remote: *const tcpip.LinkAddress, local: *const tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        return self.vtable.deliverNetworkPacket(self.ptr, remote, local, protocol, pkt);
    }
};

pub const NetworkEndpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        writePacket: *const fn (ptr: *anyopaque, r: *const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void,
        writePackets: ?*const fn (ptr: *anyopaque, r: *const Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void = null,
        handlePacket: *const fn (ptr: *anyopaque, r: *const Route, pkt: tcpip.PacketBuffer) void,
        mtu: *const fn (ptr: *anyopaque) u32,
        close: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn writePacket(self: NetworkEndpoint, r: *const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        return self.vtable.writePacket(self.ptr, r, protocol, pkt);
    }

    pub fn writePackets(self: NetworkEndpoint, r: *const Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        if (self.vtable.writePackets) |f| {
            return f(self.ptr, r, protocol, packets);
        }
        for (packets) |p| {
            try self.vtable.writePacket(self.ptr, r, protocol, p);
        }
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
        deinit: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn deinit(self: NetworkProtocol) void {
        if (self.vtable.deinit) |f| f(self.ptr);
    }

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
    transport_protocol: tcpip.TransportProtocolNumber = 0,

    pub fn hash(self: TransportEndpointID) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&self.transport_protocol));
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
        return self.transport_protocol == other.transport_protocol and
            self.local_port == other.local_port and
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
        notify: ?*const fn (ptr: *anyopaque, mask: waiter.EventMask) void = null,
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

    pub fn notify(self: TransportEndpoint, mask: waiter.EventMask) void {
        if (self.vtable.notify) |f| {
            return f(self.ptr, mask);
        }
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
        deinit: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn deinit(self: TransportProtocol) void {
        if (self.vtable.deinit) |f| f(self.ptr);
    }

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
        self.linkEP.close();
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

    fn deliverNetworkPacket(ptr: *anyopaque, remote: *const tcpip.LinkAddress, local: *const tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        const start_processing: i64 = @intCast(std.time.nanoTimestamp());
        defer {
            const end_processing: i64 = @intCast(std.time.nanoTimestamp());
            if (pkt.timestamp_ns != 0) {
                stats.global_stats.latency.link_layer.record(@as(i64, @intCast(start_processing - pkt.timestamp_ns)));
                stats.global_stats.latency.network_layer.record(@as(i64, @intCast(end_processing - start_processing)));
            }
        }
        const self = @as(*NIC, @ptrCast(@alignCast(ptr)));
        // log.debug("NIC: Received packet proto=0x{x} remote={any} local={any}", .{ protocol, remote, local });

        if (remote.eq(self.linkEP.linkAddress())) return;

        const proto_opt = self.stack.network_protocols.get(protocol);

        if (proto_opt == null) return;
        const proto = proto_opt.?;

        const ep_opt = self.network_endpoints.get(protocol);

        if (ep_opt == null) return;
        const ep = ep_opt.?;

        const addrs = proto.parseAddresses(pkt);
        if (!addrs.src.isAny()) {
            if (self.stack.link_addr_cache.get(addrs.src)) |prev| {
                if (!prev.eq(remote.*)) {
                    self.stack.addLinkAddress(addrs.src, remote.*) catch {};
                }
            } else {
                self.stack.addLinkAddress(addrs.src, remote.*) catch {};
            }
        }

        const r = Route{
            .local_address = addrs.dst,
            .remote_address = addrs.src,
            .local_link_address = local.*,
            .remote_link_address = remote.*,
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
    generation: u64 = 0,

    pub fn writePacket(self: *Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        // Determine next hop (gateway if route has one, otherwise destination)
        const next_hop = self.next_hop orelse self.remote_address;

        if (self.remote_link_address == null) {
            const link_addr_opt = self.nic.stack.link_addr_cache.get(next_hop);

            if (link_addr_opt) |link_addr| {
                self.remote_link_address = link_addr;
            } else {
                var it = self.nic.stack.network_protocols.valueIterator();
                while (it.next()) |proto| {
                    proto.linkAddressRequest(next_hop, self.local_address, self.nic) catch {};
                }
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

    pub fn init(allocator: std.mem.Allocator) RouteTable {
        return .{
            .routes = std.ArrayList(RouteEntry).init(allocator),
        };
    }

    pub fn deinit(self: *RouteTable) void {
        self.routes.deinit();
    }

    // Add a route to the table (inserted in prefix-length order)
    pub fn addRoute(self: *RouteTable, route: RouteEntry) !void {
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
        return self.routes.items;
    }
};

pub const TransportTable = struct {
    shards: [256]std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80),

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
            shard.* = std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80).init(allocator);
        }
        return self;
    }

    pub fn deinit(self: *TransportTable) void {
        for (&self.shards) |*shard| {
            shard.deinit();
        }
    }

    pub fn getShard(self: *TransportTable, id: TransportEndpointID) *std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80) {
        return &self.shards[id.hash() % 256];
    }

    pub fn put(self: *TransportTable, id: TransportEndpointID, ep: TransportEndpoint) !void {
        try self.getShard(id).put(id, ep);
    }

    pub fn fetchRemove(self: *TransportTable, id: TransportEndpointID) ?std.HashMap(TransportEndpointID, TransportEndpoint, TransportContext, 80).KV {
        return self.getShard(id).fetchRemove(id);
    }

    pub fn remove(self: *TransportTable, id: TransportEndpointID) bool {
        return self.getShard(id).remove(id);
    }

    pub fn get(self: *TransportTable, id: TransportEndpointID) ?TransportEndpoint {
        const ep = self.getShard(id).get(id);
        if (ep) |e| e.incRef();
        return ep;
    }
};

pub const LinkCacheEntry = struct {
    link_addr: tcpip.LinkAddress,
    timestamp: i64, // milliTimestamp() when entry was last confirmed
    confirmed: bool = false, // true = solicited reply or traffic seen from this host
};

pub const Stack = struct {
    allocator: std.mem.Allocator,
    nics: std.AutoHashMap(tcpip.NICID, *NIC),
    endpoints: TransportTable,
    link_addr_cache: std.HashMap(tcpip.Address, LinkCacheEntry, AddressContext, 80),
    transport_protocols: std.AutoHashMap(tcpip.TransportProtocolNumber, TransportProtocol),
    network_protocols: std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkProtocol),
    route_table: RouteTable,
    timer_queue: time.TimerQueue,
    cluster_pool: buffer.ClusterPool,
    ephemeral_port: u16,
    tcp_msl: u64 = 30000,
    next_nic_id: tcpip.NICID = 1,
    arp_confirmed_ttl: i64 = 60_000, // 60s for confirmed entries (Linux default)
    arp_unconfirmed_ttl: i64 = 3_000, // 3s for unconfirmed entries (Linux default)
    arp_gc_timer: time.Timer = undefined,
    route_generation: u64 = 0,

    pub const AddressContext = struct {
        pub fn hash(_: AddressContext, key: tcpip.Address) u64 {
            return key.hash();
        }
        pub fn eql(_: AddressContext, a: tcpip.Address, b: tcpip.Address) bool {
            return a.eq(b);
        }
    };

    pub fn init(allocator: std.mem.Allocator) !Stack {
        var cluster_pool = buffer.ClusterPool.init(allocator);
        try cluster_pool.prewarm(1024);
        return .{
            .allocator = allocator,
            .nics = std.AutoHashMap(tcpip.NICID, *NIC).init(allocator),
            .endpoints = TransportTable.init(allocator),
            .link_addr_cache = std.HashMap(tcpip.Address, LinkCacheEntry, AddressContext, 80).init(allocator),
            .transport_protocols = std.AutoHashMap(tcpip.TransportProtocolNumber, TransportProtocol).init(allocator),
            .network_protocols = std.AutoHashMap(tcpip.NetworkProtocolNumber, NetworkProtocol).init(allocator),
            .route_table = RouteTable.init(allocator),
            .timer_queue = .{},
            .cluster_pool = cluster_pool,
            .ephemeral_port = 32768,
            .tcp_msl = 30000,
            .next_nic_id = 1,
            .route_generation = 0,
        };
    }

    pub fn allocNicId(self: *Stack) tcpip.NICID {
        const id = self.next_nic_id;
        self.next_nic_id += 1;
        return id;
    }

    pub fn deinit(self: *Stack) void {
        var shard_idx: usize = 0;
        while (shard_idx < 256) : (shard_idx += 1) {
            var shard = &self.endpoints.shards[shard_idx];
            var it = shard.valueIterator();
            while (it.next()) |ep| {
                // decRef might destroy the endpoint, but we clear the map after
                // so we don't care about map corruption here.
                // However, we MUST NOT use fetchRemove inside the loop.
                ep.decRef();
            }
            shard.clearAndFree();
        }
        self.endpoints.deinit();
        self.cluster_pool.deinit();
        var nic_it = self.nics.valueIterator();
        while (nic_it.next()) |nic| {
            nic.*.deinit();
            self.allocator.destroy(nic.*);
        }
        self.nics.deinit();
        self.link_addr_cache.deinit();

        var transport_it = self.transport_protocols.valueIterator();
        while (transport_it.next()) |proto| {
            proto.deinit();
        }
        self.transport_protocols.deinit();

        var network_it = self.network_protocols.valueIterator();
        while (network_it.next()) |proto| {
            proto.deinit();
        }
        self.network_protocols.deinit();

        self.route_table.deinit();
    }

    pub fn registerNetworkProtocol(self: *Stack, proto: NetworkProtocol) !void {
        try self.network_protocols.put(proto.number(), proto);
    }

    pub fn registerTransportProtocol(self: *Stack, proto: TransportProtocol) !void {
        try self.transport_protocols.put(proto.number(), proto);
    }

    pub fn getLinkAddress(self: *Stack, addr: tcpip.Address) ?tcpip.LinkAddress {
        const entry = self.link_addr_cache.get(addr) orelse return null;
        return entry.link_addr;
    }

    pub fn addLinkAddress(self: *Stack, addr: tcpip.Address, link_addr: tcpip.LinkAddress) !void {
        var is_new = false;
        if (self.link_addr_cache.get(addr)) |prev| {
            if (prev.link_addr.eq(link_addr)) {
                // Same MAC — just refresh timestamp
                const entry_ptr = self.link_addr_cache.getPtr(addr).?;
                entry_ptr.timestamp = std.time.milliTimestamp();
                entry_ptr.confirmed = true;
                return;
            }
        } else {
            is_new = true;
        }
        try self.link_addr_cache.put(addr, .{
            .link_addr = link_addr,
            .timestamp = std.time.milliTimestamp(),
            .confirmed = true,
        });

        // Start GC timer if first entry
        if (self.link_addr_cache.count() == 1) {
            self.arp_gc_timer = time.Timer.init(arpGcTimer, self);
            self.timer_queue.schedule(&self.arp_gc_timer, 10_000);
        }

        if (is_new) {
            for (&self.endpoints.shards) |*shard| {
                var it = shard.valueIterator();
                while (it.next()) |ep| {
                    ep.notify(waiter.EventOut);
                }
            }
        }
    }

    fn arpGcTimer(ptr: *anyopaque) void {
        const self = @as(*Stack, @ptrCast(@alignCast(ptr)));
        const now = std.time.milliTimestamp();
        var it = self.link_addr_cache.iterator();
        while (it.next()) |entry| {
            const ttl = if (entry.value_ptr.confirmed) self.arp_confirmed_ttl else self.arp_unconfirmed_ttl;
            if (now - entry.value_ptr.timestamp >= ttl) {
                self.link_addr_cache.removeByPtr(entry.key_ptr);
            }
        }
        // Reschedule if cache not empty
        if (self.link_addr_cache.count() > 0) {
            self.timer_queue.schedule(&self.arp_gc_timer, 10_000); // Every 10s
        }
    }

    pub fn registerTransportEndpoint(self: *Stack, id: TransportEndpointID, ep: TransportEndpoint) !void {
        try self.endpoints.put(id, ep);
        ep.incRef();
    }

    pub fn unregisterTransportEndpoint(self: *Stack, id: TransportEndpointID) void {
        const ep_opt = self.endpoints.fetchRemove(id);
        if (ep_opt) |kv| {
            kv.value.decRef();
        }
    }

    pub fn getNextEphemeralPort(self: *Stack) u16 {
        const port = self.ephemeral_port;
        if (self.ephemeral_port == 65535) {
            self.ephemeral_port = 32768;
        } else {
            self.ephemeral_port += 1;
        }
        return port;
    }

    // Find route using longest-prefix matching in routing table
    // Find route using longest-prefix matching in routing table
    pub fn findRoute(self: *Stack, nic_id: tcpip.NICID, local_addr: tcpip.Address, remote_addr: tcpip.Address, net_proto: tcpip.NetworkProtocolNumber) !Route {
        if (nic_id != 0) {
            const nic_opt = self.nics.get(nic_id);
            const next_hop = remote_addr;
            const link_addr_opt = if (self.link_addr_cache.get(next_hop)) |entry| entry.link_addr else null;

            const nic = nic_opt orelse return tcpip.Error.UnknownNICID;

            return Route{
                .local_address = local_addr,
                .remote_address = remote_addr,
                .local_link_address = nic.linkEP.linkAddress(),
                .remote_link_address = link_addr_opt,
                .net_proto = net_proto,
                .nic = nic,
                .next_hop = null,
                .route_entry = null,
                .generation = self.route_generation,
            };
        }

        // Find route in routing table (longest-prefix matching)
        const route_entry = self.route_table.findRoute(remote_addr, nic_id) orelse return tcpip.Error.NoRoute;

        const nic_opt = self.nics.get(route_entry.nic);
        const next_hop = route_entry.gateway;
        const link_addr_opt = if (next_hop.isAny()) (if (self.link_addr_cache.get(remote_addr)) |entry| entry.link_addr else null) else (if (self.link_addr_cache.get(next_hop)) |entry| entry.link_addr else null);

        const nic = nic_opt orelse return tcpip.Error.UnknownNICID;

        var final_local_addr = local_addr;
        if (final_local_addr.isAny()) {
            // Find address on the NIC that matches the protocol
            for (nic.addresses.items) |addr| {
                if (addr.protocol == net_proto) {
                    final_local_addr = addr.address_with_prefix.address;
                    break;
                }
            }
        }

        return Route{
            .local_address = final_local_addr,
            .remote_address = remote_addr,
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = link_addr_opt,
            .net_proto = net_proto,
            .nic = nic,
            .next_hop = if (next_hop.isAny()) null else next_hop,
            .route_entry = route_entry,
            .generation = self.route_generation,
        };
    }

    // Add a route to the routing table
    pub fn addRoute(self: *Stack, route: RouteEntry) !void {
        try self.route_table.addRoute(route);
        self.route_generation += 1;
    }

    // Set entire route table (replaces existing)
    pub fn setRouteTable(self: *Stack, routes: []const RouteEntry) !void {
        self.route_table.routes.clearRetainingCapacity();
        for (routes) |route| {
            try self.route_table.routes.append(route);
        }
        self.route_generation += 1;
    }

    // Remove routes matching a predicate
    pub fn removeRoutes(self: *Stack, match: *const fn (route: RouteEntry) bool) usize {
        const removed = self.route_table.removeRoutes(match);
        if (removed > 0) self.route_generation += 1;
        return removed;
    }

    pub fn getRouteTable(self: *Stack) []const RouteEntry {
        return self.route_table.getRoutes();
    }

    pub fn flush(self: *Stack) void {
        var it = self.nics.valueIterator();
        while (it.next()) |nic| {
            nic.*.linkEP.flush();
        }
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
        defer {
            const end_processing: i64 = @intCast(std.time.nanoTimestamp());
            if (pkt.timestamp_ns != 0) {
                stats.global_stats.latency.transport_dispatch.record(end_processing - pkt.timestamp_ns);
            }
        }
        const self = @as(*Stack, @ptrCast(@alignCast(ptr)));

        const proto_opt = self.transport_protocols.get(protocol);

        const proto = proto_opt orelse return;
        const ports = proto.parsePorts(pkt);

        const id = TransportEndpointID{
            .local_port = ports.dst,
            .local_address = r.local_address,
            .remote_port = ports.src,
            .remote_address = r.remote_address,
            .transport_protocol = protocol,
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
                .transport_protocol = protocol,
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
                    .transport_protocol = protocol,
                };

                if (self.endpoints.get(any_id)) |ep| {
                    ep.handlePacket(r, id, pkt);
                    ep.decRef();
                } else {
                    if (protocol == 17) {
                        stats.global_stats.udp.no_port += 1;
                        stats.global_stats.udp.dropped_packets += 1;
                        log.warn("Stack: No endpoint for UDP port {}. Looked for exact: {}, listener: {}, any: {}", .{ ports.dst, id.hash(), listener_id.hash(), any_id.hash() });
                        log.debug("Exact: local={any}:{} remote={any}:{}", .{ id.local_address, id.local_port, id.remote_address, id.remote_port });
                        log.debug("Any: local={any}:{} remote={any}:{}", .{ any_id.local_address, any_id.local_port, any_id.remote_address, any_id.remote_port });
                    }
                }
            }
        }
    }
};

test "Stack.findRoute 0.0.0.0 bind" {
    const allocator = std.testing.allocator;
    var s = try Stack.init(allocator);
    defer s.deinit();

    // Mock LinkEndpoint
    var fake_link = struct {
        fn writePacket(_: *anyopaque, _: ?*const Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
            return;
        }
        fn attach(_: *anyopaque, _: *NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) LinkEndpointCapabilities {
            return 0;
        }
    }{};

    const link_ep = LinkEndpoint{
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

    const local_ip = tcpip.Address{ .v4 = .{ 10, 0, 0, 1 } };
    try nic.addAddress(.{
        .protocol = 0x0800,
        .address_with_prefix = .{ .address = local_ip, .prefix_len = 24 },
    });

    // Add a route
    try s.addRoute(.{
        .destination = .{ .address = .{ .v4 = .{ 10, 0, 0, 0 } }, .prefix = 24 },
        .gateway = .{ .v4 = .{ 0, 0, 0, 0 } },
        .nic = 1,
        .mtu = 1500,
    });

    // Test findRoute with any (0.0.0.0) source address
    const remote_ip = tcpip.Address{ .v4 = .{ 10, 0, 0, 2 } };
    const route = try s.findRoute(0, .{ .v4 = .{ 0, 0, 0, 0 } }, remote_ip, 0x0800);

    try std.testing.expect(route.local_address.eq(local_ip));
    try std.testing.expect(route.remote_address.eq(remote_ip));
    try std.testing.expectEqual(@as(tcpip.NICID, 1), route.nic.id);
}

test "Stack NIC creation" {
    const FakeLinkEndpoint = struct {
        address: [6]u8 = [_]u8{ 1, 2, 3, 4, 5, 6 },
        mtu_val: u32 = 1500,

        fn writePacket(ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            _ = ptr;
            _ = r;
            _ = protocol;
            _ = pkt;
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return .{ .addr = self.address };
        }
        fn mtu(ptr: *anyopaque) u32 {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return self.mtu_val;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            self.mtu_val = m;
        }
        fn capabilities(ptr: *anyopaque) LinkEndpointCapabilities {
            _ = ptr;
            return CapabilityNone;
        }
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
        ref_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),

        fn handlePacket(ptr: *anyopaque, r: *const Route, id: TransportEndpointID, pkt: tcpip.PacketBuffer) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r;
            _ = id;
            _ = pkt;
            self.notified = true;
        }
        fn close(ptr: *anyopaque) void {
            decRef(ptr);
        }
        fn incRef(ptr: *anyopaque) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = self.ref_count.fetchAdd(1, .monotonic);
        }
        fn decRef(ptr: *anyopaque) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            if (self.ref_count.fetchSub(1, .release) == 1) {
                self.ref_count.fence(.acquire);
                self.stack.allocator.destroy(self);
            }
        }
    };

    const FakeTransportProtocol = struct {
        fn number(ptr: *anyopaque) tcpip.TransportProtocolNumber {
            _ = ptr;
            return 17;
        }
        fn newEndpoint(ptr: *anyopaque, s: *Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
            _ = ptr;
            _ = s;
            _ = net_proto;
            _ = wait_queue;
            return tcpip.Error.NotPermitted;
        }
        fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) TransportProtocol.PortPair {
            _ = ptr;
            _ = pkt;
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

    const fake_ep_ptr = try s.allocator.create(FakeTransportEndpoint);
    fake_ep_ptr.* = .{ .stack = &s };
    const ep = TransportEndpoint{
        .ptr = fake_ep_ptr,
        .vtable = &.{
            .handlePacket = FakeTransportEndpoint.handlePacket,
            .close = FakeTransportEndpoint.close,
            .incRef = FakeTransportEndpoint.incRef,
            .decRef = FakeTransportEndpoint.decRef,
        },
    };

    const id = TransportEndpointID{
        .local_port = 80,
        .local_address = .{ .v4 = .{ 127, 0, 0, 1 } },
        .remote_port = 1234,
        .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } },
        .transport_protocol = 17,
    };
    try s.registerTransportEndpoint(id, ep);

    const r = Route{
        .local_address = .{ .v4 = .{ 127, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } },
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = undefined,
    };

    Stack.deliverTransportPacket(&s, &r, 17, .{
        .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
        .header = buffer.Prependable.init(&[_]u8{}),
    });

    try std.testing.expect(fake_ep_ptr.notified);
    ep.close();
}

test "Jumbo Frames" {
    const FakeLinkEndpoint = struct {
        address: [6]u8 = [_]u8{ 1, 2, 3, 4, 5, 6 },
        mtu_val: u32 = 1500,
        last_pkt_size: usize = 0,

        fn writePacket(ptr: *anyopaque, r: ?*const Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r;
            _ = protocol;
            self.last_pkt_size = pkt.data.size + pkt.header.usedLength();
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return .{ .addr = self.address };
        }
        fn mtu(ptr: *anyopaque) u32 {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return self.mtu_val;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            self.mtu_val = m;
        }
        fn capabilities(ptr: *anyopaque) LinkEndpointCapabilities {
            _ = ptr;
            return CapabilityNone;
        }
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

    ep.setMTU(9000);
    try std.testing.expectEqual(@as(u32, 9000), ep.mtu());

    try s.createNIC(1, ep);
}
