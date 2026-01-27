const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");

pub const ProtocolNumber = 0x86dd;

pub const IPv6Protocol = struct {
    pub fn init() IPv6Protocol {
        return .{};
    }

    pub fn protocol(self: *IPv6Protocol) stack.NetworkProtocol {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.NetworkProtocol.VTable{
        .number = number,
        .newEndpoint = newEndpoint,
        .linkAddressRequest = linkAddressRequest,
        .parseAddresses = parseAddresses,
    };

    fn number(ptr: *anyopaque) tcpip.NetworkProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn parseAddresses(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.NetworkProtocol.AddressPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{
            .src = .{ .v6 = [_]u8{0} ** 16 },
            .dst = .{ .v6 = [_]u8{0} ** 16 },
        };
        const h = header.IPv6.init(v);
        return .{
            .src = .{ .v6 = h.sourceAddress() },
            .dst = .{ .v6 = h.destinationAddress() },
        };
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;
        if (addr != .v6) return;
        const target = addr.v6;
        const src = local_addr.v6;

        // Solicited-node multicast address
        const dst = addr.toSolicitedNodeMulticast().v6;

        // Build Neighbor Solicitation
        const payload_len = header.ICMPv6MinimumSize + 20 + 8;
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6NeighborSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        var ns = header.ICMPv6NS.init(buf[header.ICMPv6MinimumSize..]);
        ns.setTargetAddress(target);

        // Option: Source Link-Layer Address
        buf[header.ICMPv6MinimumSize + 20] = header.ICMPv6OptionSourceLinkLayerAddress;
        buf[header.ICMPv6MinimumSize + 21] = 1;
        @memcpy(buf[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28], &nic.linkEP.linkAddress().addr);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        var r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            // Ethernet multicast for IPv6: 33:33: + last 32 bits of IPv6 address
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, dst[12], dst[13], dst[14], dst[15] } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        if (nic.network_endpoints.get(ProtocolNumber)) |ep| {
            try ep.writePacket(&r, 58, pkt); // ICMPv6 is 58
        }
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        const self = @as(*IPv6Protocol, @ptrCast(@alignCast(ptr)));
        const ep = nic.stack.allocator.create(IPv6Endpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = .{
            .nic = nic,
            .address = addr.address,
            .protocol = self,
            .dispatcher = dispatcher,
        };

        // Perform DAD (RFC 4862)
        // Send NS with unspecified source to solicited-node multicast of the new address
        const target = addr.address.v6;
        const src = [_]u8{0} ** 16;
        const dst = addr.address.toSolicitedNodeMulticast().v6;

        const payload_len = header.ICMPv6MinimumSize + 20; // No SLLA option for DAD
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6NeighborSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        var ns = header.ICMPv6NS.init(buf[header.ICMPv6MinimumSize..]);
        ns.setTargetAddress(target);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, dst[12], dst[13], dst[14], dst[15] } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        // Manual IP header since NetworkEndpoint is not registered yet
        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);
        h.encode(src, dst, 58, @as(u16, @intCast(pkt.data.size)));

        nic.linkEP.writePacket(&r, ProtocolNumber, mut_pkt) catch {};

        // Also send Router Solicitation to all-routers multicast
        self.sendRouterSolicitation(nic) catch {};

        return ep.networkEndpoint();
    }

    fn sendRouterSolicitation(self: *IPv6Protocol, nic: *stack.NIC) tcpip.Error!void {
        _ = self;
        var src = [_]u8{0} ** 16;
        for (nic.addresses.items) |pa| {
            if (pa.protocol == ProtocolNumber) {
                const addr = pa.address_with_prefix.address.v6;
                if (addr[0] == 0xfe and addr[1] == 0x80) {
                    src = addr;
                    break;
                }
            }
        }

        const dst = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }; // All-Routers multicast

        const payload_len = header.ICMPv6MinimumSize + 4 + 8;
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6RouterSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        // Reserved 4 bytes
        @memset(buf[header.ICMPv6MinimumSize .. header.ICMPv6MinimumSize + 4], 0);

        // Option: Source Link-Layer Address
        buf[header.ICMPv6MinimumSize + 4] = header.ICMPv6OptionSourceLinkLayerAddress;
        buf[header.ICMPv6MinimumSize + 5] = 1;
        @memcpy(buf[header.ICMPv6MinimumSize + 6 .. header.ICMPv6MinimumSize + 12], &nic.linkEP.linkAddress().addr);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, 0, 0, 0, 2 } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);
        h.encode(src, dst, 58, @as(u16, @intCast(pkt.data.size)));

        return nic.linkEP.writePacket(&r, ProtocolNumber, mut_pkt);
    }
};

pub const IPv6Endpoint = struct {
    nic: *stack.NIC,
    address: tcpip.Address,
    protocol: *IPv6Protocol,
    dispatcher: stack.TransportDispatcher,

    pub fn networkEndpoint(self: *IPv6Endpoint) stack.NetworkEndpoint {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.NetworkEndpoint.VTable{
        .writePacket = writePacket,
        .handlePacket = handlePacket,
        .mtu = mtu,
        .close = close,
    };

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv6MinimumSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));

        // Simplified: no fragmentation check yet
        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);

        h.encode(r.local_address.v6, r.remote_address.v6, @as(u8, @intCast(protocol)), @as(u16, @intCast(pkt.data.size)));

        return self.nic.linkEP.writePacket(r, ProtocolNumber, mut_pkt);
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;
        const headerView = mut_pkt.data.first() orelse return;
        const h = header.IPv6.init(headerView);
        if (!h.isValid(mut_pkt.data.size)) {
            return;
        }

        mut_pkt.network_header = headerView[0..header.IPv6MinimumSize];

        const hlen = header.IPv6MinimumSize;
        const plen = h.payloadLength();
        mut_pkt.data.trimFront(hlen);
        mut_pkt.data.capLength(plen); // Payload length doesn't include header in IPv6

        const p = h.nextHeader();
        self.dispatcher.deliverTransportPacket(r, p, mut_pkt);
    }
};
