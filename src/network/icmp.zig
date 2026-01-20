const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");

pub const ProtocolNumber = 1;

pub const ICMPv4Protocol = struct {
    pub fn init() ICMPv4Protocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv4Protocol) stack.NetworkProtocol {
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

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr; _ = addr; _ = local_addr; _ = nic;
        return tcpip.Error.NotPermitted;
    }

    fn parseAddresses(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.NetworkProtocol.AddressPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{
            .src = .{ .v4 = .{ 0, 0, 0, 0 } },
            .dst = .{ .v4 = .{ 0, 0, 0, 0 } },
        };
        const h = header.IPv4.init(v);
        return .{
            .src = .{ .v4 = h.sourceAddress() },
            .dst = .{ .v4 = h.destinationAddress() },
        };
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        const self = @as(*ICMPv4Protocol, @ptrCast(@alignCast(ptr)));
        const ep = nic.stack.allocator.create(ICMPv4Endpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = .{
            .nic = nic,
            .address = addr.address,
            .protocol = self,
        };
        _ = dispatcher;
        return ep.networkEndpoint();
    }
};

pub const ICMPv4Endpoint = struct {
    nic: *stack.NIC,
    address: tcpip.Address,
    protocol: *ICMPv4Protocol,

    pub fn networkEndpoint(self: *ICMPv4Endpoint) stack.NetworkEndpoint {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.NetworkEndpoint.VTable{
        .writePacket = writePacket,
        .handlePacket = handlePacket,
        .mtu = mtu,
    };

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv4MinimumSize;
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        _ = ptr; _ = r; _ = protocol; _ = pkt;
        return tcpip.Error.NotPermitted;
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        var h = header.ICMPv4.init(v);
        
        if (h.@"type"() == header.ICMPv4EchoType) {
            // Echo request, send reply
            const payload = mut_pkt.data.toView(self.nic.stack.allocator) catch return;
            defer self.nic.stack.allocator.free(payload);
            
            var reply_hdr = [_]u8{0} ** header.ICMPv4MinimumSize;
            @memcpy(&reply_hdr, payload[0..header.ICMPv4MinimumSize]);
            var reply_h = header.ICMPv4.init(&reply_hdr);
            reply_h.data[0] = header.ICMPv4EchoReplyType;
            reply_h.setChecksum(0);
            const c = reply_h.calculateChecksum(payload[header.ICMPv4MinimumSize..]);
            reply_h.setChecksum(c);
            
            var views = [_]buffer.View{payload[header.ICMPv4MinimumSize..]};
            var reply_pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(payload.len - header.ICMPv4MinimumSize, &views),
                .header = buffer.Prependable.initFull(&reply_hdr),
            };
            
            // Send via IPv4
            const ipv4_proto = self.nic.stack.network_protocols.get(0x0800) orelse return;
            const ipv4 = @as(*const @import("ipv4.zig").IPv4Protocol, @ptrCast(@alignCast(ipv4_proto.ptr)));
            _ = ipv4;

            // We need to send this packet back. The Route r is inbound (remote -> local).
            // We need an outbound Route (local -> remote).
            // Since we don't have full routing table yet, we can try to reuse the NIC and reverse addresses.
            
            // This is a bit of a hack until we have proper routing
            // We really should be using stack.FindRoute but we need to know the protocol (IPv4)
            // and we are currently in ICMP which is kinda above IPv4 but also next to it.
            
            // Let's manually construct a route for reply
            var reply_route = stack.Route{
                .local_address = r.local_address,
                .remote_address = r.remote_address,
                .local_link_address = r.local_link_address,
                .remote_link_address = r.remote_link_address,
                .net_proto = 0x0800, // IPv4
                .nic = self.nic,
            };
            
            // We need to call IPv4 writePacket. But IPv4Endpoint is what has writePacket.
            // And we don't have an IPv4Endpoint here, we are in ICMP endpoint.
            // This suggests that ICMP should probably use a RawEndpoint or similar, 
            // or we need a way to send IP packets directly.
            
            // For now, let's assume we can use the NIC's IPv4 endpoint if it exists
            if (self.nic.network_endpoints.get(0x0800)) |ip_ep| {
                ip_ep.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch {};
            }
        }
    }
};
