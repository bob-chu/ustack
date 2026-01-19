const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");

pub const ProtocolNumber = 58;

pub const ICMPv6Protocol = struct {
    pub fn init() ICMPv6Protocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv6Protocol) stack.NetworkProtocol {
        return .{
            .ptr = self,
            .vtable = &.{
                .number = number,
                .newEndpoint = newEndpoint,
                .linkAddressRequest = linkAddressRequest,
                .parseAddresses = parseAddresses,
            },
        };
    }

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
        // ICMPv6 doesn't have src/dst in its header, they are in IPv6 header which is already parsed.
        // This function is for finding transport addresses?
        // Wait, stack calls this on the transport protocol?
        // No, stack calls this on Network Protocol to get addresses from packet?
        // Ah, ICMP is treated as Transport sometimes?
        // In our stack.zig, NetworkProtocol has parseAddresses.
        // But ICMPv6 is usually over IPv6.
        // So this might not be called directly on ICMPv6 packet buffer if it's encapsulated?
        // Actually, if we treat ICMPv6 as a NetworkProtocol (like ARP? No, ARP is net protocol 0x0806).
        // ICMPv6 is NextHeader 58 inside IPv6.
        
        // Wait, stack.zig registers ICMPv6 as a Network Protocol?
        // ARP is a network protocol.
        // IPv4/IPv6 are network protocols.
        // ICMPv4/ICMPv6 are typically Transport protocols over IP?
        // But they also handle control messages.
        
        // Let's check how we registered ICMPv4.
        // We defined it in main.zig, but did we register it in stack?
        // We didn't register ICMPv4 in the stack in our tests yet.
        // We only registered IPv4, ARP, UDP, TCP.
        
        // ICMPv6 should likely be registered as a TransportProtocol (proto 58) inside IPv6.
        // But currently our Stack structure separates network_protocols (EtherType) and transport_protocols (IP Protocol).
        // IPv6 (0x86dd) is a network protocol.
        // ICMPv6 (58) is a transport protocol.
        
        // So this file should probably define a TransportProtocol, not NetworkProtocol.
        // But wait, the prompt says "ICMPv6 support (basic Echo)".
        // Let's look at icmp.zig (ICMPv4).
        
        _ = pkt;
        return .{
            .src = .{ .v6 = [_]u8{0} ** 16 },
            .dst = .{ .v6 = [_]u8{0} ** 16 },
        };
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        _ = ptr; _ = nic; _ = addr; _ = dispatcher;
        return tcpip.Error.NotPermitted;
    }
};

// Re-implementing as Transport Protocol for correct integration
pub const ICMPv6TransportProtocol = struct {
    pub fn init() ICMPv6TransportProtocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv6TransportProtocol) stack.TransportProtocol {
        return .{
            .ptr = self,
            .vtable = &.{
                .number = transportNumber,
                .newEndpoint = newTransportEndpoint,
                .parsePorts = parsePorts,
            },
        };
    }

    fn transportNumber(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newTransportEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        _ = ptr; _ = s; _ = net_proto; _ = wait_queue;
        // TODO: Implement ICMPv6 endpoint for raw sockets?
        return tcpip.Error.NotPermitted;
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        // ICMP doesn't have ports, use ID as source port?
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        // Echo request/reply has ID at offset 4
        if (v.len >= 8) {
             const id = std.mem.readIntBig(u16, v[4..6]);
             return .{ .src = id, .dst = 0 };
        }
        return .{ .src = 0, .dst = 0 };
    }
};

// Simple endpoint to handle Echo Requests automatically (like kernel)
pub const ICMPv6PacketHandler = struct {
    pub fn handlePacket(s: *stack.Stack, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        var h = header.ICMPv6.init(v);
        
        if (h.@"type"() == header.ICMPv6EchoRequestType) {
            // Echo request, send reply
            // Payload follows header (4 bytes type/code/csum + 4 bytes ID/seq) = 8 bytes
            // Wait, ICMPv6 header is type(1), code(1), csum(2). Total 4.
            // Echo request body: ID(2), Seq(2), Data(...).
            
            const payload = mut_pkt.data.toView(s.allocator) catch return;
            defer s.allocator.free(payload);
            
            // Allocate buffer for reply
            // We reuse the payload but change type and update checksum
            var reply_buf = s.allocator.alloc(u8, payload.len) catch return;
            defer s.allocator.free(reply_buf);
            @memcpy(reply_buf, payload);
            
            var reply_h = header.ICMPv6.init(reply_buf);
            reply_h.data[0] = header.ICMPv6EchoReplyType;
            reply_h.setChecksum(0);
            
            // Calculate Checksum (needs pseudo header)
            // Route has addresses
            const src = r.local_address.v6;
            const dst = r.remote_address.v6;
            const c = reply_h.calculateChecksum(src, dst, reply_buf[header.ICMPv6MinimumSize..]);
            reply_h.setChecksum(c);
            
            var views = [_]buffer.View{reply_buf};
            var reply_pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(reply_buf.len, &views),
                .header = undefined, // Headers will be prepended by writePacket
            };
            
            // We need a mutable route to write
            var reply_route = r.*; // Copy route
            // Swap addresses? Route r is inbound (remote->local).
            // We want outbound (local->remote).
            // Stack.findRoute would be better but we have the info here.
            // reply_route.local is correct (was r.local).
            // reply_route.remote is correct (was r.remote).
            // Wait, r is Inbound route?
            // Usually Route struct represents the path *to* destination.
            // If r came from IPv6Endpoint.handlePacket, it was constructed as:
            // .local_address = addrs.dst (which is us)
            // .remote_address = addrs.src (which is them)
            // So for writing back, we use this route?
            // writePacket uses r.local as source and r.remote as dest.
            // But IPv6Endpoint.writePacket:
            // h.encode(r.local_address.v6, r.remote_address.v6, ...)
            // Yes, so we can reuse r.
            
            // But we need to use the NIC's IPv6 endpoint to write.
            if (r.nic.network_endpoints.get(0x86dd)) |ep| {
                // We need to pass the transport protocol number (58)
                ep.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch {};
            }
        }
    }
};
