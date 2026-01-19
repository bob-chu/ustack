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
        _ = ptr; _ = addr; _ = local_addr; _ = nic;
        // TODO: Implement NDP (Neighbor Discovery Protocol)
        return tcpip.Error.NotPermitted;
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
        return ep.networkEndpoint();
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
            .vtable = &.{
                .writePacket = writePacket,
                .handlePacket = handlePacket,
                .mtu = mtu,
            },
        };
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv6MinimumSize;
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
