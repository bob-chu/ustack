const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");

pub const ProtocolNumber = 1;

pub const ICMPv4TransportProtocol = struct {
    pub fn init() ICMPv4TransportProtocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv4TransportProtocol) stack.TransportProtocol {
        return .{
            .ptr = self,
            .vtable = &.{
                .number = transportNumber,
                .newEndpoint = newTransportEndpoint,
                .parsePorts = parsePorts,
                .handlePacket = handlePacket_external,
            },
        };
    }

    fn transportNumber(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newTransportEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        _ = ptr;
        _ = s;
        _ = net_proto;
        _ = wait_queue;
        return tcpip.Error.NotPermitted;
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        if (v.len >= 8) {
            const id = std.mem.readInt(u16, v[4..6], .big);
            return .{ .src = id, .dst = 0 };
        }
        return .{ .src = 0, .dst = 0 };
    }

    fn handlePacket_external(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        _ = ptr;
        _ = id;
        ICMPv4PacketHandler.handlePacket(r.nic.stack, r, pkt);
    }
};

pub const ICMPv4PacketHandler = struct {
    pub fn handlePacket(s: *stack.Stack, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        var h = header.ICMPv4.init(v);

        if (h.type() == header.ICMPv4EchoType) {
            const payload = mut_pkt.data.toView(s.allocator) catch return;
            defer s.allocator.free(payload);

            var reply_hdr = [_]u8{0} ** header.ICMPv4MinimumSize;
            @memcpy(&reply_hdr, payload[0..header.ICMPv4MinimumSize]);
            var reply_h = header.ICMPv4.init(&reply_hdr);
            reply_h.data[0] = header.ICMPv4EchoReplyType;
            reply_h.setChecksum(0);
            const c = reply_h.calculateChecksum(payload[header.ICMPv4MinimumSize..]);
            reply_h.setChecksum(c);

            var views = [_]buffer.ClusterView{.{ .cluster = null, .view = payload[header.ICMPv4MinimumSize..] }};
            const reply_pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(payload.len - header.ICMPv4MinimumSize, &views),
                .header = buffer.Prependable.initFull(&reply_hdr),
            };

            var reply_route = r.*;
            if (r.nic.network_endpoints.get(0x0800)) |ip_ep| {
                ip_ep.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch {};
            }
        }
    }
};

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
        _ = ptr;
        _ = addr;
        _ = local_addr;
        _ = nic;
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
        .close = close,
    };

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv4MinimumSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        _ = ptr;
        _ = r;
        _ = protocol;
        _ = pkt;
        return tcpip.Error.NotPermitted;
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        ICMPv4PacketHandler.handlePacket(self.nic.stack, r, pkt);
    }
};
