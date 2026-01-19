const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");

pub const ProtocolNumber = 0x0806;
pub const ProtocolAddress = "arp";

pub const ARPProtocol = struct {
    pub fn init() ARPProtocol {
        return .{};
    }

    pub fn protocol(self: *ARPProtocol) stack.NetworkProtocol {
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
            .src = .{ .v4 = .{ 0, 0, 0, 0 } },
            .dst = .{ .v4 = .{ 0, 0, 0, 0 } },
        };
        const h = header.ARP.init(v);
        return .{
            .src = .{ .v4 = h.protocolAddressSender() },
            .dst = .{ .v4 = h.protocolAddressTarget() },
        };
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;
        var hdr_buf = nic.stack.allocator.alloc(u8, header.ARPSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_buf);
        
        var h = header.ARP.init(hdr_buf);
        h.setIPv4OverEthernet();
        h.setOp(1); // Request
        @memcpy(h.data[8..14], &nic.linkEP.linkAddress());
        @memcpy(h.data[14..18], &local_addr.v4);
        @memcpy(h.data[24..28], &addr.v4);

        var pb = tcpip.PacketBuffer{
            .data = .{.views = &[_]buffer.View{}, .size = 0},
            .header = buffer.Prependable.initFull(hdr_buf),
        };
        
        const broadcast_hw = [_]u8{0xff} ** 6;
        var r = stack.Route{
            .local_address = local_addr,
            .remote_address = addr,
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = broadcast_hw,
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        return nic.linkEP.writePacket(&r, ProtocolNumber, pb);
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        _ = ptr; _ = addr; _ = dispatcher;
        const ep = try nic.stack.allocator.create(ARPEndpoint);
        ep.* = .{
            .nic = nic,
        };
        return ep.networkEndpoint();
    }
};

pub const ARPEndpoint = struct {
    nic: *stack.NIC,

    pub fn networkEndpoint(self: *ARPEndpoint) stack.NetworkEndpoint {
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
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.ARPSize;
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        _ = ptr; _ = r; _ = protocol; _ = pkt;
        return tcpip.Error.NotPermitted;
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        _ = r;
        const v = pkt.data.first() orelse return;
        const h = header.ARP.init(v);
        if (!h.isValid()) return;

        const sender_proto_addr = tcpip.Address{ .v4 = h.protocolAddressSender() };
        const sender_hw_addr = h.hardwareAddressSender();
        
        self.nic.stack.addLinkAddress(sender_proto_addr, sender_hw_addr) catch {};

        const target_proto_addr = tcpip.Address{ .v4 = h.protocolAddressTarget() };
        if (h.op() == 1) { // Request
            if (self.nic.hasAddress(target_proto_addr)) {
                var hdr_buf = self.nic.stack.allocator.alloc(u8, header.ARPSize) catch return;
                defer self.nic.stack.allocator.free(hdr_buf);
                
                var reply_h = header.ARP.init(hdr_buf);
                reply_h.setIPv4OverEthernet();
                reply_h.setOp(2); // Reply
                @memcpy(reply_h.data[8..14], &self.nic.linkEP.linkAddress());
                @memcpy(reply_h.data[14..18], &h.data[24..28]);
                @memcpy(reply_h.data[18..24], &h.data[8..14]);
                @memcpy(reply_h.data[24..28], &h.data[14..18]);

                var pb = tcpip.PacketBuffer{
                    .data = .{.views = &[_]buffer.View{}, .size = 0},
                    .header = buffer.Prependable.initFull(hdr_buf),
                };
                
                self.nic.linkEP.writePacket(null, ProtocolNumber, pb) catch {};
            }
        }
    }
};
