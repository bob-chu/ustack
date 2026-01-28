const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const time = @import("../time.zig");

pub const ProtocolNumber = 0x0806;
pub const ProtocolAddress = "arp";

pub const ARPProtocol = struct {
    pub fn init() ARPProtocol {
        return .{};
    }

    pub fn protocol(self: *ARPProtocol) stack.NetworkProtocol {
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
        
        const ep_opt = nic.network_endpoints.get(ProtocolNumber);
        if (ep_opt) |ep| {
            const arp_ep = @as(*ARPEndpoint, @ptrCast(@alignCast(ep.ptr)));
            if (!arp_ep.pending_requests.contains(addr)) {
                arp_ep.pending_requests.put(addr, std.time.milliTimestamp()) catch {};
                if (!arp_ep.timer.active) {
                    nic.stack.timer_queue.schedule(&arp_ep.timer, 1000);
                }
            }
        }

        const hdr_buf = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_buf);

        var pre = buffer.Prependable.init(hdr_buf);
        const arp_hdr = pre.prepend(header.ARPSize).?;
        var h = header.ARP.init(arp_hdr);
        h.setIPv4OverEthernet();
        h.setOp(1); // Request
        @memcpy(h.data[8..14], &nic.linkEP.linkAddress().addr);
        @memcpy(h.data[14..18], &local_addr.v4);
        @memcpy(h.data[24..28], &addr.v4);

        const pb = tcpip.PacketBuffer{
            .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
            .header = pre,
        };

        const broadcast_hw = tcpip.LinkAddress{ .addr = [_]u8{0xff} ** 6 };
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
        _ = ptr;
        _ = addr;
        _ = dispatcher;
        const ep = try nic.stack.allocator.create(ARPEndpoint);
        ep.* = .{
            .nic = nic,
            .pending_requests = std.AutoHashMap(tcpip.Address, i64).init(nic.stack.allocator),
            .timer = time.Timer.init(ARPEndpoint.handleTimer, ep),
        };
        return ep.networkEndpoint();
    }
};

pub const ARPEndpoint = struct {
    nic: *stack.NIC,
    pending_requests: std.AutoHashMap(tcpip.Address, i64),
    timer: time.Timer = undefined,

    pub fn networkEndpoint(self: *ARPEndpoint) stack.NetworkEndpoint {
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

    pub fn handleTimer(ptr: *anyopaque) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        var it = self.pending_requests.iterator();
        const now = std.time.milliTimestamp();
        var has_pending = false;

        while (it.next()) |entry| {
            if (now - entry.value_ptr.* >= 1000) {
                const proto_opt = self.nic.stack.network_protocols.get(ProtocolNumber);
                if (proto_opt) |p| {
                    const proto = @as(*ARPProtocol, @ptrCast(@alignCast(p.ptr)));
                    var local_addr: ?tcpip.Address = null;
                    const addrs = self.nic.addresses.items;
                    if (addrs.len > 0) local_addr = addrs[0].address_with_prefix.address;

                    if (local_addr) |la| {
                        ARPProtocol.linkAddressRequest(proto, entry.key_ptr.*, la, self.nic) catch {};
                        entry.value_ptr.* = now;
                    }
                }
            }
            has_pending = true;
        }

        if (has_pending) {
            self.nic.stack.timer_queue.schedule(&self.timer, 1000);
        }
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.ARPSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        self.nic.stack.timer_queue.cancel(&self.timer);
        self.pending_requests.deinit();
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
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        _ = r;
        const v = pkt.data.first() orelse return;
        const h = header.ARP.init(v);
        if (!h.isValid()) return;

        const sender_proto_addr = tcpip.Address{ .v4 = h.protocolAddressSender() };
        const sender_hw_addr = h.hardwareAddressSender();

        _ = self.pending_requests.remove(sender_proto_addr);
        self.nic.stack.addLinkAddress(sender_proto_addr, .{ .addr = sender_hw_addr }) catch {};

        const target_proto_addr = tcpip.Address{ .v4 = h.protocolAddressTarget() };
        if (h.op() == 1) { // Request
            if (self.nic.hasAddress(target_proto_addr)) {
                const hdr_buf = self.nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
                defer self.nic.stack.allocator.free(hdr_buf);

                var pre = buffer.Prependable.init(hdr_buf);
                const arp_hdr = pre.prepend(header.ARPSize).?;
                var reply_h = header.ARP.init(arp_hdr);
                reply_h.setIPv4OverEthernet();
                reply_h.setOp(2); // Reply
                @memcpy(reply_h.data[8..14], &self.nic.linkEP.linkAddress().addr);
                @memcpy(reply_h.data[14..18], h.data[24..28]);
                @memcpy(reply_h.data[18..24], h.data[8..14]);
                @memcpy(reply_h.data[24..28], h.data[14..18]);

                const reply_pkt = tcpip.PacketBuffer{
                    .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
                    .header = pre,
                };

                const remote_link_address = tcpip.LinkAddress{ .addr = sender_hw_addr };
                var reply_route = stack.Route{
                    .local_address = target_proto_addr,
                    .remote_address = sender_proto_addr,
                    .local_link_address = self.nic.linkEP.linkAddress(),
                    .remote_link_address = remote_link_address,
                    .net_proto = ProtocolNumber,
                    .nic = self.nic,
                };

                self.nic.linkEP.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch {};
            }
        }
    }
};
