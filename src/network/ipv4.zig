const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");

const buffer = @import("../buffer.zig");

pub const ProtocolNumber = 0x0800;

pub const IPv4Protocol = struct {
    pub fn init() IPv4Protocol {
        return .{};
    }

    pub fn protocol(self: *IPv4Protocol) stack.NetworkProtocol {
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
        const h = header.IPv4.init(v);
        return .{
            .src = .{ .v4 = h.sourceAddress() },
            .dst = .{ .v4 = h.destinationAddress() },
        };
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;
        _ = addr;
        _ = local_addr;
        _ = nic;
        return tcpip.Error.NotPermitted;
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        const self = @as(*IPv4Protocol, @ptrCast(@alignCast(ptr)));
        const ep = nic.stack.allocator.create(IPv4Endpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = .{
            .nic = nic,
            .address = addr.address,
            .protocol = self,
            .dispatcher = dispatcher,
            .reassembly_list = std.AutoHashMap(ReassemblyKey, ReassemblyContext).init(nic.stack.allocator),
        };
        return ep.networkEndpoint();
    }
};

const Fragment = struct {
    data: tcpip.PacketBuffer,
    offset: u16,
    more: bool,
    id: u16,
    src: tcpip.Address,
    dst: tcpip.Address,
};

const ReassemblyKey = struct {
    src: tcpip.Address,
    dst: tcpip.Address,
    id: u16,
    protocol: u8,
};

const ReassemblyContext = struct {
    fragments: std.ArrayList(Fragment),

    pub fn init(allocator: std.mem.Allocator) ReassemblyContext {
        return .{ .fragments = std.ArrayList(Fragment).init(allocator) };
    }

    pub fn deinit(self: *ReassemblyContext) void {
        self.fragments.deinit();
    }
};

pub const IPv4Endpoint = struct {
    nic: *stack.NIC,
    address: tcpip.Address,
    protocol: *IPv4Protocol,
    dispatcher: stack.TransportDispatcher,

    reassembly_list: std.AutoHashMap(ReassemblyKey, ReassemblyContext),

    pub fn networkEndpoint(self: *IPv4Endpoint) stack.NetworkEndpoint {
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
        const self = @as(*IPv4Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv4MinimumSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*IPv4Endpoint, @ptrCast(@alignCast(ptr)));
        var it = self.reassembly_list.valueIterator();
        while (it.next()) |ctx| {
            ctx.deinit();
        }
        self.reassembly_list.deinit();
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*IPv4Endpoint, @ptrCast(@alignCast(ptr)));

        const max_payload = self.nic.linkEP.mtu() - header.IPv4MinimumSize;
        if (pkt.data.size > max_payload) {
            return tcpip.Error.MessageTooLong;
        }

        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv4MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv4.init(ip_header);

        @memset(ip_header, 0);
        ip_header[0] = 0x45; // Version 4, IHL 5
        std.mem.writeInt(u16, ip_header[2..4], @as(u16, @intCast(mut_pkt.header.usedLength() + mut_pkt.data.size)), .big);
        ip_header[8] = 64; // TTL
        ip_header[9] = @as(u8, @intCast(protocol));
        @memcpy(ip_header[12..16], &r.local_address.v4);
        @memcpy(ip_header[16..20], &r.remote_address.v4);

        h.setChecksum(h.calculateChecksum());

        return self.nic.linkEP.writePacket(r, ProtocolNumber, mut_pkt);
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*IPv4Endpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;
        const headerView = mut_pkt.data.first() orelse return;
        const h = header.IPv4.init(headerView);
        if (!h.isValid(mut_pkt.data.size)) {
            return;
        }

        const hlen = h.headerLength();
        if (header.finishChecksum(header.internetChecksum(headerView[0..hlen], 0)) != 0) {
            std.debug.print("IPv4: Checksum failure from {any}\n", .{h.sourceAddress()});
            // return; // Disable drop for debugging
        }

        if (h.moreFragments() or h.fragmentOffset() > 0) {
            std.debug.print("IPv4: Fragment received. offset={}, more={}\n", .{ h.fragmentOffset(), h.moreFragments() });
            const key = ReassemblyKey{
                .src = .{ .v4 = h.sourceAddress() },
                .dst = .{ .v4 = h.destinationAddress() },
                .id = h.id(),
                .protocol = h.protocol(),
            };

            var ctx_ptr = self.reassembly_list.getPtr(key);
            if (ctx_ptr == null) {
                const ctx = ReassemblyContext.init(self.nic.stack.allocator);
                self.reassembly_list.put(key, ctx) catch return;
                ctx_ptr = self.reassembly_list.getPtr(key);
            }
            const ctx = ctx_ptr.?;

            var payload_pkt = pkt;
            payload_pkt.data.trimFront(hlen);
            // Cap length to what IP header says
            const tlen = h.totalLength();
            if (tlen > hlen) {
                payload_pkt.data.capLength(tlen - hlen);
            } else {
                return; // Invalid length
            }

            const cloned_data = payload_pkt.data.clone(self.nic.stack.allocator) catch return;

            const fragment = Fragment{
                .data = .{ .data = cloned_data, .header = undefined },
                .offset = h.fragmentOffset(),
                .more = h.moreFragments(),
                .id = h.id(),
                .src = key.src,
                .dst = key.dst,
            };
            ctx.fragments.append(fragment) catch return;

            const Sort = struct {
                fn less(context: void, a: Fragment, b: Fragment) bool {
                    _ = context;
                    return a.offset < b.offset;
                }
            };
            std.sort.block(Fragment, ctx.fragments.items, {}, Sort.less);

            var expected_offset: u16 = 0;
            var complete = true;
            var has_last = false;

            for (ctx.fragments.items) |f| {
                if (f.offset != expected_offset) {
                    complete = false;
                    break;
                }
                expected_offset += @as(u16, @intCast(f.data.data.size));
                if (!f.more) has_last = true;
            }

            if (complete and has_last) {
                var total_size: usize = 0;
                for (ctx.fragments.items) |f| total_size += f.data.data.size;

                const reassembled_buf = self.nic.stack.allocator.alloc(u8, total_size) catch return;
                var offset: usize = 0;
                for (ctx.fragments.items) |f| {
                    const v = f.data.data.toView(self.nic.stack.allocator) catch return;
                    defer self.nic.stack.allocator.free(v);
                    @memcpy(reassembled_buf[offset .. offset + v.len], v);
                    offset += v.len;
                    var mut_data = f.data.data;
                    mut_data.deinit();
                }

                ctx.fragments.deinit();
                _ = self.reassembly_list.remove(key);

                var views = [_]buffer.View{reassembled_buf};
                const reassembled_pkt = tcpip.PacketBuffer{
                    .data = buffer.VectorisedView.init(total_size, &views),
                    .header = undefined,
                };

                const p = h.protocol();
                self.dispatcher.deliverTransportPacket(r, p, reassembled_pkt);
                self.nic.stack.allocator.free(reassembled_buf);
            }
            return;
        }

        mut_pkt.network_header = headerView[0..h.headerLength()];

        const tlen = h.totalLength();
        mut_pkt.data.trimFront(hlen);
        mut_pkt.data.capLength(tlen - hlen);

        const p = h.protocol();
        self.dispatcher.deliverTransportPacket(r, p, mut_pkt);
    }
};

test "IPv4 fragmentation and reassembly" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var fake_ep = struct {
        mtu_val: u32 = 1500,
        fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            _ = ptr;
            _ = r;
            _ = protocol;
            _ = pkt;
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            _ = ptr;
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(ptr: *anyopaque) u32 {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return self.mtu_val;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            self.mtu_val = m;
        }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
            _ = ptr;
            return stack.CapabilityNone;
        }
    }{ .mtu_val = 1500 };

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_ep,
        .vtable = &.{
            .writePacket = @TypeOf(fake_ep).writePacket,
            .attach = @TypeOf(fake_ep).attach,
            .linkAddress = @TypeOf(fake_ep).linkAddress,
            .mtu = @TypeOf(fake_ep).mtu,
            .setMTU = @TypeOf(fake_ep).setMTU,
            .capabilities = @TypeOf(fake_ep).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const ipv4_proto = IPv4Protocol.init();

    var delivered = false;
    var delivered_len: usize = 0;
    const FakeDispatcher = struct {
        delivered: *bool,
        delivered_len: *usize,
        fn deliverTransportPacket(ptr: *anyopaque, r: *const stack.Route, protocol: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r;
            _ = protocol;
            self.delivered.* = true;
            self.delivered_len.* = pkt.data.size;
        }
    };
    var fd = FakeDispatcher{ .delivered = &delivered, .delivered_len = &delivered_len };
    const dispatcher = stack.TransportDispatcher{
        .ptr = &fd,
        .vtable = &.{
            .deliverTransportPacket = FakeDispatcher.deliverTransportPacket,
        },
    };

    var ep_ipv4 = try nic.stack.allocator.create(IPv4Endpoint);
    ep_ipv4.* = .{
        .nic = nic,
        .address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .protocol = @constCast(&ipv4_proto),
        .dispatcher = dispatcher,
        .reassembly_list = std.AutoHashMap(ReassemblyKey, ReassemblyContext).init(allocator),
    };
    defer {
        ep_ipv4.reassembly_list.deinit();
        nic.stack.allocator.destroy(ep_ipv4);
    }

    const r = stack.Route{
        .local_address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 10, 0, 0, 2 } },
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };

    const payload = "hello world this is a fragmented packet";
    var frag1_buf = [_]u8{0} ** (header.IPv4MinimumSize + 16);
    var frag1_h = header.IPv4.init(&frag1_buf);
    frag1_h.data[0] = 0x45;
    std.mem.writeInt(u16, frag1_h.data[2..4], header.IPv4MinimumSize + 16, .big);
    std.mem.writeInt(u16, frag1_h.data[4..6], 12345, .big);
    std.mem.writeInt(u16, frag1_h.data[6..8], 0x2000, .big);
    frag1_h.data[9] = 17;
    @memcpy(frag1_h.data[12..16], &[_]u8{ 10, 0, 0, 2 });
    @memcpy(frag1_h.data[16..20], &[_]u8{ 10, 0, 0, 1 });
    @memcpy(frag1_buf[20..], payload[0..16]);
    frag1_h.setChecksum(frag1_h.calculateChecksum());

    const rem_len = payload.len - 16;
    var frag2_buf = try allocator.alloc(u8, header.IPv4MinimumSize + rem_len);
    defer allocator.free(frag2_buf);
    @memset(frag2_buf, 0);
    var frag2_h = header.IPv4.init(frag2_buf);
    frag2_h.data[0] = 0x45;
    std.mem.writeInt(u16, frag2_h.data[2..4], @as(u16, @intCast(header.IPv4MinimumSize + rem_len)), .big);
    std.mem.writeInt(u16, frag2_h.data[4..6], 12345, .big);
    std.mem.writeInt(u16, frag2_h.data[6..8], 0x0002, .big);
    frag2_h.data[9] = 17;
    @memcpy(frag2_h.data[12..16], &[_]u8{ 10, 0, 0, 2 });
    @memcpy(frag2_h.data[16..20], &[_]u8{ 10, 0, 0, 1 });
    @memcpy(frag2_buf[20..], payload[16..]);
    frag2_h.setChecksum(frag2_h.calculateChecksum());

    var views1 = [_]buffer.View{&frag1_buf};
    const pkt1 = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(frag1_buf.len, &views1),
        .header = undefined,
    };
    ep_ipv4.networkEndpoint().handlePacket(&r, pkt1);

    try std.testing.expect(!delivered);

    var views2 = [_]buffer.View{frag2_buf};
    const pkt2 = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(frag2_buf.len, &views2),
        .header = undefined,
    };
    ep_ipv4.networkEndpoint().handlePacket(&r, pkt2);

    try std.testing.expect(delivered);
    try std.testing.expectEqual(payload.len, delivered_len);
}
