const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const ipv4 = @import("../network/ipv4.zig");
const tcp = @import("tcp.zig");
const TCPEndpoint = tcp.TCPEndpoint;
const TCPProtocol = tcp.TCPProtocol;

test "TCP Fast Retransmit" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());
    var wq_server = waiter.Queue{};
    const ep_server_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_server);
    const ep_server = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_server_res.ptr)));
    defer ep_server.close();

    var fake_ep = struct {
        last_pkt: ?[]u8 = null,
        allocator: std.mem.Allocator,
        fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            const hdr_view = pkt.header.view();
            const data_len = pkt.data.size;
            if (self.last_pkt) |p| self.allocator.free(p);
            self.last_pkt = self.allocator.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
            var offset = hdr_view.len;
            for (pkt.data.views) |cv| {
                @memcpy(self.last_pkt.?[offset .. offset + cv.view.len], cv.view);
                offset += cv.view.len;
            }
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return stack.CapabilityNone;
        }
    }{ .allocator = allocator };
    defer if (fake_ep.last_pkt) |p| allocator.free(p);
    const link_ep = stack.LinkEndpoint{ .ptr = &fake_ep, .vtable = &.{ .writePacket = @TypeOf(fake_ep).writePacket, .writePackets = null, .attach = @TypeOf(fake_ep).attach, .linkAddress = @TypeOf(fake_ep).linkAddress, .mtu = @TypeOf(fake_ep).mtu, .setMTU = @TypeOf(fake_ep).setMTU, .capabilities = @TypeOf(fake_ep).capabilities } };
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const ca = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const sa = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = ca.addr, .prefix_len = 24 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = sa.addr, .prefix_len = 24 } });
    try s.addLinkAddress(sa.addr, .{ .addr = [_]u8{0} ** 6 });
    try s.addLinkAddress(ca.addr, .{ .addr = [_]u8{0} ** 6 });
    try ep_server.endpoint().bind(sa);
    try ep_server.endpoint().listen(10);
    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_client_res.ptr)));
    defer ep_client.close();
    try ep_client.endpoint().bind(ca);
    try ep_client.endpoint().connect(sa);
    const syn_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(fake_ep.last_pkt.?[20..], allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_syn = syn_pkt;
    defer mut_syn.data.deinit();
    const r_to_server = stack.Route{ .local_address = sa.addr, .remote_address = ca.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_server = stack.TransportEndpointID{ .local_port = 80, .local_address = sa.addr, .remote_port = 1234, .remote_address = ca.addr, .transport_protocol = 6 };
    ep_server.handlePacket(&r_to_server, id_to_server, mut_syn);
    const syn_ack_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(fake_ep.last_pkt.?[20..], allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_syn_ack = syn_ack_pkt;
    defer mut_syn_ack.data.deinit();
    const r_to_client = stack.Route{ .local_address = ca.addr, .remote_address = sa.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_client = stack.TransportEndpointID{ .local_port = 1234, .local_address = ca.addr, .remote_port = 80, .remote_address = sa.addr, .transport_protocol = 6 };
    ep_client.handlePacket(&r_to_client, id_to_client, mut_syn_ack);

    try std.testing.expect(ep_client.state == .established);
}

test "TCP Keepalive" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_ep = struct {
        tx_count: u32 = 0,
        allocator: std.mem.Allocator,
        fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            self.tx_count += 1;
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return stack.CapabilityNone;
        }
    }{ .allocator = allocator };
    const link_ep = stack.LinkEndpoint{ .ptr = &fake_ep, .vtable = &.{ .writePacket = @TypeOf(fake_ep).writePacket, .writePackets = null, .attach = @TypeOf(fake_ep).attach, .linkAddress = @TypeOf(fake_ep).linkAddress, .mtu = @TypeOf(fake_ep).mtu, .setMTU = @TypeOf(fake_ep).setMTU, .capabilities = @TypeOf(fake_ep).capabilities } };
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_res.ptr)));
    defer ep.close();

    ep.state = .established;
    ep.local_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    ep.remote_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };

    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = ep.local_addr.?.addr, .prefix_len = 24 } });
    try s.addLinkAddress(ep.remote_addr.?.addr, .{ .addr = [_]u8{0} ** 6 });

    try ep.endpoint().setOption(.{ .keepalive_enabled = true });
    try ep.endpoint().setOption(.{ .tcp_keepidle = 1 });
    try ep.endpoint().setOption(.{ .tcp_keepintvl = 1 });
    try ep.endpoint().setOption(.{ .tcp_keepcnt = 3 });

    try std.testing.expect(ep.keepalive_timer.active);
    try std.testing.expectEqual(@as(u64, 1000), ep.keepalive_timer.delay_ms);

    // Tick to expire idle timer
    _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 1000);
    try std.testing.expect(fake_ep.tx_count == 1);
    try std.testing.expect(ep.keepalive_probes_sent == 1);

    // Should be rescheduled for intvl
    try std.testing.expect(ep.keepalive_timer.active);
    try std.testing.expectEqual(@as(u64, 1000), ep.keepalive_timer.delay_ms);

    // Tick again
    _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 1000);
    try std.testing.expect(fake_ep.tx_count == 2);
    try std.testing.expect(ep.keepalive_probes_sent == 2);

    // Tick again (3rd probe)
    _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 1000);
    try std.testing.expect(fake_ep.tx_count == 3);
    try std.testing.expect(ep.keepalive_probes_sent == 3);

    // Tick again (should timeout and transition to error_state)
    _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 1000);
    try std.testing.expect(ep.state == .error_state);

    // Reset test
    ep.state = .established;
    ep.keepalive_probes_sent = 0;
    try ep.endpoint().setOption(.{ .keepalive_enabled = true });
    _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 500);

    // Simulate packet arrival
    const la = ep.local_addr.?;
    const ra = ep.remote_addr.?;
    const r = stack.Route{ .local_address = la.addr, .remote_address = ra.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = s.nics.get(1).? };
    const id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = ra.port, .remote_address = ra.addr, .transport_protocol = 6 };

    const hdr_buf = try s.allocator.alloc(u8, 20);
    defer s.allocator.free(hdr_buf);
    @memset(hdr_buf, 0);
    var h = header.TCP.init(hdr_buf);
    h.encode(ra.port, la.port, 0, 0, header.TCPFlagAck, 1024);

    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = hdr_buf }};
    const pb = tcpip.PacketBuffer{ .header = buffer.Prependable.init(hdr_buf), .data = buffer.VectorisedView.init(20, &views) };
    ep.handlePacket(&r, id, pb);

    // Timer should have been reset to 1000ms from now
    try std.testing.expect(ep.keepalive_timer.expire_tick == s.timer_queue.current_tick + 1000);
}

test "TCP Retransmission" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());
    var fake_ep = struct {
        last_pkt: ?[]u8 = null,
        allocator: std.mem.Allocator,
        drop_next: bool = false,
        fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            if (self.drop_next) {
                self.drop_next = false;
                return;
            }
            const hdr_view = pkt.header.view();
            const data_len = pkt.data.size;
            if (self.last_pkt) |p| self.allocator.free(p);
            self.last_pkt = self.allocator.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
            var offset = hdr_view.len;
            for (pkt.data.views) |cv| {
                @memcpy(self.last_pkt.?[offset .. offset + cv.view.len], cv.view);
                offset += cv.view.len;
            }
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return stack.CapabilityNone;
        }
    }{ .allocator = allocator };
    defer if (fake_ep.last_pkt) |p| allocator.free(p);
    const link_ep = stack.LinkEndpoint{ .ptr = &fake_ep, .vtable = &.{ .writePacket = @TypeOf(fake_ep).writePacket, .writePackets = null, .attach = @TypeOf(fake_ep).attach, .linkAddress = @TypeOf(fake_ep).linkAddress, .mtu = @TypeOf(fake_ep).mtu, .setMTU = @TypeOf(fake_ep).setMTU, .capabilities = @TypeOf(fake_ep).capabilities } };
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const ca = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const sa = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = sa.addr, .prefix_len = 24 } });
    try s.addLinkAddress(ca.addr, .{ .addr = [_]u8{0} ** 6 });
    var wq_server = waiter.Queue{};
    const ep_server_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_server);
    const ep_server = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_server_res.ptr)));
    defer ep_server.close();
    try ep_server.endpoint().bind(sa);
    try ep_server.endpoint().listen(10);
    const syn_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(syn_buf);
    @memset(syn_buf, 0);
    var syn = header.TCP.init(syn_buf);
    syn.encode(ca.port, sa.port, 1000, 0, header.TCPFlagSyn, 65535);
    const syn_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(syn_buf, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_syn = syn_pkt;
    defer mut_syn.data.deinit();
    const r_to_server = stack.Route{ .local_address = sa.addr, .remote_address = ca.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_server = stack.TransportEndpointID{ .local_port = 80, .local_address = sa.addr, .remote_port = 1234, .remote_address = ca.addr, .transport_protocol = 6 };
    ep_server.handlePacket(&r_to_server, id_to_server, mut_syn);
    const ack_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(ack_buf);
    @memset(ack_buf, 0);
    var ack = header.TCP.init(ack_buf);
    const server_initial_seq = header.TCP.init(fake_ep.last_pkt.?[20..]).sequenceNumber();
    ack.encode(ca.port, sa.port, 1001, server_initial_seq +% 1, header.TCPFlagAck, 65535);
    const ack_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(ack_buf, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_ack = ack_pkt;
    defer mut_ack.data.deinit();
    ep_server.handlePacket(&r_to_server, id_to_server, mut_ack);

    const accept_res = try ep_server.endpoint().accept();
    const ep_accepted = @as(*TCPEndpoint, @ptrCast(@alignCast(accept_res.ep.ptr)));
    defer ep_accepted.decRef();
    defer accept_res.ep.close();
    const FakePayloader = struct {
        data: []const u8,
        pub fn payloader(self: *const @This()) tcpip.Payloader {
            return .{ .ptr = @constCast(self), .vtable = &.{ .fullPayload = fullPayload } };
        }
        fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
            return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
        }
    };
    var fp = FakePayloader{ .data = "important data" };
    fake_ep.drop_next = true;
    _ = try ep_accepted.endpoint().write(fp.payloader(), .{});
    try std.testing.expect(fake_ep.drop_next == false);
}

test "TCP CWND Enforcement" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_link = struct {
        fn writePacket(_: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return 0;
        }
    }{};
    const link_ep = stack.LinkEndpoint{ .ptr = &fake_link, .vtable = &.{ .writePacket = @TypeOf(fake_link).writePacket, .writePackets = null, .attach = @TypeOf(fake_link).attach, .linkAddress = @TypeOf(fake_link).linkAddress, .mtu = @TypeOf(fake_link).mtu, .setMTU = @TypeOf(fake_link).setMTU, .capabilities = @TypeOf(fake_link).capabilities } };
    try s.createNIC(1, link_ep);
    _ = s.nics.get(1).?;
    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_res.ptr)));
    defer ep.close();
    ep.state = .established;
    ep.local_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 80 };
    ep.remote_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 1234 };
    ep.rcv_nxt = 1000;

    var data1 = [_]u8{'B'} ** 100;
    const pkt1 = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(&data1, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_pkt1 = pkt1;
    defer mut_pkt1.data.deinit();
    try ep.insertOOO(2000, mut_pkt1.data);
    try std.testing.expectEqual(@as(usize, 1), ep.ooo_list.len);
    try std.testing.expectEqual(@as(u32, 2000), ep.ooo_list.first.?.data.seq);

    var data2 = [_]u8{'A'} ** 100;
    const pkt2 = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(&data2, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_pkt2 = pkt2;
    const node2 = try tcp_proto.packet_node_pool.acquire();
    node2.data = .{ .data = try mut_pkt2.data.clone(allocator), .seq = 1000 };
    ep.rcv_list.append(node2);
    mut_pkt2.data.deinit();
    ep.rcv_nxt = 1100;
    ep.processOOO();
    try std.testing.expectEqual(@as(usize, 1), ep.rcv_list.len);
    try std.testing.expectEqual(@as(u32, 1100), ep.rcv_nxt);

    var data3 = [_]u8{'C'} ** 900;
    const pkt3 = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(&data3, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_pkt3 = pkt3;
    const node3 = try tcp_proto.packet_node_pool.acquire();
    node3.data = .{ .data = try mut_pkt3.data.clone(allocator), .seq = 1100 };
    ep.rcv_list.append(node3);
    mut_pkt3.data.deinit();
    ep.rcv_nxt = 2000;
    ep.processOOO();
    try std.testing.expectEqual(@as(u32, 2100), ep.rcv_nxt);
    try std.testing.expectEqual(@as(usize, 3), ep.rcv_list.len);
    try std.testing.expectEqual(@as(usize, 0), ep.ooo_list.len);
}

test "TCP SACK Blocks Generation" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_res.ptr)));
    ep.hint_sack_enabled = true;
    defer ep.close();
    ep.state = .established;
    ep.rcv_nxt = 1000;

    var data1 = [_]u8{'B'} ** 100;
    const pkt1 = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(&data1, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_pkt1 = pkt1;
    try ep.insertOOO(2000, mut_pkt1.data);
    try std.testing.expectEqual(@as(usize, 1), ep.sack_blocks.items.len);
    try std.testing.expectEqual(@as(u32, 2000), ep.sack_blocks.items[0].start);
    try std.testing.expectEqual(@as(u32, 2100), ep.sack_blocks.items[0].end);

    try ep.insertOOO(3000, mut_pkt1.data);
    mut_pkt1.data.deinit();
    try std.testing.expectEqual(@as(usize, 2), ep.sack_blocks.items.len);
    try std.testing.expectEqual(@as(u32, 3000), ep.sack_blocks.items[0].start);
    try std.testing.expectEqual(@as(u32, 3100), ep.sack_blocks.items[0].end);
    try std.testing.expectEqual(@as(u32, 2000), ep.sack_blocks.items[1].start);
    try std.testing.expectEqual(@as(u32, 2100), ep.sack_blocks.items[1].end);

    ep.rcv_nxt = 2100;
    ep.processOOO();
    try std.testing.expectEqual(@as(usize, 1), ep.sack_blocks.items.len);
    try std.testing.expectEqual(@as(u32, 3000), ep.sack_blocks.items[0].start);
}

test "TCP readv/writev zero-copy" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var wq = waiter.Queue{};
    const ep_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq);
    const ep = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_res.ptr)));
    ep.state = .established;
    ep.local_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 80 };
    ep.remote_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 1234 };

    // We need a mock NIC/Link to capture the packets
    var fake_link = struct {
        captured: std.ArrayList(u8),
        fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            const hdr = pkt.header.view();
            self.captured.appendSlice(hdr) catch return tcpip.Error.OutOfMemory;
            for (pkt.data.views) |v| {
                self.captured.appendSlice(v.view) catch return tcpip.Error.OutOfMemory;
            }
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return 0;
        }
    }{ .captured = std.ArrayList(u8).init(allocator) };
    defer fake_link.captured.deinit();
    defer ep.close();

    // Test writev
    const data1 = "hello ";
    const data2 = "world";
    var iov_write = [_][]u8{ @constCast(data1), @constCast(data2) };
    var uio_write = buffer.Uio.init(&iov_write);

    const link_ep = stack.LinkEndpoint{ .ptr = &fake_link, .vtable = &.{ .writePacket = @TypeOf(fake_link).writePacket, .attach = @TypeOf(fake_link).attach, .linkAddress = @TypeOf(fake_link).linkAddress, .mtu = @TypeOf(fake_link).mtu, .setMTU = @TypeOf(fake_link).setMTU, .capabilities = @TypeOf(fake_link).capabilities } };
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = ep.local_addr.?.addr, .prefix_len = 24 } });
    try s.addLinkAddress(ep.remote_addr.?.addr, .{ .addr = [_]u8{0} ** 6 });

    _ = try ep.endpoint().writev(&uio_write, .{});

    // Check if "hello world" is in captured data (after headers)
    const captured = fake_link.captured.items;
    try std.testing.expect(std.mem.indexOf(u8, captured, "hello world") != null);

    // Test readv
    var rcv_buf1: [3]u8 = undefined;
    var rcv_buf2: [10]u8 = undefined;
    var iov_read = [_][]u8{ &rcv_buf1, &rcv_buf2 };
    var uio_read = buffer.Uio.init(&iov_read);

    // Inject data into rcv_list
    const inject_data = "readv test";
    const node = try tcp_proto.packet_node_pool.acquire();
    node.data = .{ .data = try buffer.VectorisedView.fromSlice(inject_data, allocator, &s.cluster_pool), .seq = 1000 };
    ep.rcv_list.append(node);
    ep.rcv_buf_used = inject_data.len;
    ep.rcv_view_count = 1;

    const n = try ep.endpoint().readv(&uio_read, null);
    try std.testing.expectEqual(@as(usize, 10), n);
    try std.testing.expectEqualStrings("rea", &rcv_buf1);
    try std.testing.expectEqualStrings("dv test", rcv_buf2[0..7]);
}
