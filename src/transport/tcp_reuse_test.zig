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

fn createStack(allocator: std.mem.Allocator) !*stack.Stack {
    const s = try allocator.create(stack.Stack);
    s.* = try stack.Stack.init(allocator);
    return s;
}

test "TCP TIME_WAIT Reuse" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    defer tcp_proto.deinit();
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_link = struct {
        allocator: std.mem.Allocator,
        last_pkt: ?[]u8 = null,
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
    defer if (fake_link.last_pkt) |p| allocator.free(p);
    const link_ep = stack.LinkEndpoint{ .ptr = &fake_link, .vtable = &.{ .writePacket = @TypeOf(fake_link).writePacket, .writePackets = null, .attach = @TypeOf(fake_link).attach, .linkAddress = @TypeOf(fake_link).linkAddress, .mtu = @TypeOf(fake_link).mtu, .setMTU = @TypeOf(fake_link).setMTU, .capabilities = @TypeOf(fake_link).capabilities } };
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const ca = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const sa = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = ca.addr, .prefix_len = 24 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = sa.addr, .prefix_len = 24 } });
    try s.addLinkAddress(sa.addr, .{ .addr = [_]u8{0} ** 6 });
    try s.addLinkAddress(ca.addr, .{ .addr = [_]u8{0} ** 6 });

    // 1. Establish connection
    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_client_res.ptr)));
    // ep_client.retransmit_timer.context = ep_client;
    // ep_client.time_wait_timer.context = ep_client;
    defer ep_client.decRef();

    try ep_client.endpoint().bind(ca);
    try ep_client.endpoint().connect(sa);

    // Mock SYN-ACK from server
    const r_to_client = stack.Route{ .local_address = ca.addr, .remote_address = sa.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_client = stack.TransportEndpointID{ .local_port = 1234, .local_address = ca.addr, .remote_port = 80, .remote_address = sa.addr, .protocol = tcp.ProtocolNumber };
    
    const client_isn = header.TCP.init(fake_link.last_pkt.?[20..]).sequenceNumber();

    var syn_ack_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(syn_ack_buf);
    @memset(syn_ack_buf, 0);
    var syn_ack = header.TCP.init(syn_ack_buf);
    syn_ack.encode(sa.port, ca.port, 5000, client_isn +% 1, header.TCPFlagSyn | header.TCPFlagAck, 65535);
    const syn_ack_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(syn_ack_buf, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_syn_ack = syn_ack_pkt;
    
    ep_client.handlePacket(&r_to_client, id_to_client, mut_syn_ack);
    mut_syn_ack.data.deinit();
    try std.testing.expect(ep_client.state == .established);

    // 2. Close connection (Active close by client)
    ep_client.endpoint().close();
    try std.testing.expect(ep_client.state == .fin_wait1);

    // Mock ACK for client's FIN
    var ack_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(ack_buf);
    @memset(ack_buf, 0);
    var ack = header.TCP.init(ack_buf);
    ack.encode(sa.port, ca.port, 5001, ep_client.snd_nxt, header.TCPFlagAck, 65535);
    const ack_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(ack_buf, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_ack = ack_pkt;
    ep_client.handlePacket(&r_to_client, id_to_client, mut_ack);
    mut_ack.data.deinit();
    try std.testing.expect(ep_client.state == .fin_wait2);

    // Mock FIN from server
    var fin_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(fin_buf);
    @memset(fin_buf, 0);
    var fin = header.TCP.init(fin_buf);
    fin.encode(sa.port, ca.port, 5001, ep_client.snd_nxt, header.TCPFlagFin | header.TCPFlagAck, 65535);
    const fin_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(fin_buf, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    var mut_fin = fin_pkt;
    ep_client.handlePacket(&r_to_client, id_to_client, mut_fin);
    mut_fin.data.deinit();
    try std.testing.expect(ep_client.state == .time_wait);

    // 3. Try to establish NEW connection with same 4-tuple without SO_REUSEADDR
    var wq_client2 = waiter.Queue{};
    const ep_client2_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client2);
    const ep_client2 = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_client2_res.ptr)));
    // ep_client2.retransmit_timer.context = ep_client2;
    // ep_client2.time_wait_timer.context = ep_client2;
    defer ep_client2.decRef();

    try ep_client2.endpoint().bind(ca);
    const connect_res = ep_client2.endpoint().connect(sa);
    try std.testing.expectError(tcpip.Error.DuplicateAddress, connect_res);

    // 4. Try WITH SO_REUSEADDR
    try ep_client2.endpoint().setOption(.{ .reuse_address = true });
    try ep_client2.endpoint().connect(sa);
    try std.testing.expect(ep_client2.state == .syn_sent);
}
