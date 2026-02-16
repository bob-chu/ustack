const std = @import("std");
const stack = @import("../stack.zig");
const tcpip = @import("../tcpip.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const ipv4 = @import("../network/ipv4.zig");
const TCPProtocol = @import("tcp.zig").TCPProtocol;
const TCPEndpoint = @import("tcp.zig").TCPEndpoint;

test "TCP 2MSL TIME_WAIT Expiration" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    // Set MSL very low for testing
    s.tcp_msl = 100; // 100ms -> 200ms TIME_WAIT

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

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).mtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const ca = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const sa = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };

    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_client_res.ptr)));

    ep_client.state = .fin_wait2;
    ep_client.local_addr = ca;
    ep_client.remote_addr = sa;
    const id = stack.TransportEndpointID{
        .local_port = ca.port,
        .local_address = ca.addr,
        .remote_port = sa.port,
        .remote_address = sa.addr,
        .transport_protocol = 6,
    };
    try s.registerTransportEndpoint(id, ep_client.transportEndpoint());

    // Mock FIN from server to trigger TIME_WAIT
    const fin_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(fin_buf);
    @memset(fin_buf, 0);
    var fin = header.TCP.init(fin_buf);
    fin.encode(sa.port, ca.port, 5001, ep_client.snd_nxt, header.TCPFlagFin | header.TCPFlagAck, 65535);
    const r_to_client = stack.Route{ .local_address = ca.addr, .remote_address = sa.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    var fin_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(fin_buf, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    defer fin_pkt.data.deinit();

    ep_client.handlePacket(&r_to_client, id, fin_pkt);

    try std.testing.expect(ep_client.state == .time_wait);
    try std.testing.expect(ep_client.time_wait_timer.active);
    try std.testing.expect(s.endpoints.get(id) != null);
    if (s.endpoints.get(id)) |e| e.decRef();

    // Advance time by 2MSL (200ms)
    _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 201);

    try std.testing.expect(ep_client.state == .closed);
    try std.testing.expect(s.endpoints.get(id) == null);
}

test "TCP RFC 1337 RST in TIME_WAIT" {
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

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).mtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const ca = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const sa = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };

    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client = @as(*TCPEndpoint, @ptrCast(@alignCast(ep_client_res.ptr)));

    ep_client.state = .time_wait;
    ep_client.local_addr = ca;
    ep_client.remote_addr = sa;
    const id = stack.TransportEndpointID{
        .local_port = ca.port,
        .local_address = ca.addr,
        .remote_port = sa.port,
        .remote_address = sa.addr,
        .transport_protocol = 6,
    };
    try s.registerTransportEndpoint(id, ep_client.transportEndpoint());
    s.timer_queue.schedule(&ep_client.time_wait_timer, 60000);

    // Mock RST from server
    const rst_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(rst_buf);
    @memset(rst_buf, 0);
    var rst = header.TCP.init(rst_buf);
    rst.encode(sa.port, ca.port, 5001, ep_client.snd_nxt, header.TCPFlagRst, 65535);
    const r_to_client = stack.Route{ .local_address = ca.addr, .remote_address = sa.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    var rst_pkt = tcpip.PacketBuffer{ .data = try buffer.VectorisedView.fromSlice(rst_buf, allocator, &s.cluster_pool), .header = buffer.Prependable.init(&[_]u8{}) };
    defer rst_pkt.data.deinit();

    ep_client.handlePacket(&r_to_client, id, rst_pkt);

    // Should still be in TIME_WAIT (RFC 1337)
    try std.testing.expect(ep_client.state == .time_wait);
    try std.testing.expect(ep_client.time_wait_timer.active);
}
