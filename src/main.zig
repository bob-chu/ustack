const std = @import("std");
const builtin = @import("builtin");

pub const buffer = @import("buffer.zig");
pub const header = @import("header.zig");
pub const log = @import("log.zig");
pub const stack = @import("stack.zig");
pub const waiter = @import("waiter.zig");
pub const time = @import("time.zig");
pub const tcpip = @import("tcpip.zig");
pub const network = struct {
    pub const ipv4 = @import("network/ipv4.zig");
    pub const ipv6 = @import("network/ipv6.zig");
    pub const arp = @import("network/arp.zig");
    pub const icmp = @import("network/icmp.zig");
    pub const icmpv6 = @import("network/icmpv6.zig");
};
pub const transport = struct {
    pub const udp = @import("transport/udp.zig");
    pub const tcp = @import("transport/tcp.zig");
    pub const congestion = struct {
        pub const control = @import("transport/congestion/control.zig");
        pub const cubic = @import("transport/congestion/cubic.zig");
        pub const bbr = @import("transport/congestion/bbr.zig");
    };
};
pub const link = struct {
    pub const eth = @import("link/eth.zig");
};
pub const dns = @import("dns.zig");
pub const posix = @import("posix.zig");
pub const event_mux = @import("event_mux.zig");

pub const drivers = struct {
    pub const loopback = @import("drivers/loopback.zig");
    pub const tap = if (builtin.os.tag == .linux) @import("drivers/linux/tap.zig") else struct {};
    pub const af_packet = if (builtin.os.tag == .linux) @import("drivers/linux/af_packet.zig") else struct {};
    pub const af_xdp = if (builtin.os.tag == .linux) @import("drivers/linux/af_xdp.zig") else struct {};
};

pub fn init(allocator: std.mem.Allocator) !stack.Stack {
    var s = try stack.Stack.init(allocator);
    errdefer s.deinit();

    const ipv4_proto = try allocator.create(network.ipv4.IPv4Protocol);
    ipv4_proto.* = network.ipv4.IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    const ipv6_proto = try allocator.create(network.ipv6.IPv6Protocol);
    ipv6_proto.* = network.ipv6.IPv6Protocol.init();
    try s.registerNetworkProtocol(ipv6_proto.protocol());

    const arp_proto = try allocator.create(network.arp.ARPProtocol);
    arp_proto.* = network.arp.ARPProtocol.init();
    try s.registerNetworkProtocol(arp_proto.protocol());

    const icmp_proto = try allocator.create(network.icmp.ICMPv4Protocol);
    icmp_proto.* = network.icmp.ICMPv4Protocol.init();
    try s.registerNetworkProtocol(icmp_proto.protocol());

    const icmpv4_transport = try allocator.create(network.icmp.ICMPv4TransportProtocol);
    icmpv4_transport.* = network.icmp.ICMPv4TransportProtocol.init();
    try s.registerTransportProtocol(icmpv4_transport.protocol());

    const tcp_proto = transport.tcp.TCPProtocol.init(allocator);
    try s.registerTransportProtocol(tcp_proto.protocol());

    const udp_proto = try allocator.create(transport.udp.UDPProtocol);
    udp_proto.* = transport.udp.UDPProtocol.init();
    try s.registerTransportProtocol(udp_proto.protocol());

    const icmpv6_proto = try allocator.create(network.icmpv6.ICMPv6TransportProtocol);
    icmpv6_proto.* = network.icmpv6.ICMPv6TransportProtocol.init();
    try s.registerTransportProtocol(icmpv6_proto.protocol());

    return s;
}

pub const interface = @import("interface.zig");
pub const utils = @import("utils.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("drivers/linux/test_af_xdp.zig");
}
