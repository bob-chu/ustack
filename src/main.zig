const std = @import("std");

pub const buffer = @import("buffer.zig");
pub const header = @import("header.zig");
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

test {
    std.testing.refAllDecls(@This());
    _ = network.ipv4;
    _ = network.arp;
    _ = transport.udp;
    _ = transport.tcp;
    _ = transport.congestion.control;
    _ = transport.congestion.cubic;
    _ = transport.congestion.bbr;
    _ = link.eth;
    _ = time;
}
