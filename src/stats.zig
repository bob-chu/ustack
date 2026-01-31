const std = @import("std");

pub const StackStats = struct {
    ip: IPStats = .{},
    tcp: TCPStats = .{},
    arp: ARPStats = .{},

    pub fn reset(self: *StackStats) void {
        self.ip = .{};
        self.tcp = .{};
        self.arp = .{};
    }

    pub fn dump(self: StackStats) void {
        std.debug.print("\n--- ustack Statistics ---\n", .{});
        std.debug.print("IP:\n", .{});
        std.debug.print("  Rx: {d}, Tx: {d}, Dropped: {d}\n", .{ self.ip.rx_packets, self.ip.tx_packets, self.ip.dropped_packets });
        std.debug.print("ARP:\n", .{});
        std.debug.print("  Rx Req: {d}, Rx Rep: {d}, Tx Req: {d}, Tx Rep: {d}\n", .{ self.arp.rx_requests, self.arp.rx_replies, self.arp.tx_requests, self.arp.tx_replies });
        std.debug.print("TCP:\n", .{});
        std.debug.print("  Rx Seg: {d}, Tx Seg: {d}, Retrans: {d}\n", .{ self.tcp.rx_segments, self.tcp.tx_segments, self.tcp.retransmits });
        std.debug.print("  Active: {d}, Passive: {d}, Failed: {d}, Resets: {d}, PoolEx: {d}, SynDrop: {d}\n", .{ self.tcp.active_opens, self.tcp.passive_opens, self.tcp.failed_connections, self.tcp.resets_sent, self.tcp.pool_exhausted, self.tcp.syncache_dropped });
        std.debug.print("  Rx Flags - SYN: {d}, SYN+ACK: {d}, ACK: {d}, PSH: {d}, FIN: {d}\n", .{ self.tcp.rx_syn, self.tcp.rx_syn_ack, self.tcp.rx_ack, self.tcp.rx_psh, self.tcp.rx_fin });
        std.debug.print("  Tx Flags - SYN: {d}, SYN+ACK: {d}, ACK: {d}, PSH: {d}, FIN: {d}\n", .{ self.tcp.tx_syn, self.tcp.tx_syn_ack, self.tcp.tx_ack, self.tcp.tx_psh, self.tcp.tx_fin });
        std.debug.print("-------------------------\n\n", .{});
    }
};

pub fn dumpLinkStats(self: *LinkStats) void {
    std.debug.print("\n--- Link Statistics ---\n", .{});
    std.debug.print("  Rx: {d} packets, {d} bytes\n", .{ self.rx_packets, self.rx_bytes });
    std.debug.print("  Tx: {d} packets, {d} bytes\n", .{ self.tx_packets, self.tx_bytes });
    std.debug.print("  Rx Errors: {d}, Tx Errors: {d}\n", .{ self.rx_errors, self.tx_errors });
    std.debug.print("-------------------------\n\n", .{});
}

pub fn resetLinkStats(self: *LinkStats) void {
    self.* = .{};
}

pub const IPStats = struct {
    rx_packets: usize = 0,
    tx_packets: usize = 0,
    dropped_packets: usize = 0,
    invalid_checksum: usize = 0,
    no_route: usize = 0,
};

pub const TCPStats = struct {
    rx_segments: usize = 0,
    tx_segments: usize = 0,
    retransmits: usize = 0,
    active_opens: usize = 0,
    passive_opens: usize = 0,
    failed_connections: usize = 0,
    established: usize = 0,
    resets_sent: usize = 0,
    resets_received: usize = 0,
    pool_exhausted: usize = 0,
    syncache_dropped: usize = 0,

    // TCP flags stats
    rx_syn: usize = 0,
    rx_syn_ack: usize = 0,
    rx_ack: usize = 0,
    rx_psh: usize = 0,
    rx_fin: usize = 0,
    tx_syn: usize = 0,
    tx_syn_ack: usize = 0,
    tx_ack: usize = 0,
    tx_psh: usize = 0,
    tx_fin: usize = 0,
};

pub const ARPStats = struct {
    rx_requests: usize = 0,
    rx_replies: usize = 0,
    tx_requests: usize = 0,
    tx_replies: usize = 0,
};

pub const LinkStats = struct {
    rx_packets: usize = 0,
    tx_packets: usize = 0,
    rx_bytes: usize = 0,
    tx_bytes: usize = 0,
    rx_errors: usize = 0,
    tx_errors: usize = 0,
};

pub var global_stats: StackStats = .{};
pub var global_link_stats: LinkStats = .{};
