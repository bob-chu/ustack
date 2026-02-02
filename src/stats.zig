const std = @import("std");

pub const StackStats = struct {
    ip: IPStats = .{},
    tcp: TCPStats = .{},
    arp: ARPStats = .{},
    latency: LatencyStats = .{},
    pool: PoolStats = .{},

    pub fn reset(self: *StackStats) void {
        self.ip = .{};
        self.tcp = .{};
        self.arp = .{};
        self.latency = .{};
        self.pool = .{};
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
        std.debug.print("  Syncache: searches={d}, max_size={d}\n", .{ self.tcp.syncache_searches, self.tcp.syncache_max_size });
        std.debug.print("  Rx Flags - SYN: {d}, SYN+ACK: {d}, ACK: {d}, PSH: {d}, FIN: {d}\n", .{ self.tcp.rx_syn, self.tcp.rx_syn_ack, self.tcp.rx_ack, self.tcp.rx_psh, self.tcp.rx_fin });
        std.debug.print("  Tx Flags - SYN: {d}, SYN+ACK: {d}, ACK: {d}, PSH: {d}, FIN: {d}\n", .{ self.tcp.tx_syn, self.tcp.tx_syn_ack, self.tcp.tx_ack, self.tcp.tx_psh, self.tcp.tx_fin });
        std.debug.print("Pool Fallbacks (Syscall heavy):\n", .{});
        std.debug.print("  Cluster: {d}, Buffer: {d}, Generic: {d}\n", .{ self.pool.cluster_fallback, self.pool.buffer_fallback, self.pool.generic_fallback });
        std.debug.print("-------------------------\n", .{});
        self.latency.dump();
    }
};

pub const LatencyMetric = struct {
    count: u64 = 0,
    sum_ns: i64 = 0,
    min_ns: i64 = std.math.maxInt(i64),
    max_ns: i64 = 0,

    pub fn record(self: *@This(), ns: i64) void {
        self.count += 1;
        self.sum_ns += ns;
        if (ns < self.min_ns) self.min_ns = ns;
        if (ns > self.max_ns) self.max_ns = ns;
    }

    pub fn average(self: @This()) f64 {
        if (self.count == 0) return 0;
        return @as(f64, @floatFromInt(self.sum_ns)) / @as(f64, @floatFromInt(self.count));
    }
};

pub const LatencyStats = struct {
    network_layer: LatencyMetric = .{},
    transport_dispatch: LatencyMetric = .{},
    tcp_endpoint: LatencyMetric = .{},
    udp_endpoint: LatencyMetric = .{},

    pub fn dump(self: @This()) void {
        std.debug.print("\n--- Latency Statistics (ns) ---\n", .{});
        self.printMetric("Network Layer   ", self.network_layer);
        self.printMetric("Transport Disp  ", self.transport_dispatch);
        self.printMetric("TCP Endpoint    ", self.tcp_endpoint);
        self.printMetric("UDP Endpoint    ", self.udp_endpoint);
        std.debug.print("-------------------------------\n\n", .{});
    }

    fn printMetric(_: @This(), name: []const u8, m: LatencyMetric) void {
        if (m.count == 0) return;
        std.debug.print("{s}: avg={d:.2}, min={d}, max={d}, count={d}\n", .{ name, m.average(), m.min_ns, m.max_ns, m.count });
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
    syncache_searches: usize = 0,
    syncache_max_size: usize = 0,

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

pub const PoolStats = struct {
    cluster_fallback: usize = 0,
    buffer_fallback: usize = 0,
    generic_fallback: usize = 0,
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
