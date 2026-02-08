const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const AfPacket = ustack.drivers.af_packet.AfPacket;
const EventMultiplexer = ustack.event_mux.EventMultiplexer;

const c = @cImport({
    @cInclude("ev.h");
});

var global_stack: stack.Stack = undefined;
var global_af_packet: AfPacket = undefined;
var global_eth: ustack.link.eth.EthernetEndpoint = undefined;
var global_mux: ?*EventMultiplexer = null;
var global_connections: std.ArrayList(*Connection) = undefined;
var global_config: Config = .{};

const MuxContext = union(enum) {
    server: *PerfServer,
    connection: *Connection,
};

const Config = struct {
    mode: []const u8 = "server",
    protocol: enum { tcp, udp } = .tcp,
    port: u16 = 5201,
    target_ip: ?[4]u8 = null,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    interface: []const u8 = "",
    mtu: u32 = 1500,
    packet_size: usize = 0,
    duration: u64 = 5,
    cc_alg: tcpip.CongestionControlAlgorithm = .new_reno,
};

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <mode> <ip/prefix> [target_ip] [options]\n", .{args[0]});
        std.debug.print("  mode: server | client\n", .{});
        std.debug.print("  options:\n", .{});
        std.debug.print("    -u        Use UDP (default TCP)\n", .{});
        std.debug.print("    -m MTU    Set MTU (default 1500)\n", .{});
        std.debug.print("    -l LEN    Payload length\n", .{});
        std.debug.print("    -t TIME   Duration in seconds (default 5)\n", .{});
        return;
    }

    const ifname = args[1];
    const mode = args[2];
    const ip_cidr = args[3];

    global_config.interface = ifname;
    global_config.mode = mode;

    var parts = std.mem.split(u8, ip_cidr, "/");
    global_config.local_ip = try parseIp(parts.first());
    const prefix_len = try std.fmt.parseInt(u8, parts.next() orelse "24", 10);

    var idx: usize = 4;
    if (std.mem.eql(u8, mode, "client")) idx = 5;
    while (idx < args.len) : (idx += 1) {
        if (std.mem.eql(u8, args[idx], "-m")) {
            idx += 1;
            global_config.mtu = try std.fmt.parseInt(u32, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-l")) {
            idx += 1;
            global_config.packet_size = try std.fmt.parseInt(usize, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-t")) {
            idx += 1;
            global_config.duration = try std.fmt.parseInt(u64, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-u")) {
            global_config.protocol = .udp;
        } else if (std.mem.eql(u8, args[idx], "-C")) {
            idx += 1;
            if (std.mem.eql(u8, args[idx], "cubic")) {
                global_config.cc_alg = .cubic;
            } else if (std.mem.eql(u8, args[idx], "bbr")) {
                global_config.cc_alg = .bbr;
            } else if (std.mem.eql(u8, args[idx], "newreno")) {
                global_config.cc_alg = .new_reno;
            }
        }
    }

    global_stack = try ustack.init(allocator);
    global_af_packet = try AfPacket.init(allocator, &global_stack.cluster_pool, global_config.interface);
    global_eth = ustack.link.eth.EthernetEndpoint.init(global_af_packet.linkEndpoint(), global_af_packet.address);
    global_eth.linkEndpoint().setMTU(global_config.mtu);
    try global_stack.createNIC(1, global_eth.linkEndpoint());

    const nic = global_stack.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0806, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = global_config.local_ip }, .prefix_len = prefix_len } });

    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = global_config.local_ip }, .prefix = prefix_len }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = global_config.mtu });
    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = global_config.mtu });

    const mux = try EventMultiplexer.init(allocator);
    global_mux = mux;
    global_connections = std.ArrayList(*Connection).init(allocator);

    const loop = my_ev_default_loop();

    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_af_packet.fd, 0x01);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.001, 0.001);
    my_ev_timer_start(loop, &timer_watcher);

    var stats_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&stats_watcher, libev_stats_cb, 1.0, 1.0);
    my_ev_timer_start(loop, &stats_watcher);

    var mux_io = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), 0x01);
    my_ev_io_start(loop, &mux_io);

    if (std.mem.eql(u8, mode, "server")) {
        _ = try PerfServer.init(&global_stack, allocator, mux);
    } else {
        const target_ip = try parseIp(args[4]);
        _ = try Connection.initClient(&global_stack, allocator, mux, target_ip, global_config.local_ip);
    }
    my_ev_run(loop);
}

fn libev_af_packet_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_af_packet.readPacket() catch {};
    global_stack.flush();
}

var last_tick: i64 = 0;
fn libev_timer_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    const now = std.time.milliTimestamp();
    if (last_tick == 0) last_tick = now;
    const diff = now - last_tick;
    if (diff > 0) {
        _ = global_stack.timer_queue.tickTo(global_stack.timer_queue.current_tick + @as(u64, @intCast(diff)));
        last_tick = now;
    }
    global_stack.flush();
}

fn libev_stats_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = watcher;
    _ = revents;
    const now = std.time.milliTimestamp();

    var total_rx_bytes: u64 = 0;
    var total_rx_pkts: u64 = 0;
    var total_tx_bytes: u64 = 0;
    var total_tx_pkts: u64 = 0;

    for (global_connections.items) |conn| {
        if (conn.is_client) {
            total_tx_bytes += conn.bytes_since_last_report;
            total_tx_pkts += conn.packets_since_last_report;
        } else {
            total_rx_bytes += conn.bytes_since_last_report;
            total_rx_pkts += conn.packets_since_last_report;
        }
        conn.bytes_since_last_report = 0;
        conn.packets_since_last_report = 0;
        const elapsed = now - conn.start_time;
        if (elapsed > global_config.duration * 1000) {
            const sec = @as(f64, @floatFromInt(elapsed)) / 1000.0;
            const role = if (conn.is_client) "TX" else "RX";
            std.debug.print("- - - - - - - - - - - - - - - - - - - - - - - - -\n", .{});
            std.debug.print("[{s}] 0.00-{d: >5.2} sec {d: >7.2} Mbits/sec (Total: {} bytes)\n", .{ role, sec, (@as(f64, @floatFromInt(conn.bytes)) * 8.0) / sec / 1000000.0, conn.bytes });

            ustack.stats.global_stats.dump();
            ustack.stats.dumpLinkStats(&ustack.stats.global_link_stats);

            // Stop the libev loop cleanly
            my_ev_break(loop, 2); // EVBREAK_ALL = 2
            return;
        }
    }

    if (total_rx_bytes > 0 or total_rx_pkts > 0) {
        const mbps = (@as(f64, @floatFromInt(total_rx_bytes)) * 8.0) / 1000000.0;
        const pps = @as(f64, @floatFromInt(total_rx_pkts));
        const avg_size = if (total_rx_pkts > 0) total_rx_bytes / total_rx_pkts else 0;
        std.debug.print("[RX ] 1.00 sec {d: >7.2} Mbits/sec  {d: >9.2} pps (avg: {} bytes)\n", .{ mbps, pps, avg_size });
    }
    if (total_tx_bytes > 0 or total_tx_pkts > 0) {
        const mbps = (@as(f64, @floatFromInt(total_tx_bytes)) * 8.0) / 1000000.0;
        const pps = @as(f64, @floatFromInt(total_tx_pkts));
        const avg_size = if (total_tx_pkts > 0) total_tx_bytes / total_tx_pkts else 0;
        std.debug.print("[TX ] 1.00 sec {d: >7.2} Mbits/sec  {d: >9.2} pps (avg: {} bytes)\n", .{ mbps, pps, avg_size });
    }
}

fn libev_mux_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    if (global_mux) |mux| {
        const ready = mux.pollReady() catch return;
        for (ready) |entry| {
            const ctx = @as(*MuxContext, @ptrCast(@alignCast(entry.context.?)));
            switch (ctx.*) {
                .server => |s| s.onAccept(),
                .connection => |conn| conn.onEvent(),
            }
        }
    }
    global_stack.flush();
}

const PerfServer = struct {
    listener: ustack.tcpip.Endpoint,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*PerfServer {
        const self = try allocator.create(PerfServer);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const is_udp = global_config.protocol == .udp;
        const ep = try s.transport_protocols.get(if (is_udp) @as(u8, 17) else 6).?.newEndpoint(s, 0x0800, wq);
        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = global_config.port });
        if (!is_udp) {
            try ep.listen(128);
        } else {
            try ep.setOption(.{ .congestion_control = global_config.cc_alg });
        }

        self.* = .{ .listener = ep, .allocator = allocator, .mux = mux, .mux_ctx = .{ .server = self }, .wait_entry = undefined };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn);

        if (is_udp) {
            _ = try Connection.init(allocator, ep, wq, mux, false);
        }
        return self;
    }

    fn onAccept(self: *PerfServer) void {
        while (true) {
            const res = self.listener.accept() catch break;
            if (global_config.protocol == .tcp) {
                res.ep.setOption(.{ .congestion_control = global_config.cc_alg }) catch {};
            }
            _ = Connection.init(self.allocator, res.ep, res.wq, self.mux, false) catch continue;
        }
    }
};

const StaticBuffer = struct {
    var buf = [_]u8{'A'} ** 65536;
};

const UperfPayloader = struct {
    len: usize,
    fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
        const self = @as(*const UperfPayloader, @ptrCast(@alignCast(ptr)));
        return StaticBuffer.buf[0..self.len];
    }
};

fn noopConsumption(ptr: *anyopaque, size: usize) void {
    _ = ptr;
    _ = size;
}

const Connection = struct {
    ep: ustack.tcpip.Endpoint,
    wq: *waiter.Queue,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    is_client: bool,
    closed: bool = false,
    start_time: i64 = 0,
    last_report_time: i64 = 0,
    bytes: u64 = 0,
    bytes_since_last_report: u64 = 0,
    packets_since_last_report: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer, is_client: bool) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{ .ep = ep, .wq = wq, .allocator = allocator, .mux = mux, .mux_ctx = .{ .connection = self }, .wait_entry = undefined, .is_client = is_client, .start_time = std.time.milliTimestamp(), .last_report_time = std.time.milliTimestamp() };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn | (if (is_client) waiter.EventOut else 0) | waiter.EventHUp | waiter.EventErr);
        try global_connections.append(self);
        return self;
    }

    pub fn initClient(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, target: [4]u8, local: [4]u8) !*Connection {
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(if (global_config.protocol == .udp) @as(u8, 17) else 6).?.newEndpoint(s, 0x0800, wq);
        if (global_config.protocol == .tcp) {
            try ep.setOption(.{ .congestion_control = global_config.cc_alg });
        }
        const self = try Connection.init(allocator, ep, wq, mux, true);
        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = local }, .port = 0 });
        _ = ep.connect(.{ .nic = 1, .addr = .{ .v4 = target }, .port = global_config.port }) catch |err| {
            if (err != tcpip.Error.WouldBlock) return err;
        };
        if (global_config.protocol == .udp) self.onEvent();
        return self;
    }

    fn onEvent(self: *Connection) void {
        _ = std.time.milliTimestamp();
        if (self.is_client) {
            // Stats moved to libev_stats_cb
        }

        if (!self.is_client) {
            while (true) {
                var buf = self.ep.read(null) catch break;
                defer buf.deinit();
                if (buf.size == 0) {
                    self.close();
                    break;
                }
                self.bytes_since_last_report += buf.size;
                self.bytes += buf.size;
                self.packets_since_last_report += 1; // Assuming 1 buf = 1 packet, roughly correct for UDP
            }
        } else {
            var slen: usize = 0;
            if (global_config.packet_size > 0) {
                slen = global_config.packet_size;
            } else {
                if (global_config.protocol == .udp) {
                    slen = @as(usize, @intCast(global_config.mtu - 28)); // IP(20) + UDP(8)
                } else {
                    slen = 65536; // Default to 64KB for TCP to enable batching
                }
            }
            var p = UperfPayloader{ .len = @min(slen, 65536) };
            var budget: usize = 1000;
            while (budget > 0) : (budget -= 1) {
                const sl = @min(slen, 65536);
                const n = if (global_config.protocol == .tcp)
                    self.ep.writeZeroCopy(StaticBuffer.buf[0..sl], .{ .ptr = self, .run = noopConsumption }, .{}) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        return;
                    }
                else
                    self.ep.write(.{ .ptr = &p, .vtable = &.{ .fullPayload = UperfPayloader.fullPayload } }, .{}) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        return;
                    };
                self.bytes += n;
                self.bytes_since_last_report += n;
                self.packets_since_last_report += 1;
            }
            EventMultiplexer.upcall(&self.wait_entry);
        }
    }

    fn close(self: *Connection) void {
        if (self.closed) return;
        self.closed = true;
        self.wq.eventUnregister(&self.wait_entry);
        self.ep.close();
    }
};

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |j| out[j] = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidIP, 10);
    return out;
}

extern fn my_ev_default_loop() ?*anyopaque;
extern fn my_ev_io_init(w: *c.ev_io, cb: *const fn (?*anyopaque, *c.ev_io, i32) callconv(.C) void, fd: i32, events: i32) void;
extern fn my_ev_timer_init(w: *c.ev_timer, cb: *const fn (?*anyopaque, *c.ev_timer, i32) callconv(.C) void, after: f64, repeat: f64) void;
extern fn my_ev_io_start(loop: ?*anyopaque, w: *c.ev_io) void;
extern fn my_ev_timer_start(loop: ?*anyopaque, w: *c.ev_timer) void;
extern fn my_ev_run(loop: ?*anyopaque) void;
extern fn my_ev_break(loop: ?*anyopaque, how: i32) void;
