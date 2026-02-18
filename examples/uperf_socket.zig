const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const AfPacket = ustack.drivers.af_packet.AfPacket;
const EventMultiplexer = ustack.event_mux.EventMultiplexer;
const socket = ustack.socket;

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

const StaticBuffer = struct {
    var buf = [_]u8{'A'} ** 65536;
};

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <mode> <ip/prefix> [target_ip] [options]\n", .{args[0]});
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
    if (std.mem.eql(u8, mode, "client")) {
        global_config.target_ip = try parseIp(args[4]);
        idx = 5;
    }

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
        _ = try Connection.initClient(&global_stack, allocator, mux, global_config.target_ip.?, global_config.local_ip);
    }

    my_ev_run(loop);
    
    std.debug.print("--- Final Summary ---\n", .{});
    for (global_connections.items) |conn| {
        const end = if (conn.end_time > 0) conn.end_time else std.time.milliTimestamp();
        const start = if (conn.first_packet_time > 0) conn.first_packet_time else conn.start_time;
        const elapsed_ms = end - start;
        if (elapsed_ms == 0) continue;
        const sec = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        const role = if (conn.is_client) "TX" else "RX";
        const bytes = if (conn.is_client) conn.bytes_tx else conn.bytes_rx;
        std.debug.print("[{s}] Avg: {d: >7.2} Mbits/sec (Total: {} bytes over {d:.2}s)\n", .{ role, (@as(f64, @floatFromInt(bytes)) * 8.0) / sec / 1000000.0, bytes, sec });
    }
    ustack.stats.global_stats.dump();
}

fn libev_af_packet_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop; _ = watcher; _ = revents;
    _ = global_af_packet.readPacket() catch {};
    global_stack.flush();
}

var last_tick: i64 = 0;
fn libev_timer_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = loop; _ = watcher; _ = revents;
    const now = std.time.milliTimestamp();
    if (last_tick == 0) last_tick = now;
    const diff = now - last_tick;
    if (diff > 0) {
        _ = global_stack.timer_queue.tickTo(global_stack.timer_queue.current_tick + @as(u64, @intCast(diff)));
        last_tick = now;
    }
    global_stack.flush();

    if (global_config.protocol == .udp and std.mem.eql(u8, global_config.mode, "client")) {
        for (global_connections.items) |conn| {
            if (conn.is_client and !conn.closed) {
                conn.onEvent();
            }
        }
    }
}

fn libev_stats_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = watcher; _ = revents;
    const now = std.time.milliTimestamp();

    var total_rx_bytes: u64 = 0;
    var total_tx_bytes: u64 = 0;

    for (global_connections.items) |conn| {
        if (conn.is_client) {
            total_tx_bytes += conn.bytes_since_last_report;
        } else {
            total_rx_bytes += conn.bytes_since_last_report;
        }
        conn.bytes_since_last_report = 0;

        if (conn.is_client and conn.first_packet_time > 0) {
            const elapsed = now - conn.first_packet_time;
            if (elapsed > global_config.duration * 1000) {
                conn.end_time = now;
                my_ev_break(loop, 2);
                return;
            }
        }
    }

    if (total_rx_bytes > 0) {
        const mbps = (@as(f64, @floatFromInt(total_rx_bytes)) * 8.0) / 1000000.0;
        std.debug.print("[RX ] 1.00 sec {d: >7.2} Mbits/sec\n", .{ mbps });
    }
    if (total_tx_bytes > 0) {
        const mbps = (@as(f64, @floatFromInt(total_tx_bytes)) * 8.0) / 1000000.0;
        std.debug.print("[TX ] 1.00 sec {d: >7.2} Mbits/sec\n", .{ mbps });
    }
}

fn libev_mux_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop; _ = watcher; _ = revents;
    if (global_mux) |mux| {
        const ready = mux.pollReady() catch return;
        for (ready) |entry| {
            socket.Socket.dispatch(entry);
        }
    }
    global_stack.flush();
}

const PerfServer = struct {
    sock: *socket.Socket,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*PerfServer {
        const self = try allocator.create(PerfServer);
        const is_udp = global_config.protocol == .udp;
        const sock_obj = try socket.Socket.create(s, .inet, if (is_udp) .dgram else .stream, if (is_udp) .udp else .tcp);
        try sock_obj.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = global_config.port });
        if (!is_udp) try sock_obj.listen(128);

        self.* = .{ .sock = sock_obj, .allocator = allocator, .mux = mux };
        sock_obj.setHandler(mux, self, PerfServer.onEvent);

        if (is_udp) {
            _ = try Connection.init(allocator, sock_obj, mux, false);
        }
        return self;
    }

    fn onEvent(ctx: ?*anyopaque, sock_obj: *socket.Socket, events: waiter.EventMask) void {
        const self = @as(*PerfServer, @ptrCast(@alignCast(ctx.?)));
        if (events & waiter.EventIn != 0 and global_config.protocol == .tcp) {
            while (true) {
                const accepted = sock_obj.accept() catch break;
                accepted.setOption(.{ .congestion_control = global_config.cc_alg }) catch {};
                _ = Connection.init(self.allocator, accepted, self.mux, false) catch continue;
            }
        }
    }
};

fn noopConsumption(_: ?*anyopaque, _: usize) void {}

const UperfPayloader = struct {
    len: usize,
    fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
        const self = @as(*const UperfPayloader, @ptrCast(@alignCast(ptr)));
        return StaticBuffer.buf[0..self.len];
    }
};

const Connection = struct {
    sock: *socket.Socket,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    is_client: bool,
    closed: bool = false,
    start_time: i64 = 0,
    first_packet_time: i64 = 0,
    end_time: i64 = 0,
    bytes_rx: u64 = 0,
    bytes_tx: u64 = 0,
    bytes_since_last_report: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, sock: *socket.Socket, mux: *EventMultiplexer, is_client: bool) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{
            .sock = sock,
            .allocator = allocator,
            .mux = mux,
            .is_client = is_client,
            .start_time = std.time.milliTimestamp(),
            .first_packet_time = 0,
            .end_time = 0,
            .bytes_rx = 0,
            .bytes_tx = 0,
            .bytes_since_last_report = 0,
        };
        sock.setHandler(mux, self, Connection.onSocketEvent);
        try global_connections.append(self);
        return self;
    }

    pub fn initClient(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, target: [4]u8, local: [4]u8) !*Connection {
        const is_udp = global_config.protocol == .udp;
        const sock_obj = try socket.Socket.create(s, .inet, if (is_udp) .dgram else .stream, if (is_udp) .udp else .tcp);
        if (!is_udp) try sock_obj.setOption(.{ .congestion_control = global_config.cc_alg });
        const self = try Connection.init(allocator, sock_obj, mux, true);
        try sock_obj.bind(.{ .nic = 1, .addr = .{ .v4 = local }, .port = 0 });
        _ = sock_obj.connect(.{ .nic = 1, .addr = .{ .v4 = target }, .port = global_config.port }) catch |err| {
            if (err != tcpip.Error.WouldBlock) return err;
        };
        if (is_udp) self.onEvent();
        return self;
    }

    fn onSocketEvent(ctx: ?*anyopaque, _: *socket.Socket, events: waiter.EventMask) void {
        const self = @as(*Connection, @ptrCast(@alignCast(ctx.?)));
        self.onEventExplicit(events);
    }

    fn onEventExplicit(self: *Connection, mask: waiter.EventMask) void {
        if (self.closed) return;
        if (mask & (waiter.EventHUp | waiter.EventErr) != 0) {
            self.close();
            return;
        }

        // Handle RX
        if (mask & waiter.EventIn != 0) {
            while (true) {
                var vview = self.sock.endpoint.read(null) catch break;
                if (self.first_packet_time == 0) self.first_packet_time = std.time.milliTimestamp();
                if (vview.size == 0) { vview.deinit(); if (global_config.protocol == .tcp) self.close(); break; }
                self.bytes_rx += vview.size;
                self.bytes_since_last_report += vview.size;
                vview.deinit();
            }
        }
        
        // Handle TX
        if (self.is_client and (mask & waiter.EventOut != 0)) {
            if (self.first_packet_time == 0) self.first_packet_time = std.time.milliTimestamp();
            const slen = if (global_config.packet_size > 0) global_config.packet_size else if (global_config.protocol == .udp) @as(usize, @intCast(global_config.mtu - 28)) else 65536;
            var budget: usize = 10000;
            const p = UperfPayloader{ .len = @min(slen, 65536) };
            while (budget > 0) : (budget -= 1) {
                const sl = @min(slen, 65536);
                const n = if (global_config.protocol == .tcp)
                    self.sock.endpoint.writeZeroCopy(StaticBuffer.buf[0..sl], .{ .ptr = self, .run = noopConsumption }, .{}) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        return;
                    }
                else
                    self.sock.endpoint.write(.{ .ptr = @constCast(&p), .vtable = &.{ .fullPayload = UperfPayloader.fullPayload, .viewPayload = null } }, .{}) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        return;
                    };
                self.bytes_tx += n;
                self.bytes_since_last_report += n;
            }
        }
    }

    fn onEvent(self: *Connection) void {
        self.onEventExplicit(waiter.EventIn | (if (self.is_client) waiter.EventOut else 0));
    }

    fn close(self: *Connection) void {
        if (self.closed) return;
        self.closed = true;
        self.sock.deinit();
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
