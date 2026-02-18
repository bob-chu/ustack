const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const header = ustack.header;
const AfPacket = ustack.drivers.af_packet.AfPacket;
const EventMultiplexer = ustack.event_mux.EventMultiplexer;
const socket = ustack.socket;
const stats = @import("ustack").stats;

const c = @cImport({
    @cInclude("ev.h");
});

var global_stack: stack.Stack = undefined;
var global_af_packet: AfPacket = undefined;
var global_eth: ustack.link.eth.EthernetEndpoint = undefined;
var global_mux: ?*EventMultiplexer = null;

const Mode = enum { server, client };

const Config = struct {
    mode: Mode,
    port: u16 = 5201,
    target_ip: ?[4]u8 = null,
    local_ip: [4]u8,
    interface: []const u8,
    mtu: u32 = 1500,
    max_conns: ?u32 = null,
    concurrency: u32 = 1,
    duration: ?u64 = null,
};

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const config = try parseArgs(args);

    global_stack = try ustack.init(allocator);
    global_stack.tcp_msl = 100;
    global_af_packet = try AfPacket.init(allocator, &global_stack.cluster_pool, config.interface);
    global_eth = ustack.link.eth.EthernetEndpoint.init(global_af_packet.linkEndpoint(), global_af_packet.address);
    global_eth.linkEndpoint().setMTU(config.mtu);
    try global_stack.createNIC(1, global_eth.linkEndpoint());
    const nic = global_stack.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0806, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = config.local_ip }, .prefix_len = 24 } });
    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = config.local_ip }, .prefix = 24 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = config.mtu });
    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = config.mtu });

    const loop = my_ev_default_loop();
    global_loop = loop;
    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_af_packet.fd, 0x01);
    my_ev_io_start(loop, &io_watcher);
    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.001, 0.001);
    my_ev_timer_start(loop, &timer_watcher);
    const mux = try EventMultiplexer.init(allocator);
    global_mux = mux;
    var mux_io = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), 0x01);
    my_ev_io_start(loop, &mux_io);

    if (config.mode == .server) {
        _ = try PingServer.init(&global_stack, allocator, mux, config);
    } else {
        const client = try PingClient.init(&global_stack, allocator, mux, config);
        try client.start();
    }
    my_ev_run(loop);

    std.debug.print("\n=== BENCHMARK STATS ===\n", .{});
    stats.global_stats.dump();
    global_stack.deinit();
    if (global_mux) |m| m.deinit();
}

fn parseArgs(args: []const []const u8) !Config {
    if (args.len < 4) std.process.exit(1);
    const interface = args[1];
    var parts = std.mem.split(u8, args[2], "/");
    const local_ip = try parseIp(parts.first());
    var mode: ?Mode = null;
    var target_ip: ?[4]u8 = null;
    var port: u16 = 5201;
    var max_conns: ?u32 = null;
    var concurrency: u32 = 1;
    var duration: ?u64 = null;
    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-s")) {
            mode = .server;
        } else if (std.mem.eql(u8, args[i], "-c")) {
            mode = .client;
            i += 1;
            target_ip = try parseIp(args[i]);
        } else if (std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-n")) {
            i += 1;
            max_conns = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-C")) {
            i += 1;
            concurrency = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-t")) {
            i += 1;
            duration = try std.fmt.parseInt(u64, args[i], 10);
        }
    }
    return .{ .mode = mode.?, .port = port, .local_ip = local_ip, .target_ip = target_ip, .interface = interface, .max_conns = max_conns, .concurrency = concurrency, .duration = duration };
}

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

var global_loop: ?*anyopaque = null;
var global_mark_done: bool = false;
var global_done_time: i64 = 0;
var last_tick_time: i64 = 0;
var global_client: ?*PingClient = null;

fn libev_af_packet_cb(_: ?*anyopaque, _: *c.ev_io, _: i32) callconv(.C) void {
    var budget: usize = 1024;
    while (budget > 0) : (budget -= 1) {
        const ok = global_af_packet.readPacket() catch return;
        if (!ok) break;
    }
    global_stack.flush();
}

fn libev_timer_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    const now = std.time.milliTimestamp();
    if (last_tick_time == 0) last_tick_time = now;
    const diff = now - last_tick_time;
    if (diff > 0) {
        _ = global_stack.timer_queue.tickTo(global_stack.timer_queue.current_tick + @as(u64, @intCast(diff)));
        last_tick_time = now;
        perform_cleanup();
        if (global_client) |client| client.refill();
    }
    if (global_mark_done and (std.time.milliTimestamp() - global_done_time >= 1000)) {
        if (global_loop) |l| my_ev_break(l, 2);
    }
    global_stack.flush();
}

fn libev_mux_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    if (global_mux) |mux| {
        const ready = mux.pollReady() catch return;
        for (ready) |entry| socket.Socket.dispatch(entry);
    }
    perform_cleanup();
    global_stack.flush();
}

const PingServer = struct {
    sock: *socket.Socket,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    conn_count: u32 = 0,
    active_conns: u32 = 0,
    start_time: i64 = 0,
    last_report_time: i64 = 0,
    last_conn_count: u32 = 0,
    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, config: Config) !*PingServer {
        const self = try allocator.create(PingServer);
        const sock_obj = try socket.Socket.create(s, .inet, .stream, .tcp);
        try sock_obj.setOption(.{ .ts_enabled = true });
        try sock_obj.bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = config.port });
        try sock_obj.listen(1024);
        self.* = .{ .sock = sock_obj, .allocator = allocator, .mux = mux, .config = config, .last_report_time = std.time.milliTimestamp() };
        sock_obj.setHandler(mux, self, onEvent);
        return self;
    }
    fn onEvent(ctx: ?*anyopaque, sock_obj: *socket.Socket, events: waiter.EventMask) void {
        const self = @as(*PingServer, @ptrCast(@alignCast(ctx.?)));
        if (events & waiter.EventIn != 0) {
            while (true) {
                const accepted = sock_obj.accept() catch |err| {
                    if (err == tcpip.Error.WouldBlock) return;
                    return;
                };
                if (self.conn_count == 0) self.start_time = std.time.milliTimestamp();
                self.conn_count += 1;
                self.active_conns += 1;
                const now = std.time.milliTimestamp();
                if (now - self.last_report_time >= 1000) {
                    const diff_conns = self.conn_count - self.last_conn_count;
                    const diff_time_s = @as(f64, @floatFromInt(now - self.last_report_time)) / 1000.0;
                    std.debug.print("CPS: {d:.0}\n", .{@as(f64, @floatFromInt(diff_conns)) / diff_time_s});
                    self.last_report_time = now;
                    self.last_conn_count = self.conn_count;
                }
                const conn = PingConnection.fromSocket(self.allocator, accepted, self.mux, self.config, self, self.conn_count) catch {
                    accepted.deinit();
                    self.active_conns -= 1;
                    continue;
                };
                conn.onEvent(0);
            }
        }
    }
};

const PingClient = struct {
    stack_obj: *stack.Stack,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    next_conn_id: u32 = 1,
    active_conns: u32 = 0,
    start_time: i64 = 0,
    last_report_time: i64 = 0,
    last_report_count: u32 = 0,
    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, config: Config) !*PingClient {
        const self = try allocator.create(PingClient);
        self.* = .{ .stack_obj = s, .allocator = allocator, .mux = mux, .config = config };
        global_client = self;
        return self;
    }
    pub fn start(self: *PingClient) !void {
        self.start_time = std.time.milliTimestamp();
        self.last_report_time = self.start_time;
        const total = self.config.max_conns orelse 1000000;
        var i: u32 = 0;
        while (i < self.config.concurrency and i < total) : (i += 1) try self.startConnection();
    }
    pub fn startConnection(self: *PingClient) !void {
        const id = self.next_conn_id;
        self.next_conn_id += 1;
        self.active_conns += 1;
        const sock_obj = socket.Socket.create(self.stack_obj, .inet, .stream, .tcp) catch {
            self.active_conns -= 1;
            return;
        };
        try sock_obj.setOption(.{ .ts_enabled = true });
        const conn = try PingConnection.fromSocket(self.allocator, sock_obj, self.mux, self.config, self, id);
        try sock_obj.bind(.{ .nic = 0, .addr = .{ .v4 = self.config.local_ip }, .port = 0 });
        _ = sock_obj.connect(.{ .nic = 1, .addr = .{ .v4 = self.config.target_ip.? }, .port = self.config.port }) catch |err| {
            if (err != tcpip.Error.WouldBlock) return err;
        };
        conn.onEvent(0);
    }
    pub fn refill(self: *PingClient) void {
        const total = self.config.max_conns orelse 1000000;
        if (self.next_conn_id <= total) {
            while (self.active_conns < self.config.concurrency) {
                self.startConnection() catch break;
                if (self.next_conn_id > total) break;
            }
        } else if (self.active_conns == 0 and !global_mark_done) {
            const now = std.time.milliTimestamp();
            const total_completed = self.next_conn_id - 1;
            const duration_s = @as(f64, @floatFromInt(now - self.start_time)) / 1000.0;
            std.debug.print("Benchmark finished: {d} connections, CPS: {d:.0}\n", .{ total_completed, @as(f64, @floatFromInt(total_completed)) / duration_s });
            global_mark_done = true;
            global_done_time = now;
        }
    }
    pub fn onConnectionFinished(self: *PingClient) void {
        self.active_conns -= 1;
        const now = std.time.milliTimestamp();
        if (now - self.last_report_time >= 1000) {
            const completed = self.next_conn_id - self.active_conns - 1;
            const diff_conns = completed - self.last_report_count;
            const diff_time_s = @as(f64, @floatFromInt(now - self.last_report_time)) / 1000.0;
            std.debug.print("[ID: C] CPS: {d:.0} ActiveEP: {}\n", .{ @as(f64, @floatFromInt(diff_conns)) / diff_time_s, stats.global_stats.tcp.active_endpoints });
            self.last_report_time = now;
            self.last_report_count = completed;
        }
        self.refill();
    }
};

const PingConnection = struct {
    sock: *socket.Socket,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    parent: *anyopaque,
    connection_id: u32,
    closed: bool = false,
    pending_cleanup: bool = false,
    sent: bool = false,
    next_cleanup: ?*PingConnection = null,
    pub fn fromSocket(allocator: std.mem.Allocator, sock: *socket.Socket, mux: *EventMultiplexer, config: Config, parent: *anyopaque, id: u32) !*PingConnection {
        const self = try allocator.create(PingConnection);
        self.* = .{ .sock = sock, .allocator = allocator, .mux = mux, .config = config, .parent = parent, .connection_id = id };
        sock.setHandler(mux, self, onSocketEvent);
        return self;
    }
    fn onSocketEvent(ctx: ?*anyopaque, _: *socket.Socket, events: waiter.EventMask) void {
        const self = @as(*PingConnection, @ptrCast(@alignCast(ctx.?)));
        self.onEvent(events);
    }
    fn onEvent(self: *PingConnection, _: waiter.EventMask) void {
        if (self.closed or self.pending_cleanup) return;
        const current_events = self.sock.wait_queue.events();
        if (current_events & (waiter.EventHUp | waiter.EventErr) != 0) {
            self.close();
            return;
        }
        if (self.config.mode == .client) {
            if (current_events & waiter.EventOut != 0 and !self.sent) {
                const tcp_ep = @as(*ustack.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.sock.endpoint.ptr)));
                if (tcp_ep.state == .established) {
                    _ = self.sock.write("ping") catch return;
                    self.sent = true;
                }
            }
            if (current_events & waiter.EventIn != 0) {
                var buf: [16]u8 = undefined;
                while (true) {
                    const n = self.sock.read(&buf) catch |err| {
                        if (err == tcpip.Error.WouldBlock) break;
                        self.close();
                        return;
                    };
                    if (n == 0) {
                        self.close();
                        return;
                    }
                    if (self.sent and std.mem.eql(u8, buf[0..n], "pong")) {
                        self.close();
                        return;
                    }
                }
            }
        } else {
            if (current_events & waiter.EventIn != 0) {
                var buf: [16]u8 = undefined;
                while (true) {
                    const n = self.sock.read(&buf) catch |err| {
                        if (err == tcpip.Error.WouldBlock) break;
                        self.close();
                        return;
                    };
                    if (n > 0) {
                        if (std.mem.eql(u8, buf[0..n], "ping")) _ = self.sock.write("pong") catch {};
                    } else {
                        self.close();
                        return;
                    }
                }
            }
        }
    }
    fn close(self: *PingConnection) void {
        if (self.closed) return;
        self.closed = true;
        self.pending_cleanup = true;
        self.sock.close();
        if (self.config.mode == .client) {
            @as(*PingClient, @ptrCast(@alignCast(self.parent))).onConnectionFinished();
        } else {
            @as(*PingServer, @ptrCast(@alignCast(self.parent))).active_conns -= 1;
        }
        self.next_cleanup = global_cleanup_list;
        global_cleanup_list = self;
    }
};

var global_cleanup_list: ?*PingConnection = null;
fn perform_cleanup() void {
    var current = global_cleanup_list;
    global_cleanup_list = null;
    while (current) |conn| {
        const next = conn.next_cleanup;
        conn.sock.deinit();
        conn.allocator.destroy(conn);
        current = next;
    }
}
