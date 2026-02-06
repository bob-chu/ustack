const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const header = ustack.header;
const AfPacket = ustack.drivers.af_packet.AfPacket;
const EventMultiplexer = ustack.event_mux.EventMultiplexer;
const stats = @import("ustack").stats;

const c = @cImport({
    @cInclude("ev.h");
    @cInclude("stdio.h");
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

const MuxContext = union(enum) {
    server: *PingServer,
    connection: *PingConnection,
};

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config = try parseArgs(args);

    global_stack = try ustack.init(allocator);
    global_stack.tcp_msl = 100; // Set MSL to 100ms for benchmark recycling
    global_af_packet = try AfPacket.init(allocator, &global_stack.cluster_pool, config.interface);

    global_eth = ustack.link.eth.EthernetEndpoint.init(global_af_packet.linkEndpoint(), global_af_packet.address);
    global_eth.linkEndpoint().setMTU(config.mtu);
    try global_stack.createNIC(1, global_eth.linkEndpoint());

    const nic = global_stack.nics.get(1).?;
    try nic.addAddress(.{
        .protocol = 0x0806,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
    });
    try nic.addAddress(.{
        .protocol = 0x0800,
        .address_with_prefix = .{ .address = .{ .v4 = config.local_ip }, .prefix_len = 24 },
    });

    try global_stack.addRoute(.{
        .destination = .{ .address = .{ .v4 = config.local_ip }, .prefix = 24 },
        .gateway = .{ .v4 = .{ 0, 0, 0, 0 } },
        .nic = 1,
        .mtu = config.mtu,
    });
    try global_stack.addRoute(.{
        .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
        .gateway = .{ .v4 = .{ 0, 0, 0, 0 } },
        .nic = 1,
        .mtu = config.mtu,
    });

    const loop = my_ev_default_loop();
    global_loop = loop;

    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_af_packet.fd, c.EV_READ);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.001, 0.001);
    my_ev_timer_start(loop, &timer_watcher);

    const mux = try EventMultiplexer.init(allocator);
    global_mux = mux;
    var mux_io = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), c.EV_READ);
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
    stats.dumpLinkStats(&stats.global_link_stats);

    global_stack.deinit();
    if (global_mux) |m| m.deinit();
}

fn parseArgs(args: []const []const u8) !Config {
    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <ip/prefix> -s|-c <target_ip> [-p port]\n", .{args[0]});
        std.process.exit(1);
    }

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
            if (i >= args.len) return error.MissingTargetIp;
            target_ip = try parseIp(args[i]);
        } else if (std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            if (i >= args.len) return error.MissingPort;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-n")) {
            i += 1;
            if (i >= args.len) return error.MissingMaxConns;
            max_conns = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-C")) {
            i += 1;
            if (i >= args.len) return error.MissingConcurrency;
            concurrency = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-t")) {
            i += 1;
            if (i >= args.len) return error.MissingDuration;
            duration = try std.fmt.parseInt(u64, args[i], 10);
        }
    }

    if (mode == null) return error.MissingMode;
    if (mode == .client and target_ip == null) return error.MissingTargetIp;

    return .{
        .mode = mode.?,
        .port = port,
        .local_ip = local_ip,
        .target_ip = target_ip,
        .interface = interface,
        .max_conns = max_conns,
        .concurrency = concurrency,
        .duration = duration,
    };
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
extern fn my_ev_break(loop: ?*anyopaque) void;

var global_loop: ?*anyopaque = null;
var global_mark_done: bool = false;
var global_done_time: i64 = 0;
var global_start_time: i64 = 0;
var last_tick_time: i64 = 0;
var global_client: ?*PingClient = null;

fn libev_af_packet_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    var budget: usize = 1024;
    while (budget > 0) : (budget -= 1) {
        const ok = global_af_packet.readPacket() catch {
            return;
        };
        if (!ok) break;
    }
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
        if (global_client) |client| {
            client.refill();
        }
    }

    if (global_mark_done) {
        if (std.time.milliTimestamp() - global_done_time >= 1000) {
            if (global_loop) |l| my_ev_break(l);
        }
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
                .server => |s| s.onEvent(),
                .connection => |conn| conn.onEvent(),
            }
        }
    }
}

const PingServer = struct {
    listener: ustack.tcpip.Endpoint,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    conn_count: u32 = 0,
    active_conns: u32 = 0,
    start_time: i64 = 0,
    end_time: i64 = 0,
    last_report_time: i64 = 0,
    last_conn_count: u32 = 0,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, config: Config) !*PingServer {
        const self = try allocator.create(PingServer);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};

        const ep = try s.transport_protocols.get(6).?.newEndpoint(s, 0x0800, wq);
        try ep.setOption(.{ .ts_enabled = true });
        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = config.port });
        try ep.listen(1024);

        self.* = .{
            .listener = ep,
            .allocator = allocator,
            .mux = mux,
            .config = config,
            .mux_ctx = .{ .server = self },
            .wait_entry = undefined,
            .last_report_time = std.time.milliTimestamp(),
        };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn);

        return self;
    }

    fn onEvent(self: *PingServer) void {
        while (true) {
            const res = self.listener.accept() catch |err| {
                if (err == tcpip.Error.WouldBlock) return;
                return;
            };
            if (self.conn_count == 0) {
                self.start_time = std.time.milliTimestamp();
            }
            self.conn_count += 1;
            self.active_conns += 1;

            const now = std.time.milliTimestamp();
            if (now - self.last_report_time >= 1000) {
                const diff_conns = self.conn_count - self.last_conn_count;
                const diff_time_s = @as(f64, @floatFromInt(now - self.last_report_time)) / 1000.0;
                const current_cps = @as(f64, @floatFromInt(diff_conns)) / diff_time_s;
                std.debug.print("CPS: {d:.0}\n", .{current_cps});
                self.last_report_time = now;
                self.last_conn_count = self.conn_count;
            }

            const conn = PingConnection.init(self.allocator, res.ep, res.wq, self.mux, self.config, self, self.conn_count) catch {
                res.ep.close();
                self.active_conns -= 1;
                continue;
            };
            conn.onEvent();
        }
    }
};

const PingClient = struct {
    stack: *stack.Stack,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    next_conn_id: u32 = 1,
    active_conns: u32 = 0,
    start_time: i64 = 0,
    end_time: i64 = 0,
    last_report_time: i64 = 0,
    last_report_count: u32 = 0,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, config: Config) !*PingClient {
        const self = try allocator.create(PingClient);
        self.* = .{
            .stack = s,
            .allocator = allocator,
            .mux = mux,
            .config = config,
            .active_conns = 0,
        };
        global_client = self;
        return self;
    }

    pub fn start(self: *PingClient) !void {
        self.start_time = std.time.milliTimestamp();
        global_start_time = self.start_time;
        self.last_report_time = self.start_time;
        const total = self.config.max_conns orelse 1000000;
        const concurrency = self.config.concurrency;
        var i: u32 = 0;
        while (i < concurrency and i < total) : (i += 1) {
            try self.startConnection();
        }
    }

    pub fn startConnection(self: *PingClient) !void {
        const id = self.next_conn_id;
        self.next_conn_id += 1;
        self.active_conns += 1;
        errdefer self.active_conns -= 1;

        const wq = try self.allocator.create(waiter.Queue);
        errdefer self.allocator.destroy(wq);
        wq.* = .{};
        const ep = try self.stack.transport_protocols.get(6).?.newEndpoint(self.stack, 0x0800, wq);
        errdefer ep.close();
        try ep.setOption(.{ .ts_enabled = true });

        const conn = try PingConnection.init(self.allocator, ep, wq, self.mux, self.config, self, id);

        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = self.config.local_ip }, .port = 0 });
        _ = ep.connect(.{ .nic = 1, .addr = .{ .v4 = self.config.target_ip.? }, .port = self.config.port }) catch |err| {
            if (err != tcpip.Error.WouldBlock) return err;
        };

        conn.onEvent();
    }

    pub fn refill(self: *PingClient) void {
        const now = std.time.milliTimestamp();
        const total = self.config.max_conns orelse 1000000;

        var reached_limit = false;
        if (self.next_conn_id > total) reached_limit = true;
        if (self.config.duration) |d| {
            if (now - self.start_time >= d * 1000) {
                // std.debug.print("Duration reached: {} >= {}\n", .{now - self.start_time, d * 1000});
                reached_limit = true;
            }
        }

        if (!reached_limit) {
            while (self.active_conns < self.config.concurrency) {
                self.startConnection() catch |err| {
                    if (err == tcpip.Error.AddressInUse) return;
                    std.debug.print("startConnection error: {}\n", .{err});
                    return;
                };

                if (self.next_conn_id > total) break;
            }
        } else if (self.active_conns == 0 and !global_mark_done) {
            self.end_time = now;
            const duration_ms = @as(f64, @floatFromInt(self.end_time - self.start_time));
            const duration_s = duration_ms / 1000.0;
            const total_completed = self.next_conn_id - self.active_conns - 1;
            const cps = @as(f64, @floatFromInt(total_completed)) / duration_s;

            std.debug.print("Benchmark finished: {d} connections, CPS: {d:.0}\n", .{ total_completed, cps });

            global_mark_done = true;
            global_done_time = now;
        }
    }

    pub fn onConnectionFinished(self: *PingClient) void {
        self.active_conns -= 1;
        const now = std.time.milliTimestamp();

        // Advance stack timers frequently
        if (now - last_tick_time > 0) {
            _ = global_stack.timer_queue.tickTo(global_stack.timer_queue.current_tick + @as(u64, @intCast(now - last_tick_time)));
            last_tick_time = now;
            perform_cleanup();
        }

        // Report CPS every second
        if (now - self.last_report_time >= 1000) {
            const completed = self.next_conn_id - self.active_conns - 1;
            const diff_conns = completed - self.last_report_count;
            const diff_time_s = @as(f64, @floatFromInt(now - self.last_report_time)) / 1000.0;
            const current_cps = @as(f64, @floatFromInt(diff_conns)) / diff_time_s;
            const total_sec = @as(f64, @floatFromInt(now - self.start_time)) / 1000.0;

            std.debug.print("[ID: C] {d: >5.2}-{d: >5.2} sec  CPS: {d:.0}  ActiveEP: {}\n", .{ total_sec - diff_time_s, total_sec, current_cps, stats.global_stats.tcp.active_endpoints });

            self.last_report_time = now;
            self.last_report_count = completed;
        }

        self.refill();
    }
};

const PingConnection = struct {
    ep: ustack.tcpip.Endpoint,
    wq: *waiter.Queue,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    parent: *anyopaque,
    connection_id: u32,
    closed: bool = false,
    pending_cleanup: bool = false,
    owns_wq: bool = false,
    sent: bool = false,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    next_cleanup: ?*PingConnection = null,

    pub fn init(allocator: std.mem.Allocator, ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer, config: Config, parent: *anyopaque, id: u32) !*PingConnection {
        const self = try allocator.create(PingConnection);
        self.* = .{
            .ep = ep,
            .wq = wq,
            .allocator = allocator,
            .mux = mux,
            .config = config,
            .parent = parent,
            .connection_id = id,
            .mux_ctx = .{ .connection = self },
            .wait_entry = undefined,
            .owns_wq = config.mode == .client,
        };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventHUp | waiter.EventErr);

        return self;
    }

    fn onEvent(self: *PingConnection) void {
        if (self.closed or self.pending_cleanup) return;

        const events = self.wq.events();

        if (events & waiter.EventHUp != 0) {
            self.close();
            return;
        }

        if (events & waiter.EventErr != 0) {
            self.close();
            return;
        }

        const tcp_ep = @as(*ustack.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.ep.ptr)));

        if (self.config.mode == .client) {
            self.handleClient(tcp_ep);
        } else {
            self.handleServer();
        }
    }

    fn handleClient(self: *PingConnection, tcp_ep: *ustack.transport.tcp.TCPEndpoint) void {
        if (tcp_ep.state == .established and !self.sent) {
            var p = SimplePayload{ .data = "ping" };
            _ = self.ep.write(p.payloader(), .{}) catch return;
            self.sent = true;
        }

        var buf = self.ep.read(null) catch |err| {
            if (err == tcpip.Error.WouldBlock) return;
            self.close();
            return;
        };

        if (buf.size == 0) {
            buf.deinit();
            self.close();
            return;
        }

        defer buf.deinit();

        if (self.sent) {
            const view = buf.toView(self.allocator) catch return;
            defer self.allocator.free(view);
            if (std.mem.eql(u8, view, "pong")) {
                _ = self.ep.shutdown(0) catch {}; // Shutdown write side
            }
        }
    }

    fn handleServer(self: *PingConnection) void {
        var buf = self.ep.read(null) catch |err| {
            if (err == tcpip.Error.WouldBlock) return;
            self.close();
            return;
        };
        defer buf.deinit();

        if (buf.size > 0) {
            const view = buf.toView(self.allocator) catch return;
            defer self.allocator.free(view);
            if (std.mem.eql(u8, view, "ping")) {
                var p = SimplePayload{ .data = "pong" };
                _ = self.ep.write(p.payloader(), .{}) catch {};
            }
        } else {
            self.close();
        }
    }

    fn close(self: *PingConnection) void {
        if (self.closed) return;
        self.closed = true;
        self.pending_cleanup = true;

        self.wq.eventUnregister(&self.wait_entry);
        self.ep.close();

        if (self.config.mode == .client) {
            const client = @as(*PingClient, @ptrCast(@alignCast(self.parent)));
            client.onConnectionFinished();
        } else {
            const server = @as(*PingServer, @ptrCast(@alignCast(self.parent)));
            server.active_conns -= 1;

            var done = false;
            if (server.config.max_conns) |max| {
                if (server.conn_count >= max and server.active_conns == 0) done = true;
            }
            if (server.config.duration) |d| {
                if (std.time.milliTimestamp() - server.start_time >= d * 1000 and server.active_conns == 0) done = true;
            }

            if (done) {
                server.end_time = std.time.milliTimestamp();
                const duration_ms = @as(f64, @floatFromInt(server.end_time - server.start_time));
                const duration_s = duration_ms / 1000.0;
                const cps = @as(f64, @floatFromInt(server.conn_count)) / duration_s;

                std.debug.print("Benchmark finished: {d} connections, CPS: {d:.0}\n", .{ server.conn_count, cps });

                global_mark_done = true;
                global_done_time = std.time.milliTimestamp();
            }
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
        const allocator = conn.allocator;
        if (conn.owns_wq) {
            allocator.destroy(conn.wq);
        }
        allocator.destroy(conn);
        current = next;
    }
}

const SimplePayload = struct {
    data: []const u8,

    pub fn payloader(self: *const SimplePayload) tcpip.Payloader {
        return .{
            .ptr = @constCast(self),
            .vtable = &.{
                .fullPayload = fullPayload,
                .viewPayload = null,
            },
        };
    }

    fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
        const self = @as(*const SimplePayload, @ptrCast(@alignCast(ptr)));
        return self.data;
    }
};
