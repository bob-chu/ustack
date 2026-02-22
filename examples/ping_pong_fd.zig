const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const AfPacket = ustack.drivers.af_packet.AfPacket;
const posix = ustack.posix;

const c = @cImport({
    @cInclude("ev.h");
});

var global_stack: stack.Stack = undefined;
var global_af_packet: AfPacket = undefined;
var global_eth: ustack.link.eth.EthernetEndpoint = undefined;
var global_epfd: i32 = -1;
var global_finish: bool = false;
var global_allocator: std.mem.Allocator = undefined;

const Config = struct {
    mode: []const u8 = "server",
    port: u16 = 5201,
    target_ip: ?[4]u8 = null,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    interface: []const u8 = "",
    duration: ?u64 = null,
    concurrency: u32 = 1,
    max_conns: ?u32 = null,
};

var global_config = Config{};
var global_conn_count: u32 = 0;
var global_active_conns: u32 = 0;
var global_start_time: i64 = 0;
var global_last_report_time: i64 = 0;
var global_last_conn_count: u32 = 0;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    global_allocator = gpa.allocator();
    const allocator = global_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <mode> <local_ip/prefix> [target_ip] [options]\n", .{args[0]});
        return;
    }

    const ifname = args[1];
    const mode = args[2];
    var parts = std.mem.split(u8, args[3], "/");
    const local_ip = try parseIp(parts.first());
    const prefix_len = try std.fmt.parseInt(u8, parts.next() orelse "24", 10);

    global_config.interface = ifname;
    global_config.mode = mode;
    global_config.local_ip = local_ip;

    var idx: usize = 4;
    if (std.mem.eql(u8, mode, "client")) {
        global_config.target_ip = try parseIp(args[4]);
        idx = 5;
    }

    while (idx < args.len) : (idx += 1) {
        if (std.mem.eql(u8, args[idx], "-C")) {
            idx += 1;
            global_config.concurrency = try std.fmt.parseInt(u32, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-n")) {
            idx += 1;
            global_config.max_conns = try std.fmt.parseInt(u32, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-t")) {
            idx += 1;
            global_config.duration = try std.fmt.parseInt(u64, args[idx], 10);
        }
    }

    global_stack = try ustack.init(allocator);
    defer global_stack.deinit();
    global_stack.tcp_msl = 100;

    global_af_packet = try AfPacket.init(allocator, &global_stack.cluster_pool, ifname);
    global_eth = ustack.link.eth.EthernetEndpoint.init(global_af_packet.linkEndpoint(), global_af_packet.address);
    try global_stack.createNIC(1, global_eth.linkEndpoint());

    const nic = global_stack.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0806, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = local_ip }, .prefix_len = prefix_len } });

    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = local_ip }, .prefix = prefix_len }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = 1500 });
    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = 1500 });

    global_epfd = try posix.uepoll_create(1024);

    const loop = my_ev_default_loop();

    var uepoll_watcher = std.mem.zeroInit(c.ev_io, .{});
    const uepoll_signal_fd = try posix.uepoll_get_fd(global_epfd);
    my_ev_io_init(&uepoll_watcher, libev_uepoll_cb, uepoll_signal_fd, 0x01);
    my_ev_io_start(loop, &uepoll_watcher);

    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_af_packet.fd, 0x01);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.001, 0.001);
    my_ev_timer_start(loop, &timer_watcher);

    var stats_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&stats_watcher, libev_stats_cb, 1.0, 1.0);
    my_ev_timer_start(loop, &stats_watcher);

    global_start_time = std.time.milliTimestamp();
    global_last_report_time = global_start_time;

    if (std.mem.eql(u8, global_config.mode, "server")) {
        const server_fd = try posix.socket_fd(&global_stack, std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
        const addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, global_config.port),
            .addr = 0,
            .zero = [_]u8{0} ** 8,
        };
        try posix.bind_fd(server_fd, @as(std.posix.sockaddr, @bitCast(addr)), @sizeOf(std.posix.sockaddr.in));
        try posix.listen_fd(server_fd, 8192);

        const sctx = try allocator.create(EpollContext);
        sctx.* = .{ .tag = .server, .ptr = .{ .server_fd = server_fd } };
        var ev = posix.uepoll_event{
            .events = posix.POLLIN,
            .data = .{ .ptr = @intFromPtr(sctx) },
        };
        try posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_ADD, server_fd, &ev);
        std.debug.print("Server listening on port {}...\n", .{global_config.port});
    } else {
        std.debug.print("Client connecting to {}.{}.{}.{}...\n", .{ global_config.target_ip.?[0], global_config.target_ip.?[1], global_config.target_ip.?[2], global_config.target_ip.?[3] });
        for (0..global_config.concurrency) |_| {
            try startClientConnection(loop, allocator);
        }
    }

    my_ev_run(loop);
}

fn startClientConnection(loop: ?*anyopaque, allocator: std.mem.Allocator) !void {
    if (global_finish) return;
    if (global_config.max_conns) |max| {
        if (global_conn_count >= max) {
            if (global_active_conns == 0) my_ev_break(loop, 2);
            return;
        }
    }

    const fd = try posix.socket_fd(&global_stack, std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    const conn = try Connection.init(allocator, fd, true);

    const addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, global_config.port),
        .addr = @bitCast(global_config.target_ip.?),
        .zero = [_]u8{0} ** 8,
    };

    _ = posix.bind_fd(fd, @bitCast(std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = 0,
        .addr = @bitCast(global_config.local_ip),
        .zero = [_]u8{0} ** 8,
    }), @sizeOf(std.posix.sockaddr.in)) catch {};

    _ = posix.connect_fd(fd, @as(std.posix.sockaddr, @bitCast(addr)), @sizeOf(std.posix.sockaddr.in)) catch |err| {
        if (err != error.WouldBlock) {
            std.debug.print("[C] Connection failed: {}\n", .{err});
            return err;
        }
    };

    var ev = posix.uepoll_event{
        .events = posix.POLLIN | posix.POLLOUT,
        .data = .{ .ptr = @intFromPtr(conn.ctx) },
    };
    try posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_ADD, fd, &ev);

    global_conn_count += 1;
    global_active_conns += 1;
}

const EpollContext = struct {
    tag: enum { server, connection },
    ptr: union {
        server_fd: i32,
        connection: *Connection,
    },
};

fn libev_af_packet_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    while (true) {
        const has_packet = global_af_packet.readPacket() catch false;
        if (!has_packet) break;
    }
    global_stack.flush();
    process_epoll();
}

fn libev_uepoll_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    process_epoll();
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
    process_epoll();
    perform_cleanup();
}

fn process_epoll() void {
    var events: [128]posix.uepoll_event = undefined;
    while (true) {
        const n = posix.uepoll_wait(global_epfd, &events, 0) catch break;
        if (n == 0) break;
        for (events[0..n]) |ev| {
            if (ev.data.ptr == 0) continue;
            const ctx = @as(*EpollContext, @ptrFromInt(ev.data.ptr));
            switch (ctx.tag) {
                .server => handle_server_event(ctx.ptr.server_fd, @intCast(ev.events)),
                .connection => ctx.ptr.connection.onEvent(@intCast(ev.events)),
            }
        }
    }
    global_stack.flush();
}

fn handle_server_event(fd: i32, mask: i16) void {
    if (mask & posix.POLLIN != 0) {
        while (true) {
            const client_fd = posix.accept_fd(fd, null, null) catch |err| {
                if (err == error.WouldBlock) break;
                return;
            };
            const conn = Connection.init(global_allocator, client_fd, false) catch {
                posix.close_fd(client_fd);
                continue;
            };
            std.debug.print("[S] Accepted connection, fd={}\n", .{client_fd});
            var ev = posix.uepoll_event{
                .events = posix.POLLIN,
                .data = .{ .ptr = @intFromPtr(conn.ctx) },
            };
            posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_ADD, client_fd, &ev) catch unreachable;
            global_conn_count += 1;
            global_active_conns += 1;
            conn.onEvent(posix.POLLIN);
        }
    }
}

const Connection = struct {
    fd: i32,
    allocator: std.mem.Allocator,
    is_client: bool,
    closed: bool = false,
    ping_sent: bool = false,
    pending_cleanup: bool = false,
    next_cleanup: ?*Connection = null,
    ctx: *EpollContext,

    fn init(allocator: std.mem.Allocator, fd: i32, is_client: bool) !*Connection {
        const self = try allocator.create(Connection);
        const ctx = try allocator.create(EpollContext);
        ctx.tag = .connection;
        ctx.ptr = .{ .connection = self };
        self.* = .{
            .fd = fd,
            .allocator = allocator,
            .is_client = is_client,
            .ctx = ctx,
        };
        return self;
    }

    fn onEvent(self: *Connection, mask: i16) void {
        if (self.closed or self.pending_cleanup) return;
        if (mask & (posix.POLLHUP | posix.POLLERR) != 0) {
            self.close();
            return;
        }
        if (self.is_client) {
            if (!self.ping_sent and (mask & posix.POLLOUT != 0)) {
                _ = posix.send_fd(self.fd, "ping", 0) catch {
                    self.close();
                    return;
                };
                self.ping_sent = true;
                var ev = posix.uepoll_event{ .events = posix.POLLIN, .data = .{ .ptr = @intFromPtr(self.ctx) } };
                posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_MOD, self.fd, &ev) catch {
                    self.close();
                    return;
                };
            }
            if (mask & posix.POLLIN != 0) {
                var buf: [16]u8 = undefined;
                const n = posix.recv_fd(self.fd, &buf, 0) catch |err| {
                    if (err == error.WouldBlock) return;
                    self.close();
                    return;
                };
                if (n > 0 and std.mem.eql(u8, buf[0..n], "pong")) {
                    self.close();
                } else if (n == 0) {
                    self.close();
                }
            }
        } else {
            if (mask & posix.POLLIN != 0) {
                var buf: [16]u8 = undefined;
                const n = posix.recv_fd(self.fd, &buf, 0) catch |err| {
                    if (err == error.WouldBlock) return;
                    self.close();
                    return;
                };
                if (n > 0 and std.mem.eql(u8, buf[0..n], "ping")) {
                    _ = posix.send_fd(self.fd, "pong", 0) catch {};
                } else if (n == 0) {
                    self.close();
                }
            }
        }
    }

    fn close(self: *Connection) void {
        if (self.closed) return;
        self.closed = true;
        self.pending_cleanup = true;
        posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_DEL, self.fd, null) catch {};
        posix.close_fd(self.fd);
        global_active_conns -= 1;

        self.next_cleanup = global_cleanup_list;
        global_cleanup_list = self;
    }
};

var global_cleanup_list: ?*Connection = null;
fn perform_cleanup() void {
    var current = global_cleanup_list;
    global_cleanup_list = null;
    while (current) |conn| {
        const next = conn.next_cleanup;
        if (conn.is_client) {
            startClientConnection(my_ev_default_loop(), conn.allocator) catch {};
        }
        conn.allocator.destroy(conn.ctx);
        conn.allocator.destroy(conn);
        current = next;
    }
}

fn libev_stats_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = watcher;
    _ = revents;
    const now = std.time.milliTimestamp();
    const diff_conns = global_conn_count - global_last_conn_count;
    const diff_time_s = @as(f64, @floatFromInt(now - global_last_report_time)) / 1000.0;
    if (diff_time_s == 0) return;
    const current_cps = @as(f64, @floatFromInt(diff_conns)) / diff_time_s;
    const total_s = @as(f64, @floatFromInt(now - global_start_time)) / 1000.0;
    std.debug.print("[{s}] {d:.1}s CPS: {d:.0} Active: {}\n", .{ if (std.mem.eql(u8, global_config.mode, "server")) @as([]const u8, "S") else "C", total_s, current_cps, global_active_conns });
    global_last_report_time = now;
    global_last_conn_count = global_conn_count;
    if (global_config.duration) |d| {
        if (total_s >= @as(f64, @floatFromInt(d))) {
            global_finish = true;
            if (global_active_conns == 0 or std.mem.eql(u8, global_config.mode, "server")) my_ev_break(loop, 2);
        }
    }
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
