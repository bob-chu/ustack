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
var global_connections: std.ArrayList(*Connection) = undefined;
var global_config: Config = .{};
var global_finish: bool = false;

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

    global_epfd = try posix.uepoll_create(1024);
    global_connections = std.ArrayList(*Connection).init(allocator);

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

    // For now, let's just use a timer or poll in every loop tick.
    // Or better: libev_timer_cb already runs every 1ms. We can check epoll there.

    // In server mode:
    var server_fd: i32 = -1;
    if (std.mem.eql(u8, mode, "server")) {
        std.debug.print("Starting server on port {}...\n", .{global_config.port});
        const is_udp = global_config.protocol == .udp;
        server_fd = try posix.socket_fd(&global_stack, std.posix.AF.INET, if (is_udp) std.posix.SOCK.DGRAM else std.posix.SOCK.STREAM, 0);
        std.debug.print("Created server socket fd={}\n", .{server_fd});

        const addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, global_config.port),
            .addr = 0,
            .zero = [_]u8{0} ** 8,
        };
        try posix.bind_fd(server_fd, @as(std.posix.sockaddr, @bitCast(addr)), @sizeOf(std.posix.sockaddr.in));
        if (!is_udp) try posix.listen_fd(server_fd, 128);
        std.debug.print("Listening on port {}\n", .{global_config.port});

        if (is_udp) {
            const conn = try Connection.init(allocator, server_fd, false);
            const ctx = try allocator.create(EpollContext);
            ctx.* = .{ .connection = conn };
            var ev = posix.uepoll_event{
                .events = posix.POLLIN,
                .data = .{ .ptr = @intFromPtr(ctx) },
            };
            try posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_ADD, server_fd, &ev);
        } else {
            const s_ctx = try allocator.create(EpollContext);
            s_ctx.* = .{ .server = server_fd };
            var ev = posix.uepoll_event{
                .events = posix.POLLIN,
                .data = .{ .ptr = @intFromPtr(s_ctx) },
            };
            try posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_ADD, server_fd, &ev);
        }
    } else {
        std.debug.print("Starting client connecting to {}.{}.{}.{}...\n", .{ global_config.target_ip.?[0], global_config.target_ip.?[1], global_config.target_ip.?[2], global_config.target_ip.?[3] });
        _ = try Connection.initClient(&global_stack, allocator, global_config.target_ip.?, global_config.local_ip);
    }

    std.debug.print("Entering event loop...\n", .{});
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
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_af_packet.readPacket() catch {};
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

    if (global_config.protocol == .udp and std.mem.eql(u8, global_config.mode, "client")) {
        for (global_connections.items) |conn| {
            if (conn.is_client and !conn.closed) {
                conn.onEvent(posix.POLLOUT);
            }
        }
    }
}

const EpollContext = union(enum) {
    server: i32,
    connection: *Connection,
};

fn process_epoll() void {
    var events: [64]posix.uepoll_event = undefined;
    while (true) {
        const n = posix.uepoll_wait(global_epfd, &events, 0) catch break;
        if (n == 0) break;
        for (events[0..n]) |ev| {
            const ctx = @as(*EpollContext, @ptrFromInt(ev.data.ptr));
            switch (ctx.*) {
                .server => |fd| handle_server_event(fd, @intCast(ev.events)),
                .connection => |conn| conn.onEvent(@intCast(ev.events)),
            }
        }
    }
}

fn handle_server_event(fd: i32, mask: i16) void {
    if (mask & posix.POLLIN != 0) {
        if (global_config.protocol == .tcp) {
            while (true) {
                const accepted_fd = posix.accept_fd(fd, null, null) catch |err| {
                    if (err != error.WouldBlock) std.debug.print("Accept error: {}\n", .{err});
                    break;
                };
                std.debug.print("Accepted new connection: fd={}\n", .{accepted_fd});

                const ft = posix.getGlobalFileTable(std.heap.c_allocator);
                const file = ft.get(accepted_fd).?;
                file.socket.setOption(.{ .congestion_control = global_config.cc_alg }) catch {};

                const conn = Connection.init(std.heap.c_allocator, accepted_fd, false) catch continue;

                // Reuse conn pointer for epoll context
                const ctx = std.heap.c_allocator.create(EpollContext) catch continue;
                ctx.* = .{ .connection = conn };

                var ev = posix.uepoll_event{
                    .events = posix.POLLIN | posix.POLLOUT,
                    .data = .{ .ptr = @intFromPtr(ctx) },
                };
                posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_ADD, accepted_fd, &ev) catch |err| {
                    std.debug.print("Epoll ctl error for accepted fd: {}\n", .{err});
                };
            }
        }
    }
}

fn libev_stats_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = watcher;
    _ = revents;
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
                global_finish = true;
                my_ev_break(loop, 2);
                return;
            }
        }
    }

    if (total_rx_bytes > 0) {
        const mbps = (@as(f64, @floatFromInt(total_rx_bytes)) * 8.0) / 1000000.0;
        std.debug.print("[RX ] 1.00 sec {d: >7.2} Mbits/sec\n", .{mbps});
    }
    if (total_tx_bytes > 0) {
        const mbps = (@as(f64, @floatFromInt(total_tx_bytes)) * 8.0) / 1000000.0;
        std.debug.print("[TX ] 1.00 sec {d: >7.2} Mbits/sec\n", .{mbps});
    }
}

fn noopConsumption(_: ?*anyopaque, _: usize) void {}

const Connection = struct {
    fd: i32,
    allocator: std.mem.Allocator,
    is_client: bool,
    closed: bool = false,
    start_time: i64 = 0,
    first_packet_time: i64 = 0,
    end_time: i64 = 0,
    bytes_rx: u64 = 0,
    bytes_tx: u64 = 0,
    bytes_since_last_report: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, fd: i32, is_client: bool) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{
            .fd = fd,
            .allocator = allocator,
            .is_client = is_client,
            .start_time = std.time.milliTimestamp(),
            .first_packet_time = 0,
            .end_time = 0,
            .bytes_rx = 0,
            .bytes_tx = 0,
            .bytes_since_last_report = 0,
        };
        try global_connections.append(self);
        return self;
    }

    pub fn initClient(s: *stack.Stack, allocator: std.mem.Allocator, target: [4]u8, local: [4]u8) !*Connection {
        const is_udp = global_config.protocol == .udp;
        const fd = try posix.socket_fd(s, std.posix.AF.INET, if (is_udp) std.posix.SOCK.DGRAM else std.posix.SOCK.STREAM, 0);

        if (!is_udp) {
            const ft = posix.getGlobalFileTable(allocator);
            const file = ft.get(fd).?;
            file.socket.setOption(.{ .congestion_control = global_config.cc_alg }) catch {};
        }

        const self = try Connection.init(allocator, fd, true);

        const laddr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = 0,
            .addr = @bitCast(local),
            .zero = [_]u8{0} ** 8,
        };
        try posix.bind_fd(fd, @as(std.posix.sockaddr, @bitCast(laddr)), @sizeOf(std.posix.sockaddr.in));

        const raddr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, global_config.port),
            .addr = @bitCast(target),
            .zero = [_]u8{0} ** 8,
        };
        _ = posix.connect_fd(fd, @as(std.posix.sockaddr, @bitCast(raddr)), @sizeOf(std.posix.sockaddr.in)) catch |err| {
            if (err != error.WouldBlock) return err;
        };

        const ctx = try allocator.create(EpollContext);
        ctx.* = .{ .connection = self };
        var ev = posix.uepoll_event{
            .events = posix.POLLIN | posix.POLLOUT,
            .data = .{ .ptr = @intFromPtr(ctx) },
        };
        try posix.uepoll_ctl(global_epfd, std.os.linux.EPOLL.CTL_ADD, fd, &ev);

        return self;
    }

    fn onEvent(self: *Connection, mask: i16) void {
        if (self.closed) return;
        if (mask & (posix.POLLHUP | posix.POLLERR) != 0) {
            self.close();
            return;
        }

        // Handle RX
        if (mask & posix.POLLIN != 0) {
            var buf: [65536]u8 = undefined;
            while (true) {
                const n = posix.recv_fd(self.fd, &buf, 0) catch |err| {
                    if (err == error.WouldBlock) break;
                    self.close();
                    return;
                };
                if (self.first_packet_time == 0) self.first_packet_time = std.time.milliTimestamp();
                if (n == 0) {
                    if (global_config.protocol == .tcp) self.close();
                    break;
                }
                self.bytes_rx += n;
                self.bytes_since_last_report += n;
            }
        }

        // Handle TX
        if (self.is_client and (mask & posix.POLLOUT != 0)) {
            if (self.first_packet_time == 0) self.first_packet_time = std.time.milliTimestamp();
            const slen = if (global_config.packet_size > 0) global_config.packet_size else if (global_config.protocol == .udp) @as(usize, @intCast(global_config.mtu - 28)) else 65536;
            var budget: usize = 50000;
            const sl = @min(slen, 65536);
            while (budget > 0) : (budget -= 1) {
                const n = if (global_config.protocol == .tcp)
                    posix.usend_zc_fd(self.fd, StaticBuffer.buf[0..sl], .{ .ptr = self, .run = noopConsumption }) catch |err| {
                        if (err == error.WouldBlock) return;
                        self.close();
                        return;
                    }
                else
                    posix.send_fd(self.fd, StaticBuffer.buf[0..sl], 0) catch |err| {
                        if (err == error.WouldBlock) return;
                        self.close();
                        return;
                    };
                if (n == 0) return;
                self.bytes_tx += n;
                self.bytes_since_last_report += n;
            }
        }
    }

    fn close(self: *Connection) void {
        if (self.closed) return;
        self.closed = true;

        // Find and free the EpollContext associated with this connection
        // Since we don't store it in Connection, we'd need to change that.
        // Let's change Connection to store its EpollContext.

        posix.close_fd(self.fd);
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
extern fn my_ev_run_once(loop: ?*anyopaque) void;
extern fn my_ev_break(loop: ?*anyopaque, how: i32) void;
