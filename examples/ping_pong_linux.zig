const std = @import("std");

const c = @cImport({
    @cInclude("ev.h");
});

extern fn my_ev_default_loop() ?*anyopaque;
extern fn my_ev_io_init(w: *c.ev_io, cb: *const fn (?*anyopaque, *c.ev_io, i32) callconv(.C) void, fd: i32, events: i32) void;
extern fn my_ev_timer_init(w: *c.ev_timer, cb: *const fn (?*anyopaque, *c.ev_timer, i32) callconv(.C) void, after: f64, repeat: f64) void;
extern fn my_ev_io_start(loop: ?*anyopaque, w: *c.ev_io) void;
extern fn my_ev_timer_start(loop: ?*anyopaque, w: *c.ev_timer) void;
extern fn my_ev_io_stop(loop: ?*anyopaque, w: *c.ev_io) void;
extern fn my_ev_timer_stop(loop: ?*anyopaque, w: *c.ev_timer) void;
extern fn my_ev_run(loop: ?*anyopaque) void;
extern fn my_ev_break(loop: ?*anyopaque, how: i32) void;

const Config = struct {
    mode: []const u8 = "server",
    port: u16 = 5201,
    target_ip: ?[4]u8 = null,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    concurrency: u32 = 1,
    max_conns: ?u32 = null,
    duration: ?u64 = null,
};

var global_config = Config{};
var global_connections: std.ArrayList(*Connection) = undefined;
var global_conn_count: u32 = 0;
var global_active_conns: u32 = 0;
var global_start_time: i64 = 0;
var global_last_report_time: i64 = 0;
var global_last_conn_count: u32 = 0;
var global_mark_done: bool = false;

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface_ignored> <mode> <local_ip> [target_ip] [options]\n", .{args[0]});
        std.debug.print("  mode: server | client\n", .{});
        std.debug.print("  options:\n", .{});
        std.debug.print("    -C CONNS  Concurrency (default 1)\n", .{});
        std.debug.print("    -n TOTAL  Max total connections\n", .{});
        std.debug.print("    -t TIME   Duration in seconds\n", .{});
        return;
    }

    // interface is args[1], ignored here since we use standard sockets
    global_config.mode = args[2];
    global_config.local_ip = try parseIp(args[3]);

    var idx: usize = 4;
    if (std.mem.eql(u8, global_config.mode, "client")) {
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
        } else if (std.mem.eql(u8, args[idx], "-p")) {
            idx += 1;
            global_config.port = try std.fmt.parseInt(u16, args[idx], 10);
        }
    }

    global_connections = std.ArrayList(*Connection).init(allocator);
    const loop = my_ev_default_loop();

    var stats_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&stats_watcher, statsCb, 1.0, 1.0);
    my_ev_timer_start(loop, &stats_watcher);

    global_start_time = std.time.milliTimestamp();
    global_last_report_time = global_start_time;

    if (std.mem.eql(u8, global_config.mode, "server")) {
        const sockfd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, 0);
        try std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(i32, 1)));

        const addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, global_config.port),
            .addr = @bitCast(global_config.local_ip),
            .zero = [_]u8{0} ** 8,
        };
        try std.posix.bind(sockfd, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(std.posix.sockaddr.in));
        try std.posix.listen(sockfd, 8192);

        const server_watcher = try allocator.create(c.ev_io);
        my_ev_io_init(server_watcher, acceptCb, sockfd, c.EV_READ);
        my_ev_io_start(loop, server_watcher);

        std.debug.print("Linux Native ping_pong server listening on {}.{}.{}.{}:{}\n", .{ global_config.local_ip[0], global_config.local_ip[1], global_config.local_ip[2], global_config.local_ip[3], global_config.port });
    } else {
        std.debug.print("Linux Native ping_pong client connecting to {}.{}.{}.{}:{}\n", .{ global_config.target_ip.?[0], global_config.target_ip.?[1], global_config.target_ip.?[2], global_config.target_ip.?[3], global_config.port });
        for (0..global_config.concurrency) |_| {
            try startClientConnection(loop, allocator);
        }
    }

    my_ev_run(loop);

    const total_time_s = @as(f64, @floatFromInt(std.time.milliTimestamp() - global_start_time)) / 1000.0;
    std.debug.print("--- Final Summary ---\n", .{});
    std.debug.print("Total Connections: {}\n", .{global_conn_count});
    std.debug.print("Average CPS: {d:.2}\n", .{@as(f64, @floatFromInt(global_conn_count)) / total_time_s});
}

fn startClientConnection(loop: ?*anyopaque, allocator: std.mem.Allocator) !void {
    if (global_mark_done) return;
    if (global_config.max_conns) |max| {
        if (global_conn_count >= max) {
            if (global_active_conns == 0) my_ev_break(loop, 2);
            return;
        }
    }

    const sockfd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, 0);
    const addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, global_config.port),
        .addr = @bitCast(global_config.target_ip.?),
        .zero = [_]u8{0} ** 8,
    };

    std.posix.connect(sockfd, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(std.posix.sockaddr.in)) catch |err| {
        if (err != error.WouldBlock) return err;
    };

    _ = try Connection.init(allocator, sockfd, loop, true);
    global_conn_count += 1;
    global_active_conns += 1;
}

fn acceptCb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = revents;
    while (true) {
        const client_fd = std.posix.accept(watcher.fd, null, null, std.posix.SOCK.NONBLOCK) catch |err| {
            if (err == error.WouldBlock) return;
            return;
        };
        _ = Connection.init(std.heap.c_allocator, client_fd, loop, false) catch {
            std.posix.close(client_fd);
            return;
        };
        global_conn_count += 1;
        global_active_conns += 1;
    }
}

const Connection = struct {
    fd: std.posix.socket_t,
    watcher: c.ev_io,
    is_client: bool,
    closed: bool = false,
    ping_sent: bool = false,
    pong_sent: bool = false,

    fn init(allocator: std.mem.Allocator, fd: std.posix.socket_t, loop: ?*anyopaque, is_client: bool) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{
            .fd = fd,
            .watcher = undefined,
            .is_client = is_client,
        };

        const events = if (is_client) c.EV_WRITE | c.EV_READ else c.EV_READ;
        my_ev_io_init(&self.watcher, ioCb, fd, events);
        self.watcher.data = self;
        my_ev_io_start(loop, &self.watcher);

        return self;
    }

    fn close(self: *Connection, loop: ?*anyopaque) void {
        if (self.closed) return;
        self.closed = true;
        my_ev_io_stop(loop, &self.watcher);
        std.posix.close(self.fd);
        global_active_conns -= 1;
        const allocator = std.heap.c_allocator;
        if (self.is_client and !global_mark_done) {
            startClientConnection(loop, allocator) catch {};
        }
        allocator.destroy(self);
    }
};

fn ioCb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    const conn = @as(*Connection, @ptrCast(@alignCast(watcher.data.?)));

    if (revents & c.EV_READ != 0) {
        var buf: [16]u8 = undefined;
        const n = std.posix.read(conn.fd, &buf) catch {
            conn.close(loop);
            return;
        };
        if (n == 0) {
            conn.close(loop);
            return;
        }

        if (conn.is_client) {
            if (std.mem.eql(u8, buf[0..n], "pong")) {
                _ = std.posix.shutdown(conn.fd, std.posix.ShutdownHow.send) catch {};
            }
        } else {
            if (std.mem.eql(u8, buf[0..n], "ping")) {
                _ = std.posix.write(conn.fd, "pong") catch {
                    conn.close(loop);
                    return;
                };
                conn.pong_sent = true;
            }
        }
    }

    if (revents & c.EV_WRITE != 0) {
        if (conn.is_client and !conn.ping_sent) {
            // Check for connection success
            std.posix.getsockoptError(conn.fd) catch {
                conn.close(loop);
                return;
            };

            _ = std.posix.write(conn.fd, "ping") catch {
                conn.close(loop);
                return;
            };
            conn.ping_sent = true;
            // Switch to READ only for the pong
            my_ev_io_stop(loop, watcher);
            my_ev_io_init(watcher, ioCb, conn.fd, c.EV_READ);
            my_ev_io_start(loop, watcher);
        }
    }
}

fn statsCb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = watcher;
    _ = revents;
    const now = std.time.milliTimestamp();
    const diff_conns = global_conn_count - global_last_conn_count;
    const diff_time_s = @as(f64, @floatFromInt(now - global_last_report_time)) / 1000.0;
    const current_cps = @as(f64, @floatFromInt(diff_conns)) / diff_time_s;
    const total_s = @as(f64, @floatFromInt(now - global_start_time)) / 1000.0;

    std.debug.print("[ID: {s}] {d: >5.1}-{d: >5.1} sec  CPS: {d: <6.0} Active: {d}\n", .{ if (std.mem.eql(u8, global_config.mode, "server")) @as([]const u8, "S") else "C", @max(0, total_s - diff_time_s), total_s, current_cps, global_active_conns });

    global_last_report_time = now;
    global_last_conn_count = global_conn_count;

    if (global_config.duration) |d| {
        if (total_s >= @as(f64, @floatFromInt(d))) {
            global_mark_done = true;
            if (global_active_conns == 0 or std.mem.eql(u8, global_config.mode, "server")) {
                my_ev_break(loop, 2);
            }
        }
    }
}

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |j| out[j] = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidIP, 10);
    return out;
}
