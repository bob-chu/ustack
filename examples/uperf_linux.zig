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
    protocol: enum { tcp, udp } = .tcp,
    port: u16 = 5201,
    target_ip: ?[4]u8 = null,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    interface: []const u8 = "",
    packet_size: usize = 0,
    duration: u64 = 5,
};

var global_config = Config{};
var global_connections: std.ArrayList(*Connection) = undefined;

const StaticBuffer = struct {
    var buf = [_]u8{'A'} ** 65536;
};

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <mode> <local_ip> [target_ip] [options]\n", .{args[0]});
        std.debug.print("  mode: server | client\n", .{});
        std.debug.print("  options:\n", .{});
        std.debug.print("    -u        Use UDP (default TCP)\n", .{});
        std.debug.print("    -l LEN    Payload length\n", .{});
        std.debug.print("    -t TIME   Duration in seconds (default 5)\n", .{});
        return;
    }

    global_config.interface = args[1];
    global_config.mode = args[2];
    global_config.local_ip = try parseIp(args[3]);

    var idx: usize = 4;
    if (std.mem.eql(u8, global_config.mode, "client")) {
        global_config.target_ip = try parseIp(args[4]);
        idx = 5;
    }

    while (idx < args.len) : (idx += 1) {
        if (std.mem.eql(u8, args[idx], "-l")) {
            idx += 1;
            global_config.packet_size = try std.fmt.parseInt(usize, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-t")) {
            idx += 1;
            global_config.duration = try std.fmt.parseInt(u64, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-u")) {
            global_config.protocol = .udp;
        }
    }

    global_connections = std.ArrayList(*Connection).init(allocator);

    const loop = my_ev_default_loop();

    var stats_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&stats_watcher, statsCb, 1.0, 1.0);
    my_ev_timer_start(loop, &stats_watcher);

    if (std.mem.eql(u8, global_config.mode, "server")) {
        const is_udp = global_config.protocol == .udp;
        const sock_type: u32 = if (is_udp) std.posix.SOCK.DGRAM else std.posix.SOCK.STREAM;
        const sockfd = try std.posix.socket(std.posix.AF.INET, sock_type | std.posix.SOCK.NONBLOCK, 0);
        try std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(i32, 1)));

        const addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, global_config.port),
            .addr = @bitCast(global_config.local_ip),
            .zero = [_]u8{0} ** 8,
        };
        try std.posix.bind(sockfd, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(std.posix.sockaddr.in));
        if (!is_udp) try std.posix.listen(sockfd, 128);

        const server_watcher = try allocator.create(c.ev_io);
        my_ev_io_init(server_watcher, if (is_udp) udpServerCb else acceptCb, sockfd, c.EV_READ);
        my_ev_io_start(loop, server_watcher);

        std.debug.print("Linux Native uperf {s} server listening on {}.{}.{}.{}:{}\n", .{ @tagName(global_config.protocol), global_config.local_ip[0], global_config.local_ip[1], global_config.local_ip[2], global_config.local_ip[3], global_config.port });
    } else {
        const is_udp = global_config.protocol == .udp;
        const sock_type: u32 = if (is_udp) std.posix.SOCK.DGRAM else std.posix.SOCK.STREAM;
        const sockfd = try std.posix.socket(std.posix.AF.INET, sock_type | std.posix.SOCK.NONBLOCK, 0);
        
        const addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, global_config.port),
            .addr = @bitCast(global_config.target_ip.?),
            .zero = [_]u8{0} ** 8,
        };

        if (!is_udp) {
            std.posix.connect(sockfd, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(std.posix.sockaddr.in)) catch |err| {
                if (err != error.WouldBlock) return err;
            };
        }

        _ = try Connection.init(allocator, sockfd, loop, true);
        std.debug.print("Linux Native uperf {s} client connecting to {}.{}.{}.{}:{}\n", .{ @tagName(global_config.protocol), global_config.target_ip.?[0], global_config.target_ip.?[1], global_config.target_ip.?[2], global_config.target_ip.?[3], global_config.port });
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
}

fn acceptCb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = revents;
    while (true) {
        const client_fd = std.posix.accept(watcher.fd, null, null, std.posix.SOCK.NONBLOCK) catch |err| {
            if (err == error.WouldBlock) return;
            std.debug.print("accept error: {}\n", .{err});
            return;
        };

        _ = Connection.init(std.heap.c_allocator, client_fd, loop, false) catch {
            std.posix.close(client_fd);
            return;
        };
    }
}

fn udpServerCb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = revents;
    _ = Connection.init(std.heap.c_allocator, watcher.fd, loop, false) catch {
        return;
    };
    // Only one connection for UDP server for now (to match uperf.zig)
    my_ev_io_stop(loop, watcher);
}

const Connection = struct {
    fd: std.posix.socket_t,
    watcher: c.ev_io,
    is_client: bool,
    closed: bool = false,
    start_time: i64,
    first_packet_time: i64 = 0,
    end_time: i64 = 0,
    bytes_rx: u64 = 0,
    bytes_tx: u64 = 0,
    bytes_since_last_report: u64 = 0,

    fn init(allocator: std.mem.Allocator, fd: std.posix.socket_t, loop: ?*anyopaque, is_client: bool) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{
            .fd = fd,
            .watcher = undefined,
            .is_client = is_client,
            .start_time = std.time.milliTimestamp(),
        };

        const is_udp = global_config.protocol == .udp;
        const events = if (is_client) c.EV_WRITE | c.EV_READ else c.EV_READ;
        my_ev_io_init(&self.watcher, ioCb, fd, events);
        self.watcher.data = self;
        my_ev_io_start(loop, &self.watcher);

        try global_connections.append(self);

        // For UDP client, connect it to target so write() works
        if (is_udp and is_client) {
            const addr = std.posix.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, global_config.port),
                .addr = @bitCast(global_config.target_ip.?),
                .zero = [_]u8{0} ** 8,
            };
            try std.posix.connect(fd, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(std.posix.sockaddr.in));
        }

        return self;
    }

    fn close(self: *Connection, loop: ?*anyopaque) void {
        if (self.closed) return;
        self.closed = true;
        self.end_time = std.time.milliTimestamp();
        my_ev_io_stop(loop, &self.watcher);
        // Only close if it's not the server's main UDP socket if we stopped it...
        // Actually, it's safer to just close it.
        std.posix.close(self.fd);
    }
};

fn ioCb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    const conn = @as(*Connection, @ptrCast(@alignCast(watcher.data.?)));
    const is_udp = global_config.protocol == .udp;

    // Check for connection errors on first event for clients
    if (conn.is_client and conn.first_packet_time == 0 and !is_udp) {
        std.posix.getsockoptError(conn.fd) catch |err| {
            std.debug.print("Connection failed: {}\n", .{err});
            conn.close(loop);
            return;
        };
    }
    
    if (revents & c.EV_READ != 0) {
        var buf: [65536]u8 = undefined;
        while (true) {
            const n = std.posix.read(conn.fd, &buf) catch |err| {
                if (err == error.WouldBlock) break;
                if (!is_udp) conn.close(loop);
                return;
            };
            if (n == 0) {
                if (!is_udp) conn.close(loop);
                return;
            }
            if (conn.first_packet_time == 0) conn.first_packet_time = std.time.milliTimestamp();
            conn.bytes_rx += n;
            conn.bytes_since_last_report += n;
        }
    }

    if (revents & c.EV_WRITE != 0) {
        if (conn.first_packet_time == 0) conn.first_packet_time = std.time.milliTimestamp();
        const slen = if (global_config.packet_size > 0) global_config.packet_size else (if (is_udp) @as(usize, 1472) else 65536);
        var budget: usize = 1000;
        while (budget > 0) : (budget -= 1) {
            const sl = @min(slen, StaticBuffer.buf.len);
            const n = std.posix.write(conn.fd, StaticBuffer.buf[0..sl]) catch |err| {
                if (err == error.WouldBlock) return;
                if (!is_udp) conn.close(loop);
                return;
            };
            conn.bytes_tx += n;
            conn.bytes_since_last_report += n;
        }
    }
}

fn statsCb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = watcher; _ = revents;
    const now = std.time.milliTimestamp();

    var total_rx_bytes: u64 = 0;
    var total_tx_bytes: u64 = 0;

    for (global_connections.items) |conn| {
        if (conn.closed) continue;
        if (conn.is_client) {
            total_tx_bytes += conn.bytes_since_last_report;
        } else {
            total_rx_bytes += conn.bytes_since_last_report;
        }
        conn.bytes_since_last_report = 0;

        if (conn.is_client and conn.first_packet_time > 0) {
            const elapsed = now - conn.first_packet_time;
            if (elapsed > global_config.duration * 1000) {
                conn.close(loop);
                my_ev_break(loop, 2); // EVBREAK_ALL = 2
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

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |j| {
        const s = it.next() orelse return error.InvalidIP;
        out[j] = try std.fmt.parseInt(u8, s, 10);
    }
    return out;
}
