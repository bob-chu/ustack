const std = @import("std");
const ustack = @import("ustack");
const Runtime = ustack.runtime.Runtime;
const Socket = ustack.socket.Socket;
const waiter = ustack.waiter;
const tcpip = ustack.tcpip;
const utils = ustack.utils;
const buffer = ustack.buffer;

const c = @cImport({
    @cInclude("ev.h");
});

var global_rt: Runtime = undefined;
var global_connections: std.ArrayList(*Connection) = undefined;
var global_config: Config = .{};

const Config = struct {
    mode: []const u8 = "server",
    protocol: Runtime.Protocol = .tcp,
    port: u16 = 5201,
    target_ip: ?[]const u8 = null,
    address: []const u8 = "",
    local_ip: tcpip.Address = undefined,
    interface: []const u8 = "",
    mtu: u32 = 1500,
    packet_size: usize = 0,
    duration: u64 = 5,
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

    global_config.interface = args[1];
    global_config.mode = args[2];
    global_config.address = args[3];

    {
        var it = std.mem.split(u8, global_config.address, "/");
        global_config.local_ip = try utils.parseIp(it.first());
    }

    var idx: usize = 4;
    if (std.mem.eql(u8, global_config.mode, "client")) {
        global_config.target_ip = args[4];
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
        }
    }

    global_rt = try Runtime.init(allocator, .{
        .interface = global_config.interface,
        .driver = .af_packet,
        .address = global_config.address,
        .mtu = global_config.mtu,
    });
    defer global_rt.deinit();

    global_connections = std.ArrayList(*Connection).init(allocator);

    const loop = my_ev_default_loop();

    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_rt.driverFd(), 0x01);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.001, 0.001);
    my_ev_timer_start(loop, &timer_watcher);

    var stats_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&stats_watcher, libev_stats_cb, 1.0, 1.0);
    my_ev_timer_start(loop, &stats_watcher);

    var mux_io = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&mux_io, libev_mux_cb, global_rt.muxFd(), 0x01);
    my_ev_io_start(loop, &mux_io);

    if (std.mem.eql(u8, global_config.mode, "server")) {
        _ = try PerfServer.init(allocator);
    } else {
        _ = try Connection.initClient(allocator, global_config.target_ip.?);
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
    _ = loop;
    _ = watcher;
    _ = revents;
    global_rt.processPackets() catch {};
    global_rt.flush();
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
        global_rt.tickMs(@as(u64, @intCast(diff)));
        last_tick = now;
    }
    global_rt.flush();
}

fn libev_stats_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = watcher;
    _ = revents;
    const now = std.time.milliTimestamp();
    for (global_connections.items) |conn| {
        if (conn.first_packet_time > 0) {
            const elapsed = now - conn.first_packet_time;
            if (elapsed > global_config.duration * 1000) {
                conn.end_time = now;
                my_ev_break(loop, 2);
                return;
            }
        } else {
            const start_elapsed = now - conn.start_time;
            // Shorter safety break for faster feedback in tests
            if (start_elapsed > (global_config.duration + 5) * 1000) {
                my_ev_break(loop, 2);
                return;
            }
        }
    }
}
fn libev_mux_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    const ready = global_rt.mux.pollReady() catch return;
    for (ready) |entry| Socket.dispatch(entry);
    global_rt.flush();
}

const PerfServer = struct {
    sock: *Socket,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*PerfServer {
        const self = try allocator.create(PerfServer);
        const sock_obj = try global_rt.socket(global_config.protocol);
        try sock_obj.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = global_config.port });
        if (global_config.protocol == .tcp) try sock_obj.listen(128);
        self.* = .{ .sock = sock_obj, .allocator = allocator };
        sock_obj.setHandler(global_rt.mux, self, PerfServer.onEvent);
        if (global_config.protocol == .udp) _ = try Connection.init(allocator, sock_obj, false);
        return self;
    }

    fn onEvent(ctx: ?*anyopaque, sock_obj: *Socket, events: waiter.EventMask) void {
        const self = @as(*PerfServer, @ptrCast(@alignCast(ctx.?)));
        if (events & waiter.EventIn != 0 and global_config.protocol == .tcp) {
            while (true) {
                const accepted = sock_obj.accept() catch break;
                _ = Connection.init(self.allocator, accepted, false) catch continue;
            }
        }
    }
};

fn noopConsumption(_: ?*anyopaque, _: usize) void {}

const Connection = struct {
    sock: *Socket,
    allocator: std.mem.Allocator,
    is_client: bool,
    closed: bool = false,
    start_time: i64 = 0,
    first_packet_time: i64 = 0,
    end_time: i64 = 0,
    bytes_rx: u64 = 0,
    bytes_tx: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, sock: *Socket, is_client: bool) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{
            .sock = sock,
            .allocator = allocator,
            .is_client = is_client,
            .start_time = std.time.milliTimestamp(),
            .first_packet_time = 0,
            .end_time = 0,
            .bytes_rx = 0,
            .bytes_tx = 0,
        };
        sock.setHandler(global_rt.mux, self, Connection.onSocketEvent);
        try global_connections.append(self);
        return self;
    }

    pub fn initClient(allocator: std.mem.Allocator, target_str: []const u8) !*Connection {
        const sock_obj = try global_rt.socket(global_config.protocol);
        const self = try Connection.init(allocator, sock_obj, true);
        try sock_obj.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 0 });
        const target_ip = try utils.parseIp(target_str);
        _ = sock_obj.connect(.{ .nic = 1, .addr = target_ip, .port = global_config.port }) catch |err| {
            if (err != tcpip.Error.WouldBlock) return err;
        };
        if (global_config.protocol == .udp) self.onEvent(waiter.EventOut);
        return self;
    }

    fn onSocketEvent(ctx: ?*anyopaque, _: *Socket, events: waiter.EventMask) void {
        const self = @as(*Connection, @ptrCast(@alignCast(ctx.?)));
        self.onEvent(events);
    }

    fn onEvent(self: *Connection, events: waiter.EventMask) void {
        if (self.closed) return;
        if (events & (waiter.EventHUp | waiter.EventErr) != 0) {
            self.close();
            return;
        }

        // Handle RX
        if (events & waiter.EventIn != 0) {
            while (true) {
                var vview = self.sock.endpoint.read(null) catch break;
                if (self.first_packet_time == 0) self.first_packet_time = std.time.milliTimestamp();
                if (vview.size == 0) {
                    vview.deinit();
                    if (global_config.protocol == .tcp) self.close();
                    break;
                }
                self.bytes_rx += vview.size;
                vview.deinit();
            }
        }

        // Handle TX
        if (events & waiter.EventOut != 0 and self.is_client) {
            const slen = if (global_config.packet_size > 0) global_config.packet_size else if (global_config.protocol == .udp) @as(usize, @intCast(global_config.mtu - 28)) else 65536;
            var budget: usize = 1000;
            while (budget > 0) : (budget -= 1) {
                const sl = @min(slen, 65536);
                const n = if (global_config.protocol == .tcp)
                    self.sock.endpoint.writeZeroCopy(StaticBuffer.buf[0..sl], .{ .ptr = self, .run = noopConsumption }, .{}) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        return;
                    }
                else
                    self.sock.write(StaticBuffer.buf[0..sl]) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        return;
                    };
                if (self.first_packet_time == 0) self.first_packet_time = std.time.milliTimestamp();
                self.bytes_tx += n;
            }
            ustack.event_mux.EventMultiplexer.upcall(&self.sock.wait_entry);
        }
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
