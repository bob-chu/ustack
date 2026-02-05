const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const waiter = ustack.waiter;
const buffer = ustack.buffer;

const c = @cImport({
    @cInclude("stdio.h");
});

var global_af_packet: *ustack.drivers.af_packet.AfPacket = undefined;
var global_eth: ustack.link.eth.EthernetEndpoint = undefined;
var global_stack: *stack.Stack = undefined;
var global_mux: ?*EventMultiplexer = null;
var global_client: ?*IperfClient = null;
var global_server: ?*IperfServer = null;

const Mode = enum { server, client };
const Protocol = enum { tcp, udp };

const Config = struct {
    mode: Mode = .server,
    protocol: Protocol = .tcp,
    port: u16 = 5201,
    streams: usize = 1,
    time: u64 = 10,
    interval: u64 = 1,
    target_ip: ?[4]u8 = null,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    interface: [16]u8 = [_]u8{0} ** 16,
    mtu: u32 = 1500,
    packet_size: usize = 0,
};

const MuxContext = union(enum) { server: *IperfServer, connection: *IperfConnection };

const EventMultiplexer = struct {
    ready_queue: std.fifo.LinearFifo(*waiter.Entry, .Dynamic),
    signal_fd: std.posix.fd_t,
    pub fn init(allocator: std.mem.Allocator) !EventMultiplexer {
        return .{ .ready_queue = std.fifo.LinearFifo(*waiter.Entry, .Dynamic).init(allocator), .signal_fd = try std.posix.eventfd(0, std.os.linux.EFD.NONBLOCK) };
    }
    pub fn upcall(entry: *waiter.Entry) void {
        const self = @as(*EventMultiplexer, @ptrCast(@alignCast(entry.upcall_ctx.?)));
        self.ready_queue.writeItem(entry) catch {};
        const val: u64 = 1;
        _ = std.posix.write(self.signal_fd, std.mem.asBytes(&val)) catch {};
    }
    pub fn pollReady(self: *EventMultiplexer) ![]*waiter.Entry {
        var buf: [8]u8 = undefined;
        _ = std.posix.read(self.signal_fd, &buf) catch |err| {
            if (err == error.WouldBlock) return &[_]*waiter.Entry{};
            return err;
        };
        const count = self.ready_queue.readableLength();
        if (count == 0) return &[_]*waiter.Entry{};
        const entries = try global_stack.allocator.alloc(*waiter.Entry, count);
        _ = self.ready_queue.read(entries);
        return entries;
    }
};

fn upcall_wrapper(entry: *waiter.Entry) void {
    if (global_mux) |_| EventMultiplexer.upcall(entry);
}

fn libev_af_packet_cb(loop: ?*anyopaque, watcher: ?*anyopaque, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    var budget: usize = 1024;
    while (budget > 0) : (budget -= 1) {
        const ok = global_af_packet.readPacket() catch break;
        if (!ok) break;
    }
}

var last_tick: i64 = 0;
fn libev_timer_cb(loop: ?*anyopaque, watcher: ?*anyopaque, revents: i32) callconv(.C) void {
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
    if (global_server) |s| s.report();
    if (global_client) |cl| cl.report();
}

fn libev_mux_cb(loop: ?*anyopaque, watcher: ?*anyopaque, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    if (global_mux) |mux| {
        const ready = mux.pollReady() catch return;
        defer global_stack.allocator.free(ready);
        for (ready) |entry| {
            const ctx = @as(*MuxContext, @ptrCast(@alignCast(entry.context.?)));
            switch (ctx.*) {
                .server => |s| s.onEvent(),
                .connection => |conn| conn.onEvent(),
            }
        }
    }
}

const IperfServer = struct {
    ep: ustack.tcpip.Endpoint,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    wq: *waiter.Queue,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    conns: std.ArrayList(*IperfConnection),
    last_activity: i64 = 0,
    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, config: Config) !*IperfServer {
        const self = try allocator.create(IperfServer);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(if (config.protocol == .tcp) @as(u8, 6) else 17).?.newEndpoint(s, 0x0800, wq);
        self.* = .{ .ep = ep, .allocator = allocator, .mux = mux, .config = config, .wq = wq, .mux_ctx = .{ .server = self }, .wait_entry = undefined, .conns = std.ArrayList(*IperfConnection).init(allocator), .last_activity = std.time.milliTimestamp() };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, upcall_wrapper);
        wq.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventErr);
        try ep.bind(.{ .nic = 1, .addr = .{ .v4 = config.local_ip }, .port = config.port });
        if (config.protocol == .tcp) try ep.listen(128);
        return self;
    }
    fn onEvent(self: *IperfServer) void {
        self.last_activity = std.time.milliTimestamp();
        if (self.config.protocol == .tcp) {
            while (true) {
                const res = self.ep.accept() catch break;
                const conn = IperfConnection.init(self.allocator, res.ep, res.wq, self.mux, self.config, self) catch continue;
                self.conns.append(conn) catch {};
            }
        } else if (self.conns.items.len == 0) {
            const conn = IperfConnection.init(self.allocator, self.ep, self.wq, self.mux, self.config, self) catch return;
            self.conns.append(conn) catch {};
        }
    }
    fn report(self: *IperfServer) void {
        if (std.time.milliTimestamp() - self.last_activity > 10000) std.process.exit(0);
    }
};

const IperfClient = struct {
    stack: *stack.Stack,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    conns: std.ArrayList(*IperfConnection),
    start_time: i64 = 0,
    last_report: i64 = 0,
    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, config: Config) !*IperfClient {
        const self = try allocator.create(IperfClient);
        self.* = .{ .stack = s, .allocator = allocator, .mux = mux, .config = config, .conns = std.ArrayList(*IperfConnection).init(allocator), .start_time = std.time.milliTimestamp(), .last_report = std.time.milliTimestamp() };
        return self;
    }
    pub fn report(self: *IperfClient) void {
        const now = std.time.milliTimestamp();
        const elapsed = now - self.last_report;
        if (elapsed < 1000) return;
        var tb: u64 = 0;
        var act: usize = 0;
        for (self.conns.items) |conn| {
            if (conn.closed) continue;
            tb += conn.bytes_since_last_report;
            act += 1;
            const sec = @as(f64, @floatFromInt(elapsed)) / 1000.0;
            std.debug.print("[{d: >3}] {d: >5.2}-{d: >5.2} sec {d: >6.2} Mbits/sec\n", .{ conn.id, @as(f64, @floatFromInt(self.last_report - self.start_time)) / 1000.0, @as(f64, @floatFromInt(now - self.start_time)) / 1000.0, (@as(f64, @floatFromInt(conn.bytes_since_last_report)) * 8.0) / sec / 1000000.0 });
            conn.bytes_since_last_report = 0;
        }
        if (act > 1) {
            const sec = @as(f64, @floatFromInt(elapsed)) / 1000.0;
            std.debug.print("[SUM] {d: >5.2}-{d: >5.2} sec {d: >6.2} Mbits/sec\n", .{ @as(f64, @floatFromInt(self.last_report - self.start_time)) / 1000.0, @as(f64, @floatFromInt(now - self.start_time)) / 1000.0, (@as(f64, @floatFromInt(tb)) * 8.0) / sec / 1000000.0 });
        }
        self.last_report = now;
    }
    pub fn start(self: *IperfClient) !void {
        for (0..self.config.streams) |i| {
            const wq = try self.allocator.create(waiter.Queue);
            wq.* = .{};
            const ep = try self.stack.transport_protocols.get(if (self.config.protocol == .tcp) @as(u8, 6) else 17).?.newEndpoint(self.stack, 0x0800, wq);
            const conn = try IperfConnection.init(self.allocator, ep, wq, self.mux, self.config, self);
            conn.id = i;
            try self.conns.append(conn);
            try ep.bind(.{ .nic = 0, .addr = .{ .v4 = self.config.local_ip }, .port = 0 });
            _ = ep.connect(.{ .nic = 1, .addr = .{ .v4 = self.config.target_ip.? }, .port = self.config.port }) catch {};
            if (self.config.protocol == .udp) {
                self.mux.ready_queue.writeItem(&conn.wait_entry) catch {};
                const val: u64 = 1;
                _ = std.posix.write(self.mux.signal_fd, std.mem.asBytes(&val)) catch {};
            }
        }
    }
};

const IperfConnection = struct {
    id: usize = 0,
    ep: ustack.tcpip.Endpoint,
    wq: *waiter.Queue,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    parent: *anyopaque,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    closed: bool = false,
    bytes_since_last_report: u64 = 0,
    total_bytes: u64 = 0,
    start_time: i64 = 0,
    block_buffer: []u8,
    pub fn init(allocator: std.mem.Allocator, ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer, config: Config, parent: *anyopaque) !*IperfConnection {
        const self = try allocator.create(IperfConnection);
        const buf = try allocator.alloc(u8, 128 * 1024);
        @memset(buf, 'A');
        self.* = .{ .ep = ep, .wq = wq, .allocator = allocator, .mux = mux, .config = config, .parent = parent, .mux_ctx = .{ .connection = self }, .wait_entry = undefined, .start_time = std.time.milliTimestamp(), .block_buffer = buf };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, upcall_wrapper);
        var evs: u16 = waiter.EventIn | waiter.EventHUp | waiter.EventErr;
        if (config.mode == .client) evs |= waiter.EventOut;
        wq.eventRegister(&self.wait_entry, evs);
        return self;
    }
    fn onEvent(self: *IperfConnection) void {
        if (self.closed) return;
        if (self.config.protocol == .tcp) {
            const tcp_ep = @as(*ustack.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.ep.ptr)));
            if (tcp_ep.state == .error_state) {
                self.close();
                return;
            }
            if (self.config.mode == .client and tcp_ep.state != .established) return;
        }
        if (self.config.mode == .server) {
            while (true) {
                var buf = self.ep.read(null) catch break;
                defer buf.deinit();
                if (buf.size == 0) {
                    self.close();
                    break;
                }
                self.bytes_since_last_report += buf.size;
                self.total_bytes += buf.size;
            }
        } else {
            var slen = if (self.config.packet_size > 0) self.config.packet_size else (if (self.config.protocol == .udp) self.config.mtu - 28 else self.block_buffer.len);
            slen = @min(slen, self.block_buffer.len);
            var budget: usize = 1024;
            while (budget > 0) : (budget -= 1) {
                var iov = [_]std.posix.iovec{.{ .base = self.block_buffer[0..slen].ptr, .len = slen }};
                var uio = buffer.Uio.init(@as([]const []u8, @ptrCast(iov[0..1])));
                const n = self.ep.writev(&uio, .{}) catch |err| {
                    if (err == tcpip.Error.WouldBlock) return;
                    self.close();
                    return;
                };
                self.bytes_since_last_report += n;
                self.total_bytes += n;
                if (std.time.milliTimestamp() - self.start_time > self.config.time * 1000) {
                    self.close();
                    if (global_client) |cl| {
                        var all = true;
                        var tot: u64 = 0;
                        for (cl.conns.items) |cn| {
                            if (!cn.closed) all = false;
                            tot += cn.total_bytes;
                        }
                        if (all) {
                            const sec = @as(f64, @floatFromInt(std.time.milliTimestamp() - cl.start_time)) / 1000.0;
                            std.debug.print("[SUM] 0.00-{d: >5.2} sec {d: >6.2} Mbits/sec\n", .{ sec, (@as(f64, @floatFromInt(tot)) * 8.0) / sec / 1000000.0 });
                            std.process.exit(0);
                        }
                    }
                    return;
                }
            }
            self.mux.ready_queue.writeItem(&self.wait_entry) catch {};
            const val: u64 = 1;
            _ = std.posix.write(self.mux.signal_fd, std.mem.asBytes(&val)) catch {};
        }
    }
    fn close(self: *IperfConnection) void {
        if (self.closed) return;
        self.closed = true;
        self.wq.eventUnregister(&self.wait_entry);
        self.ep.close();
        self.allocator.free(self.block_buffer);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 4) return;
    var config = Config{};
    const iname = args[1];
    @memcpy(config.interface[0..iname.len], iname);
    var ip_split = std.mem.splitSequence(u8, args[2], "/");
    const lstr = ip_split.next() orelse return;
    const plen = try std.fmt.parseInt(u8, ip_split.next() orelse "24", 10);
    config.local_ip = try parseIp(lstr);
    if (std.mem.eql(u8, args[3], "server")) config.mode = .server else {
        config.mode = .client;
        if (args.len < 5) return;
        config.target_ip = try parseIp(args[4]);
    }
    var idx: usize = if (config.mode == .server) 4 else 5;
    while (idx < args.len) : (idx += 1) {
        if (std.mem.eql(u8, args[idx], "-p")) {
            idx += 1;
            config.port = try std.fmt.parseInt(u16, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-u")) config.protocol = .udp else if (std.mem.eql(u8, args[idx], "-P")) {
            idx += 1;
            config.streams = try std.fmt.parseInt(usize, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-t")) {
            idx += 1;
            config.time = try std.fmt.parseInt(u64, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-m")) {
            idx += 1;
            config.mtu = try std.fmt.parseInt(u32, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-l")) {
            idx += 1;
            config.packet_size = try std.fmt.parseInt(usize, args[idx], 10);
        }
    }
    var s = try ustack.init(allocator);
    global_stack = &s;
    defer s.deinit();
    const dev = std.mem.sliceTo(&config.interface, 0);
    var afp = try ustack.drivers.af_packet.AfPacket.init(allocator, &s.cluster_pool, dev);
    global_af_packet = &afp;
    global_eth = ustack.link.eth.EthernetEndpoint.init(afp.linkEndpoint(), afp.address);
    global_eth.linkEndpoint().setMTU(config.mtu);
    try s.createNIC(1, global_eth.linkEndpoint());
    try s.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = config.mtu });
    try s.nics.get(1).?.addAddress(.{ .protocol = 0x0806, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try s.nics.get(1).?.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = config.local_ip }, .prefix_len = plen } });
    var mux = try EventMultiplexer.init(allocator);
    global_mux = &mux;
    const loop = my_ev_default_loop();
    const EV_OBJ_SIZE = 256;
    var af_io: [EV_OBJ_SIZE]u8 align(16) = undefined;
    @memset(&af_io, 0);
    my_ev_io_init(@ptrCast(&af_io), libev_af_packet_cb, afp.fd, 0x01);
    my_ev_io_start(loop, @ptrCast(&af_io));
    var mux_io: [EV_OBJ_SIZE]u8 align(16) = undefined;
    @memset(&mux_io, 0);
    my_ev_io_init(@ptrCast(&mux_io), libev_mux_cb, mux.signal_fd, 0x01);
    my_ev_io_start(loop, @ptrCast(&mux_io));
    var timer: [EV_OBJ_SIZE]u8 align(16) = undefined;
    @memset(&timer, 0);
    my_ev_timer_init(@ptrCast(&timer), libev_timer_cb, 0.001, 0.001);
    my_ev_timer_start(loop, @ptrCast(&timer));
    if (config.mode == .server) global_server = try IperfServer.init(&s, allocator, &mux, config) else {
        global_client = try IperfClient.init(&s, allocator, &mux, config);
        try global_client.?.start();
    }
    my_ev_run(loop);
}

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.splitSequence(u8, str, ".");
    var res: [4]u8 = undefined;
    var j: usize = 0;
    while (it.next()) |part| : (j += 1) {
        if (j >= 4) return error.InvalidIp;
        res[j] = try std.fmt.parseInt(u8, part, 10);
    }
    return if (j != 4) error.InvalidIp else res;
}

extern fn my_ev_default_loop() ?*anyopaque;
extern fn my_ev_io_init(w: *anyopaque, cb: *const fn (?*anyopaque, ?*anyopaque, i32) callconv(.C) void, fd: i32, events: i32) void;
extern fn my_ev_timer_init(w: *anyopaque, cb: *const fn (?*anyopaque, ?*anyopaque, i32) callconv(.C) void, after: f64, repeat: f64) void;
extern fn my_ev_io_start(loop: ?*anyopaque, w: *anyopaque) void;
extern fn my_ev_timer_start(loop: ?*anyopaque, w: *anyopaque) void;
extern fn my_ev_run(loop: ?*anyopaque) void;
extern fn my_ev_break(loop: ?*anyopaque) void;
