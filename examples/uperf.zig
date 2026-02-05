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

const MuxContext = union(enum) {
    server: *PerfServer,
    connection: *Connection,
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

    var mtu: u32 = 1500;
    var packet_size: usize = 0;
    var duration: u64 = 5;
    var protocol: enum { tcp, udp } = .tcp;
    var cc_alg: tcpip.CongestionControlAlgorithm = .new_reno;

    var idx: usize = 4;
    if (std.mem.eql(u8, mode, "client")) idx = 5;
    while (idx < args.len) : (idx += 1) {
        if (std.mem.eql(u8, args[idx], "-m")) {
            idx += 1;
            mtu = try std.fmt.parseInt(u32, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-l")) {
            idx += 1;
            packet_size = try std.fmt.parseInt(usize, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-t")) {
            idx += 1;
            duration = try std.fmt.parseInt(u64, args[idx], 10);
        } else if (std.mem.eql(u8, args[idx], "-u")) {
            protocol = .udp;
        } else if (std.mem.eql(u8, args[idx], "-C")) {
            idx += 1;
            if (std.mem.eql(u8, args[idx], "cubic")) {
                cc_alg = .cubic;
            } else if (std.mem.eql(u8, args[idx], "bbr")) {
                cc_alg = .bbr;
            } else if (std.mem.eql(u8, args[idx], "newreno")) {
                cc_alg = .new_reno;
            }
        }
    }

    global_stack = try ustack.init(allocator);
    global_af_packet = try AfPacket.init(allocator, &global_stack.cluster_pool, ifname);
    global_eth = ustack.link.eth.EthernetEndpoint.init(global_af_packet.linkEndpoint(), global_af_packet.address);
    global_eth.linkEndpoint().setMTU(mtu);
    try global_stack.createNIC(1, global_eth.linkEndpoint());

    var parts = std.mem.split(u8, ip_cidr, "/");
    const addr_v4 = try parseIp(parts.first());
    const prefix_len = try std.fmt.parseInt(u8, parts.next() orelse "24", 10);

    const nic = global_stack.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0806, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = addr_v4 }, .prefix_len = prefix_len } });

    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = addr_v4 }, .prefix = prefix_len }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = mtu });
    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = mtu });

    const mux = try EventMultiplexer.init(allocator);
    global_mux = mux;
    const loop = my_ev_default_loop();

    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_af_packet.fd, 0x01);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.001, 0.001);
    my_ev_timer_start(loop, &timer_watcher);

    var mux_io = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), 0x01);
    my_ev_io_start(loop, &mux_io);

    if (std.mem.eql(u8, mode, "server")) {
        _ = try PerfServer.init(&global_stack, allocator, mux, protocol == .udp, cc_alg);
    } else {
        const target_ip = try parseIp(args[4]);
        _ = try Connection.initClient(&global_stack, allocator, mux, target_ip, addr_v4, protocol == .udp, mtu, packet_size, duration, cc_alg);
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
    is_udp: bool,
    cc_alg: tcpip.CongestionControlAlgorithm,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, is_udp: bool, cc_alg: tcpip.CongestionControlAlgorithm) !*PerfServer {
        const self = try allocator.create(PerfServer);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(if (is_udp) @as(u8, 17) else 6).?.newEndpoint(s, 0x0800, wq);
        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 5201 });
        if (!is_udp) {
            try ep.listen(128);
        } else {
            try ep.setOption(.{ .congestion_control = cc_alg });
        }

        self.* = .{ .listener = ep, .allocator = allocator, .mux = mux, .mux_ctx = .{ .server = self }, .wait_entry = undefined, .is_udp = is_udp, .cc_alg = cc_alg };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn);

        if (is_udp) {
            _ = try Connection.init(allocator, ep, wq, mux, false, 0, 0, 0);
        }
        return self;
    }

    fn onAccept(self: *PerfServer) void {
        while (true) {
            const res = self.listener.accept() catch break;
            if (!self.is_udp) {
                res.ep.setOption(.{ .congestion_control = self.cc_alg }) catch {};
            }
            _ = Connection.init(self.allocator, res.ep, res.wq, self.mux, false, 0, 0, 0) catch continue;
        }
    }
};

const Connection = struct {
    ep: ustack.tcpip.Endpoint,
    wq: *waiter.Queue,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    is_client: bool,
    start_time: i64 = 0,
    last_report_time: i64 = 0,
    bytes: u64 = 0,
    bytes_since_last_report: u64 = 0,
    packets_since_last_report: u64 = 0,
    duration: u64 = 0,
    packet_size: usize = 0,
    mtu: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer, is_client: bool, mtu: u32, pkt_size: usize, duration: u64) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{ .ep = ep, .wq = wq, .allocator = allocator, .mux = mux, .mux_ctx = .{ .connection = self }, .wait_entry = undefined, .is_client = is_client, .start_time = std.time.milliTimestamp(), .last_report_time = std.time.milliTimestamp(), .mtu = mtu, .packet_size = pkt_size, .duration = duration };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn | (if (is_client) waiter.EventOut else 0) | waiter.EventHUp | waiter.EventErr);
        return self;
    }

    pub fn initClient(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, target: [4]u8, local: [4]u8, is_udp: bool, mtu: u32, pkt_size: usize, duration: u64, cc_alg: tcpip.CongestionControlAlgorithm) !*Connection {
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(if (is_udp) @as(u8, 17) else 6).?.newEndpoint(s, 0x0800, wq);
        if (!is_udp) {
            try ep.setOption(.{ .congestion_control = cc_alg });
        }
        const self = try Connection.init(allocator, ep, wq, mux, true, mtu, pkt_size, duration);
        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = local }, .port = 0 });
        _ = ep.connect(.{ .nic = 1, .addr = .{ .v4 = target }, .port = 5201 }) catch |err| {
            if (err != tcpip.Error.WouldBlock) return err;
        };
        if (is_udp) self.onEvent();
        return self;
    }

    fn onEvent(self: *Connection) void {
        const now = std.time.milliTimestamp();
        if (self.is_client) {
            if (now - self.last_report_time >= 1000) {
                const elapsed_ms = now - self.last_report_time;
                const total_elapsed_ms = now - self.start_time;
                const sec = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
                const total_sec = @as(f64, @floatFromInt(total_elapsed_ms)) / 1000.0;
                const mbps = (@as(f64, @floatFromInt(self.bytes_since_last_report)) * 8.0) / sec / 1000000.0;
                const pps = @as(f64, @floatFromInt(self.packets_since_last_report)) / sec;
                std.debug.print("[ID: 1] {d: >5.2}-{d: >5.2} sec {d: >7.2} Mbits/sec  {d: >9.2} pps\n", .{ total_sec - sec, total_sec, mbps, pps });
                self.bytes_since_last_report = 0;
                self.packets_since_last_report = 0;
                self.last_report_time = now;
            }

            if (now - self.start_time > self.duration * 1000) {
                const sec = @as(f64, @floatFromInt(now - self.start_time)) / 1000.0;
                std.debug.print("- - - - - - - - - - - - - - - - - - - - - - - - -\n", .{});
                std.debug.print("[ID: 1] 0.00-{d: >5.2} sec {d: >7.2} Mbits/sec (Total: {} bytes)\n", .{ sec, (@as(f64, @floatFromInt(self.bytes)) * 8.0) / sec / 1000000.0, self.bytes });
                std.process.exit(0);
            }
        }

        if (!self.is_client) {
            if (now - self.last_report_time >= 1000) {
                const elapsed_ms = now - self.last_report_time;
                const total_elapsed_ms = now - self.start_time;
                const sec = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
                const total_sec = @as(f64, @floatFromInt(total_elapsed_ms)) / 1000.0;
                const mbps = (@as(f64, @floatFromInt(self.bytes_since_last_report)) * 8.0) / sec / 1000000.0;
                const pps = @as(f64, @floatFromInt(self.packets_since_last_report)) / sec;
                std.debug.print("[ID: S] {d: >5.2}-{d: >5.2} sec {d: >7.2} Mbits/sec  {d: >9.2} pps\n", .{ total_sec - sec, total_sec, mbps, pps });
                self.bytes_since_last_report = 0;
                self.packets_since_last_report = 0;
                self.last_report_time = now;
            }
            while (true) {
                var buf = self.ep.read(null) catch break;
                defer buf.deinit();
                if (buf.size == 0) return;
                self.bytes += buf.size;
                self.bytes_since_last_report += buf.size;
                self.packets_since_last_report += 1;
            }
        } else {
            const slen = if (self.packet_size > 0) self.packet_size else @as(usize, @intCast(self.mtu - 100));
            const static_buf = struct {
                var buf = [_]u8{'A'} ** 65536;
            };
            const Payloader = struct {
                len: usize,
                fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                    return static_buf.buf[0..@as(*@This(), @ptrCast(@alignCast(ptr))).len];
                }
            };
            var p = Payloader{ .len = @min(slen, 65536) };
            var budget: usize = 1000;
            while (budget > 0) : (budget -= 1) {
                const n = self.ep.write(.{ .ptr = &p, .vtable = &.{ .fullPayload = Payloader.fullPayload } }, .{}) catch |err| {
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
