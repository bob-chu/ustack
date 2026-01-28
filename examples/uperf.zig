const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const header = ustack.header;
const AfPacket = ustack.drivers.af_packet.AfPacket;
const EventMultiplexer = ustack.event_mux.EventMultiplexer;

const c = @cImport({
    @cInclude("ev.h");
    @cInclude("stdio.h");
});

var global_stack: stack.Stack = undefined;
var global_af_packet: AfPacket = undefined;
var global_eth: ustack.link.eth.EthernetEndpoint = undefined;
var global_mux: ?*EventMultiplexer = null;
var global_server: ?*IperfServer = null;
var global_client: ?*IperfClient = null;

const Protocol = enum { tcp, udp };

const Mode = enum { server, client };

const Config = struct {
    mode: Mode,
    protocol: Protocol = .tcp,
    port: u16 = 5201,
    streams: usize = 1,
    time: usize = 10,
    interval: usize = 1,
    target_ip: ?[4]u8 = null,
    local_ip: [4]u8,
    interface: []const u8,
    mtu: u32 = 1500,
    packet_size: u32 = 0,
};

const MuxContext = union(enum) {
    server: *IperfServer,
    connection: *IperfConnection,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 0 }){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config = try parseArgs(args);
    std.debug.print("Starting iperf with config: {any}\n", .{config});

    global_stack = try ustack.init(allocator);
    global_af_packet = try AfPacket.init(allocator, &global_stack.cluster_pool, config.interface);

    std.debug.print("AF_PACKET initialized on {s}\n", .{config.interface});
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

    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_af_packet.fd, c.EV_READ);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.01, 0.01);
    my_ev_timer_start(loop, &timer_watcher);

    // Safety timeout to prevent hanging forever (only for client)
    var safety_timer = std.mem.zeroInit(c.ev_timer, .{});
    if (config.mode == .client) {
        my_ev_timer_init(&safety_timer, libev_safety_timeout_cb, @as(f64, @floatFromInt(config.time + 5)), 0.0);
        my_ev_timer_start(loop, &safety_timer);
    }

    const mux = try EventMultiplexer.init(allocator);
    global_mux = mux;
    var mux_io = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), c.EV_READ);
    my_ev_io_start(loop, &mux_io);

    if (config.mode == .server) {
        _ = try IperfServer.init(&global_stack, allocator, mux, config);
        std.debug.print("Iperf server listening on port {}\n", .{config.port});
    } else {
        const client = try IperfClient.init(&global_stack, allocator, mux, config);
        global_client = client;
        try client.start();
        std.debug.print("Iperf client connecting to {any} port {}\n", .{ config.target_ip.?, config.port });
    }

    my_ev_run(loop);
}

fn parseArgs(args: []const []const u8) !Config {
    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <ip/prefix> -s|-c <target_ip> [-u] [-p port] [-P streams] [-t time]\n", .{args[0]});
        std.process.exit(1);
    }

    const interface = args[1];
    var parts = std.mem.split(u8, args[2], "/");
    const local_ip = try parseIp(parts.first());

    var mode: ?Mode = null;
    var target_ip: ?[4]u8 = null;
    var protocol: Protocol = .tcp;
    var port: u16 = 5201;
    var streams: usize = 1;
    var time: usize = 10;
    var mtu: u32 = 1500;
    var packet_size: u32 = 0;

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-s")) {
            mode = .server;
        } else if (std.mem.eql(u8, args[i], "-c")) {
            mode = .client;
            i += 1;
            if (i >= args.len) return error.MissingTargetIp;
            target_ip = try parseIp(args[i]);
        } else if (std.mem.eql(u8, args[i], "-u")) {
            protocol = .udp;
        } else if (std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            if (i >= args.len) return error.MissingPort;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-P")) {
            i += 1;
            if (i >= args.len) return error.MissingStreams;
            streams = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-t")) {
            i += 1;
            if (i >= args.len) return error.MissingTime;
            time = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-m")) {
            i += 1;
            if (i >= args.len) return error.MissingMTU;
            mtu = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "-l")) {
            i += 1;
            if (i >= args.len) return error.MissingPacketSize;
            packet_size = try std.fmt.parseInt(u32, args[i], 10);
        }
    }

    if (mode == null) return error.MissingMode;
    if (mode == .client and target_ip == null) return error.MissingTargetIp;

    return .{
        .mode = mode.?,
        .protocol = protocol,
        .port = port,
        .streams = streams,
        .time = time,
        .local_ip = local_ip,
        .target_ip = target_ip,
        .interface = interface,
        .mtu = mtu,
        .packet_size = packet_size,
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

fn libev_af_packet_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    var budget: usize = 16; // Limit to 16 batches (64 packets each) per event loop iteration
    while (budget > 0) : (budget -= 1) {
        const ok = global_af_packet.readPacket() catch |err| {
            std.debug.print("AF_PACKET read error: {}\n", .{err});
            return;
        };
        if (!ok) break;
    }
}

fn libev_timer_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_stack.timer_queue.tick();
    if (global_server) |s| {
        s.report();
    }
    if (global_client) |c_ptr| {
        c_ptr.report();
    }
}

fn libev_safety_timeout_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    std.debug.print("Safety timeout reached, exiting\n", .{});
    std.process.exit(0);
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

const IperfServer = struct {
    listener: ustack.tcpip.Endpoint,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    conns: std.ArrayList(*IperfConnection),

    bytes_received: u64 = 0,
    packets_received: u64 = 0,
    last_report_time: i64 = 0,
    start_time: i64 = 0, // Added
    udp_start_time: i64 = 0,
    udp_session_active: bool = false,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, config: Config) !*IperfServer {
        const self = try allocator.create(IperfServer);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};

        const proto_num: u8 = if (config.protocol == .tcp) 6 else 17;
        const ep = try s.transport_protocols.get(proto_num).?.newEndpoint(s, 0x0800, wq);
        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = config.port });

        if (config.protocol == .tcp) {
            try ep.listen(128);
        }

        const now = std.time.milliTimestamp();
        self.* = .{
            .listener = ep,
            .allocator = allocator,
            .mux = mux,
            .config = config,
            .mux_ctx = .{ .server = self },
            .wait_entry = undefined,
            .last_report_time = now,
            .start_time = now,
            .conns = std.ArrayList(*IperfConnection).init(allocator),
        };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn);

        global_server = self;

        return self;
    }

    fn report(self: *IperfServer) void {
        if (self.config.protocol == .udp) return;
        const now = std.time.milliTimestamp();
        const elapsed = now - self.last_report_time;
        if (elapsed < 1000) return;

        var total_bytes_interval: u64 = 0;
        var total_packets_interval: u64 = 0;
        var active_conns: usize = 0;

        var i: usize = 0;
        while (i < self.conns.items.len) {
            const conn = self.conns.items[i];
            if (conn.closed) {
                _ = self.conns.swapRemove(i);
                // conn.wq is owned by the endpoint for server connections (accepted sockets)
                // so we should not destroy it here, as ep.close() (called in conn.close()) will trigger
                // TCPEndpoint.deinit which destroys the wq if owns_waiter_queue is true.
                self.allocator.destroy(conn);
                continue;
            }

            const bytes = conn.bytes_since_last_report;
            const packets = conn.packets_since_last_report;
            total_bytes_interval += bytes;
            total_packets_interval += packets;
            active_conns += 1;

            const seconds = @as(f64, @floatFromInt(elapsed)) / 1000.0;
            const mbps = (@as(f64, @floatFromInt(bytes)) * 8.0) / seconds / 1000000.0;
            const pps = @as(f64, @floatFromInt(packets)) / seconds;
            const start_sec = @as(f64, @floatFromInt(self.last_report_time - self.start_time)) / 1000.0;
            const end_sec = @as(f64, @floatFromInt(now - self.start_time)) / 1000.0;

            std.debug.print("[{d: >3}] {d: >5.2}-{d: >5.2} sec  {d: >6.2} MBytes  {d: >6.2} Mbits/sec  {d: >6.0} pps\n", .{ conn.id, start_sec, end_sec, @as(f64, @floatFromInt(bytes)) / 1024.0 / 1024.0, mbps, pps });

            conn.bytes_since_last_report = 0;
            conn.packets_since_last_report = 0;
            i += 1;
        }

        if (active_conns > 1) {
            const seconds = @as(f64, @floatFromInt(elapsed)) / 1000.0;
            const mbps = (@as(f64, @floatFromInt(total_bytes_interval)) * 8.0) / seconds / 1000000.0;
            const pps = @as(f64, @floatFromInt(total_packets_interval)) / seconds;
            const start_sec = @as(f64, @floatFromInt(self.last_report_time - self.start_time)) / 1000.0;
            const end_sec = @as(f64, @floatFromInt(now - self.start_time)) / 1000.0;

            std.debug.print("[SUM] {d: >5.2}-{d: >5.2} sec  {d: >6.2} MBytes  {d: >6.2} Mbits/sec  {d: >6.0} pps\n", .{ start_sec, end_sec, @as(f64, @floatFromInt(total_bytes_interval)) / 1024.0 / 1024.0, mbps, pps });
        }

        self.last_report_time = now;
    }

    fn onEvent(self: *IperfServer) void {
        if (self.config.protocol == .tcp) {
            while (true) {
                const res = self.listener.accept() catch |err| {
                    if (err == tcpip.Error.WouldBlock) return;
                    return;
                };
                std.debug.print("Accepted connection from {any}\n", .{res.ep.getRemoteAddress()});
                if (IperfConnection.init(self.allocator, res.ep, res.wq, self.mux, self.config)) |conn| {
                    conn.id = self.conns.items.len; // Assign ID based on count
                    self.conns.append(conn) catch {};
                    conn.onEvent();
                } else |err| {
                    std.debug.print("Failed to init connection: {}\n", .{err});
                }
            }
        } else {
            self.handleUdp();
        }
    }

    fn handleUdp(self: *IperfServer) void {
        while (true) {
            var remote_addr: tcpip.FullAddress = undefined;
            var buf = self.listener.read(&remote_addr) catch |err| {
                if (err == tcpip.Error.WouldBlock) return;
                return;
            };
            defer buf.deinit();

            const now = std.time.milliTimestamp();
            if (!self.udp_session_active) {
                self.udp_session_active = true;
                self.udp_start_time = now;
                self.last_report_time = now;
                std.debug.print("Accepted connection from {any}\n", .{remote_addr});
            }

            self.bytes_received += buf.size;
            self.packets_received += 1;
            const elapsed = now - self.last_report_time;
            if (elapsed >= 1000) {
                const seconds = @as(f64, @floatFromInt(elapsed)) / 1000.0;
                const bytes = @as(f64, @floatFromInt(self.bytes_received));
                const mbps = (bytes * 8.0) / seconds / 1000000.0;
                const pps = @as(f64, @floatFromInt(self.packets_received)) / seconds;

                const start_sec = @as(f64, @floatFromInt(self.last_report_time - self.udp_start_time)) / 1000.0;
                const end_sec = @as(f64, @floatFromInt(now - self.udp_start_time)) / 1000.0;

                std.debug.print("[  5] {d: >5.2}-{d: >5.2} sec  {d: >6.2} MBytes  {d: >6.2} Mbits/sec  {d: >6.0} pps\n", .{ start_sec, end_sec, bytes / 1024.0 / 1024.0, mbps, pps });

                self.bytes_received = 0;
                self.packets_received = 0;
                self.last_report_time = now;
            }
        }
    }
};

const IperfClient = struct {
    stack: *stack.Stack,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    config: Config,
    conns: std.ArrayList(*IperfConnection),

    last_report_time: i64 = 0,
    start_time: i64 = 0,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer, config: Config) !*IperfClient {
        const self = try allocator.create(IperfClient);
        const now = std.time.milliTimestamp();
        self.* = .{
            .stack = s,
            .allocator = allocator,
            .mux = mux,
            .config = config,
            .conns = std.ArrayList(*IperfConnection).init(allocator),
            .last_report_time = now,
            .start_time = now,
        };
        return self;
    }

    pub fn report(self: *IperfClient) void {
        const now = std.time.milliTimestamp();
        const elapsed = now - self.last_report_time;
        if (elapsed < 1000) return;

        var total_bytes_interval: u64 = 0;
        var total_packets_interval: u64 = 0;
        var active_conns: usize = 0;

        for (self.conns.items) |conn| {
            if (conn.closed) continue;

            const bytes = conn.bytes_since_last_report;
            const packets = conn.packets_since_last_report;
            total_bytes_interval += bytes;
            total_packets_interval += packets;
            active_conns += 1;

            const seconds = @as(f64, @floatFromInt(elapsed)) / 1000.0;
            const mbps = (@as(f64, @floatFromInt(bytes)) * 8.0) / seconds / 1000000.0;
            const pps = @as(f64, @floatFromInt(packets)) / seconds;
            const start_sec = @as(f64, @floatFromInt(self.last_report_time - self.start_time)) / 1000.0;
            const end_sec = @as(f64, @floatFromInt(now - self.start_time)) / 1000.0;

            std.debug.print("[{d: >3}] {d: >5.2}-{d: >5.2} sec  {d: >6.2} MBytes  {d: >6.2} Mbits/sec  {d: >6.0} pps\n", .{ conn.id, start_sec, end_sec, @as(f64, @floatFromInt(bytes)) / 1024.0 / 1024.0, mbps, pps });

            conn.bytes_since_last_report = 0;
            conn.packets_since_last_report = 0;
        }

        if (active_conns > 1) {
            const seconds = @as(f64, @floatFromInt(elapsed)) / 1000.0;
            const mbps = (@as(f64, @floatFromInt(total_bytes_interval)) * 8.0) / seconds / 1000000.0;
            const pps = @as(f64, @floatFromInt(total_packets_interval)) / seconds;
            const start_sec = @as(f64, @floatFromInt(self.last_report_time - self.start_time)) / 1000.0;
            const end_sec = @as(f64, @floatFromInt(now - self.start_time)) / 1000.0;

            std.debug.print("[SUM] {d: >5.2}-{d: >5.2} sec  {d: >6.2} MBytes  {d: >6.2} Mbits/sec  {d: >6.0} pps\n", .{ start_sec, end_sec, @as(f64, @floatFromInt(total_bytes_interval)) / 1024.0 / 1024.0, mbps, pps });
        }

        self.last_report_time = now;
    }

    pub fn start(self: *IperfClient) !void {
        for (0..self.config.streams) |i| {
            const wq = try self.allocator.create(waiter.Queue);
            wq.* = .{};
            const proto_num: u8 = if (self.config.protocol == .tcp) 6 else 17;
            const ep = try self.stack.transport_protocols.get(proto_num).?.newEndpoint(self.stack, 0x0800, wq);

            const conn = try IperfConnection.init(self.allocator, ep, wq, self.mux, self.config);
            conn.id = i;
            try self.conns.append(conn);

            if (self.config.protocol == .tcp) {
                wq.notify(waiter.EventOut);
            }

            try ep.bind(.{ .nic = 0, .addr = .{ .v4 = self.config.local_ip }, .port = 0 });
            _ = ep.connect(.{ .nic = 1, .addr = .{ .v4 = self.config.target_ip.? }, .port = self.config.port }) catch |err| {
                if (err != tcpip.Error.WouldBlock) return err;
            };

            if (self.config.protocol == .udp) {
                wq.notify(waiter.EventOut);
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
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    closed: bool = false,

    bytes_since_last_report: u64 = 0,
    packets_since_last_report: u64 = 0,
    total_bytes: u64 = 0,
    total_packets: u64 = 0,
    start_time: i64 = 0,
    last_report_time: i64 = 0,

    block_buffer: []u8,

    pub fn init(allocator: std.mem.Allocator, ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer, config: Config) !*IperfConnection {
        const self = try allocator.create(IperfConnection);
        const block_buffer = try allocator.alloc(u8, 128 * 1024);
        @memset(block_buffer, 'A');

        self.* = .{
            .ep = ep,
            .wq = wq,
            .allocator = allocator,
            .mux = mux,
            .config = config,
            .mux_ctx = .{ .connection = self },
            .wait_entry = undefined,
            .start_time = std.time.milliTimestamp(),
            .last_report_time = std.time.milliTimestamp(),
            .block_buffer = block_buffer,
        };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);

        var events: u16 = waiter.EventIn | waiter.EventHUp | waiter.EventErr;
        if (config.mode == .client) {
            events |= waiter.EventOut;
        }
        wq.eventRegister(&self.wait_entry, events);

        return self;
    }

    fn onEvent(self: *IperfConnection) void {
        if (self.closed) return;
        if (self.config.protocol == .tcp) {
            const tcp_ep = @as(*ustack.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.ep.ptr)));
            if (tcp_ep.state == .error_state) {
                std.debug.print("[{}] Connection error, closing\n", .{self.id});
                self.close();
                return;
            }
        }
        if (self.config.mode == .server) {
            self.handleServer();
        } else {
            self.handleClient();
        }
    }

    fn handleServer(self: *IperfConnection) void {
        var count: usize = 0;
        while (count < 256) : (count += 1) {
            var buf = self.ep.read(null) catch |err| {
                if (err == tcpip.Error.WouldBlock) return;
                std.debug.print("[{}] Server read error: {}\n", .{ self.id, err });
                self.close();
                return;
            };
            defer buf.deinit();
            if (buf.size == 0) {
                const now = std.time.milliTimestamp();
                const total_elapsed = now - self.start_time;
                const total_seconds = @as(f64, @floatFromInt(total_elapsed)) / 1000.0;
                const total_mbps = (@as(f64, @floatFromInt(self.total_bytes)) * 8.0) / total_seconds / 1000000.0;
                std.debug.print("[{d: >3}]  0.00-{d: >5.2} sec  {d: >6.2} MBytes  {d: >6.2} Mbits/sec  receiver\n", .{ self.id, total_seconds, @as(f64, @floatFromInt(self.total_bytes)) / 1024.0 / 1024.0, total_mbps });

                self.close();

                if (global_server) |s| {
                    var all_closed = true;
                    var total_all: u64 = 0;
                    var max_time: i64 = 0;
                    for (s.conns.items) |c_ptr| {
                        if (!c_ptr.closed) all_closed = false;
                        total_all += c_ptr.total_bytes;
                        const t = now - c_ptr.start_time;
                        if (t > max_time) max_time = t;
                    }
                    if (all_closed and s.conns.items.len > 1) {
                        const sum_seconds = @as(f64, @floatFromInt(max_time)) / 1000.0;
                        const sum_mbps = (@as(f64, @floatFromInt(total_all)) * 8.0) / sum_seconds / 1000000.0;
                        std.debug.print("[SUM]  0.00-{d: >5.2} sec  {d: >6.2} MBytes  {d: >6.2} Mbits/sec  receiver\n", .{ sum_seconds, @as(f64, @floatFromInt(total_all)) / 1024.0 / 1024.0, sum_mbps });
                    }
                }
                return;
            }
            self.bytes_since_last_report += buf.size;
            self.packets_since_last_report += 1;
            self.total_bytes += buf.size;
            self.total_packets += 1;
        }

        if (global_mux) |mux| {
            _ = mux.ready_queue.push(&self.wait_entry) catch false;
            const val: u64 = 1;
            _ = std.posix.write(mux.signal_fd, std.mem.asBytes(&val)) catch {};
        }
    }

    fn handleClient(self: *IperfConnection) void {
        if (self.config.protocol == .tcp) {
            const tcp_ep = @as(*ustack.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.ep.ptr)));
            if (tcp_ep.state != .established) return;
        }

        var send_len = self.block_buffer.len;
        if (self.config.packet_size > 0) {
            send_len = @min(self.config.packet_size, self.block_buffer.len);
        } else if (self.config.protocol == .udp) {
            send_len = @min(self.config.mtu - 28, self.block_buffer.len);
        }

        var count: usize = 0;
        while (count < 256) : (count += 1) {
            var iovecs: [128]std.posix.iovec = undefined;
            var iov_count: usize = 0;

            if (self.config.protocol == .udp) {
                iovecs[0] = .{
                    .base = self.block_buffer.ptr,
                    .len = send_len,
                };
                iov_count = 1;
            } else {
                // Using writev with multiple large iovecs (8KB each) to test regrouping performance with jumbo frames.
                const chunk_size = 8192;
                const num_chunks = (send_len + chunk_size - 1) / chunk_size;
                iov_count = @min(num_chunks, iovecs.len);

                for (0..iov_count) |i| {
                    const offset = i * chunk_size;
                    const len = @min(chunk_size, send_len - offset);
                    iovecs[i] = .{
                        .base = self.block_buffer[offset..].ptr,
                        .len = len,
                    };
                }
            }

            var uio = buffer.Uio.init(@as([]const []u8, @ptrCast(iovecs[0..iov_count])));
            const n = self.ep.writev(&uio, .{}) catch |err| {
                if (err == tcpip.Error.WouldBlock) {
                    // Re-queue to retry in the next iteration
                    if (global_mux) |mux| {
                        _ = mux.ready_queue.push(&self.wait_entry) catch false;
                        const val: u64 = 1;
                        _ = std.posix.write(mux.signal_fd, std.mem.asBytes(&val)) catch {};
                    }
                    return;
                }
                std.debug.print("[{}] Client write error: {}\n", .{ self.id, err });
                self.close();
                return;
            };
            self.bytes_since_last_report += n;
            self.packets_since_last_report += 1;
            self.total_bytes += n;
            self.total_packets += 1;

            if (std.time.milliTimestamp() - self.start_time > self.config.time * 1000) {
                self.close();
                if (global_client) |c_ptr| {
                    var all_closed = true;
                    var total_all: u64 = 0;
                    for (c_ptr.conns.items) |conn| {
                        if (!conn.closed) {
                            all_closed = false;
                        }
                        total_all += conn.total_bytes;
                    }
                    if (all_closed) {
                        const total_elapsed = std.time.milliTimestamp() - c_ptr.start_time;
                        const total_seconds = @as(f64, @floatFromInt(total_elapsed)) / 1000.0;
                        const total_mbps = (@as(f64, @floatFromInt(total_all)) * 8.0) / total_seconds / 1000000.0;
                        std.debug.print("[SUM]  0.00-{d: >5.2} sec  {d: >6.2} MBytes  {d: >6.2} Mbits/sec  sender\n", .{ total_seconds, @as(f64, @floatFromInt(total_all)) / 1024.0 / 1024.0, total_mbps });
                        std.debug.print("Test finished. Total: {} bytes\n", .{total_all});
                        std.process.exit(0);
                    }
                } else {
                    std.process.exit(0);
                }
                return;
            }
        }

        if (global_mux) |mux| {
            _ = mux.ready_queue.push(&self.wait_entry) catch false;
            const val: u64 = 1;
            _ = std.posix.write(mux.signal_fd, std.mem.asBytes(&val)) catch {};
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
