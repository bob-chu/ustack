const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const AfXdp = ustack.drivers.af_xdp.AfXdp;
const EventMultiplexer = ustack.event_mux.EventMultiplexer;

const c = @cImport({
    @cInclude("ev.h");
});

var global_stack: stack.Stack = undefined;
var global_af_xdp: AfXdp = undefined;
var global_eth: ustack.link.eth.EthernetEndpoint = undefined;
var global_mux: ?*EventMultiplexer = null;
var global_benchmark: Benchmark = undefined;
var global_io_watcher: c.ev_io = undefined;
var global_timer_watcher: c.ev_timer = undefined;
var global_mux_io: c.ev_io = undefined;

const MuxContext = union(enum) {
    server: *HttpServer,
    client: *HttpClient,
    connection: *Connection,
};

const AppEntry = struct {
    wait_entry: waiter.Entry,
    ctx: MuxContext,
};

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <mode> <ip_address/cidr> [target_ip]\n", .{args[0]});
        return;
    }

    const ifname = args[1];
    const mode = args[2];
    const ip_cidr = args[3];

    global_stack = try ustack.init(allocator);

    // Initialize AF_XDP (queue 0)
    global_af_xdp = try AfXdp.init(allocator, &global_stack.cluster_pool, ifname, 0);

    global_eth = ustack.link.eth.EthernetEndpoint.init(global_af_xdp.linkEndpoint(), global_af_xdp.address);
    try global_stack.createNIC(1, global_eth.linkEndpoint());

    var parts = std.mem.split(u8, ip_cidr, "/");
    const ip_str = parts.first();
    const prefix_len = try std.fmt.parseInt(u8, parts.next() orelse "24", 10);
    const addr_v4 = try parseIp(ip_str);

    const nic = global_stack.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0806, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = addr_v4 }, .prefix_len = prefix_len } });

    try global_stack.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = 1500 });

    const loop = my_ev_default_loop();

    my_ev_io_init(&global_io_watcher, libev_af_xdp_cb, global_af_xdp.fd, 0x01);
    my_ev_io_start(loop, &global_io_watcher);

    my_ev_timer_init(&global_timer_watcher, libev_timer_cb, 0.001, 0.001);
    my_ev_timer_start(loop, &global_timer_watcher);

    const mux = try EventMultiplexer.init(allocator);
    global_mux = mux;
    my_ev_io_init(&global_mux_io, libev_mux_cb, mux.fd(), 0x01);
    my_ev_io_start(loop, &global_mux_io);

    if (std.mem.eql(u8, mode, "server")) {
        _ = try HttpServer.init(&global_stack, allocator, mux);
    } else {
        const target_ip = try parseIp(args[4]);
        global_benchmark = .{ .allocator = allocator, .stack = &global_stack, .mux = mux, .target_ip = target_ip, .local_ip = addr_v4, .start_time = std.time.milliTimestamp() };
        global_benchmark.start();
    }

    my_ev_run(loop);
}

fn libev_af_xdp_cb(_: ?*anyopaque, _: *c.ev_io, _: i32) callconv(.C) void {
    global_af_xdp.poll() catch {};
    global_stack.flush();
}

fn libev_timer_cb(_: ?*anyopaque, _: *c.ev_timer, _: i32) callconv(.C) void {
    _ = global_stack.timer_queue.tick();
    global_af_xdp.poll() catch {};
    global_stack.flush();
}

fn libev_mux_cb(_: ?*anyopaque, _: *c.ev_io, _: i32) callconv(.C) void {
    if (global_mux) |mux| {
        const ready = mux.pollReady() catch return;
        for (ready) |entry| {
            const app_entry: *AppEntry = @fieldParentPtr("wait_entry", entry);
            switch (app_entry.ctx) {
                .server => |s| s.onAccept(),
                .client => |client| client.onEvent(),
                .connection => |conn| conn.onData(),
            }
        }
    }
}

const Benchmark = struct {
    allocator: std.mem.Allocator, stack: *stack.Stack, mux: *EventMultiplexer, target_ip: [4]u8, local_ip: [4]u8,
    total_target: usize = 100, concurrency_target: usize = 10, active_count: usize = 0, completed_count: usize = 0, failed_count: usize = 0, start_time: i64 = 0,

    pub fn start(self: *Benchmark) void { self.spawnBatch(); }
    fn spawnBatch(self: *Benchmark) void {
        while (self.active_count < self.concurrency_target and self.completed_count + self.active_count < self.total_target) {
            self.spawnOne() catch break;
        }
    }
    fn spawnOne(self: *Benchmark) !void {
        const client = try HttpClient.init(self.stack, self.allocator, self.mux);
        client.benchmark_ref = self;
        try client.connect(self.target_ip, self.local_ip);
        self.active_count += 1;
    }
    pub fn onClientDone(self: *Benchmark, success: bool) void {
        self.active_count -= 1;
        if (success) self.completed_count += 1 else self.failed_count += 1;
        if (self.completed_count + self.failed_count >= self.total_target) {
            std.debug.print("Benchmark Complete! Success: {}, Failed: {}\n", .{ self.completed_count, self.failed_count });
            std.process.exit(0);
        } else self.spawnBatch();
    }
};

const HttpClient = struct {
    ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, allocator: std.mem.Allocator, app_entry: AppEntry, benchmark_ref: ?*Benchmark = null, state: enum { connecting, sending, receiving, closed } = .connecting,
    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*HttpClient {
        const self = try allocator.create(HttpClient);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(6).?.newEndpoint(s, 0x0800, wq);
        self.* = .{ .ep = ep, .wq = wq, .allocator = allocator, .app_entry = .{ .wait_entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall), .ctx = .{ .client = self } } };
        wq.eventRegister(&self.app_entry.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventErr);
        return self;
    }
    pub fn connect(self: *HttpClient, target: [4]u8, local: [4]u8) !void {
        try self.ep.bind(.{ .nic = 0, .addr = .{ .v4 = local }, .port = 0 });
        _ = self.ep.connect(.{ .nic = 1, .addr = .{ .v4 = target }, .port = 80 }) catch |err| { if (err == tcpip.Error.WouldBlock) return; return err; };
    }
    fn onEvent(self: *HttpClient) void {
        const tcp_ep = @as(*ustack.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.ep.ptr)));
        if (self.state == .connecting and tcp_ep.state == .established) { self.state = .sending; self.sendRequest(); }
        else if (self.state == .receiving) {
            while (true) {
                var buf = self.ep.read(null) catch |err| { if (err == tcpip.Error.WouldBlock) break; self.finish(false); return; };
                defer buf.deinit();
                if (buf.size == 0) { self.finish(true); return; }
            }
        }
    }
    fn sendRequest(self: *HttpClient) void {
        const req = "GET / HTTP/1.1\r\n\r\n";
        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader { return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } }; }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 { return @as(*@This(), @ptrCast(@alignCast(ptr))).data; }
        };
        var p = Payloader{ .data = req };
        _ = self.ep.write(p.payloader(), .{}) catch |err| { if (err == tcpip.Error.WouldBlock) return; self.finish(false); return; };
        self.state = .receiving;
    }
    fn finish(self: *HttpClient, success: bool) void {
        if (self.state == .closed) return;
        self.state = .closed;
        self.wq.eventUnregister(&self.app_entry.wait_entry);
        self.ep.close();
        if (self.benchmark_ref) |bench| bench.onClientDone(success);
    }
};

const HttpServer = struct {
    listener: ustack.tcpip.Endpoint, allocator: std.mem.Allocator, mux: *EventMultiplexer, app_entry: AppEntry,
    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*HttpServer {
        const self = try allocator.create(HttpServer);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(6).?.newEndpoint(s, 0x0800, wq);
        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 80 });
        try ep.listen(128);
        self.* = .{ .listener = ep, .allocator = allocator, .mux = mux, .app_entry = .{ .wait_entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall), .ctx = .{ .server = self } } };
        wq.eventRegister(&self.app_entry.wait_entry, waiter.EventIn);
        return self;
    }
    fn onAccept(self: *HttpServer) void {
        while (true) {
            const res = self.listener.accept() catch |err| { if (err == tcpip.Error.WouldBlock) return; return; };
            _ = Connection.init(self.allocator, res.ep, res.wq, self.mux) catch continue;
        }
    }
};

const Connection = struct {
    ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, allocator: std.mem.Allocator, app_entry: AppEntry,
    pub fn init(allocator: std.mem.Allocator, ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{ .ep = ep, .wq = wq, .allocator = allocator, .app_entry = .{ .wait_entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall), .ctx = .{ .connection = self } } };
        wq.eventRegister(&self.app_entry.wait_entry, waiter.EventIn | waiter.EventHUp | waiter.EventErr);
        return self;
    }
    fn onData(self: *Connection) void {
        var buf = self.ep.read(null) catch |err| { if (err == tcpip.Error.WouldBlock) return; self.close(); return; };
        defer buf.deinit();
        if (buf.size == 0) { self.close(); return; }
        const resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader { return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } }; }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 { return @as(*@This(), @ptrCast(@alignCast(ptr))).data; }
        };
        var p = Payloader{ .data = resp };
        _ = self.ep.write(p.payloader(), .{}) catch {};
        self.close();
    }
    fn close(self: *Connection) void { self.wq.eventUnregister(&self.app_entry.wait_entry); self.ep.close(); }
};

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |i| out[i] = try std.fmt.parseInt(u8, it.next() orelse "0", 10);
    return out;
}

extern fn my_ev_default_loop() ?*anyopaque;
extern fn my_ev_io_init(w: *c.ev_io, cb: *const fn (?*anyopaque, *c.ev_io, i32) callconv(.C) void, fd: i32, events: i32) void;
extern fn my_ev_timer_init(w: *c.ev_timer, cb: *const fn (?*anyopaque, *c.ev_timer, i32) callconv(.C) void, after: f64, repeat: f64) void;
extern fn my_ev_io_start(loop: ?*anyopaque, w: *c.ev_io) void;
extern fn my_ev_timer_start(loop: ?*anyopaque, w: *c.ev_timer) void;
extern fn my_ev_run(loop: ?*anyopaque) void;
extern fn my_ev_break(loop: ?*anyopaque, how: i32) void;
