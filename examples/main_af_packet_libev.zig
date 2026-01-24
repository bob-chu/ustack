const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const AfPacket = ustack.drivers.af_packet.AfPacket;
const EventMultiplexer = @import("../src/event_mux.zig").EventMultiplexer;

var global_stack: stack.Stack = undefined;
var global_af_packet: AfPacket = undefined;
var global_eth: ustack.link.eth.EthernetEndpoint = undefined;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <mode> <ip_address/cidr> [target_ip]\n", .{args[0]});
        std.debug.print("  mode: server | client\n", .{});
        std.debug.print("  Example Server: {s} veth0 server 10.0.0.1/24\n", .{args[0]});
        std.debug.print("  Example Client: {s} veth1 client 10.0.0.2/24 10.0.0.1\n", .{args[0]});
        return;
    }

    const ifname = args[1];
    const mode = args[2];
    const ip_cidr = args[3];

    global_stack = try ustack.init(allocator);
    
    global_af_packet = try AfPacket.init(ifname);
    
    // Wrap in EthernetEndpoint so ustack handles Ethernet headers
    global_eth = ustack.link.eth.EthernetEndpoint.init(global_af_packet.linkEndpoint(), global_af_packet.address);
    try global_stack.createNIC(1, global_eth.linkEndpoint());
    
    var parts = std.mem.split(u8, ip_cidr, "/");
    const ip_str = parts.first();
    const prefix_str = parts.next() orelse "24";
    
    const addr_v4 = try parseIp(ip_str);
    const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);

    const nic = global_stack.nics.get(1).?;
    
    try nic.addAddress(.{
        .protocol = 0x0806, // ARP
        .address_with_prefix = .{
            .address = .{ .v4 = .{ 0, 0, 0, 0 } },
            .prefix_len = 0,
        }
    });

    try nic.addAddress(.{
        .protocol = 0x0800,
        .address_with_prefix = .{
            .address = .{ .v4 = addr_v4 },
            .prefix_len = prefix_len,
        }
    });

    try global_stack.addRoute(.{
        .destination = .{ .address = .{ .v4 = addr_v4 }, .prefix = prefix_len },
        .gateway = .{ .v4 = .{ 0, 0, 0, 0 } },
        .nic = 1,
        .mtu = 1500,
    });
    
    try global_stack.addRoute(.{
        .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
        .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, // Usually gateway IP but here we are on same L2
        .nic = 1,
        .mtu = 1500,
    });

    std.debug.print("AF_PACKET: Interface {s} up with IP {s}/{d}\n", .{ifname, ip_str, prefix_len});

    const loop = my_ev_default_loop();
    var io_watcher: ev_io = undefined;
    var timer_watcher: ev_timer = undefined;

    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_af_packet.fd, EV_READ);
    my_ev_io_start(loop, &io_watcher);

    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.01, 0.01);
    my_ev_timer_start(loop, &timer_watcher);

    if (std.mem.eql(u8, mode, "server")) {
        try runServer(&global_stack, loop);
    } else if (std.mem.eql(u8, mode, "client")) {
        if (args.len < 5) {
            std.debug.print("Client mode requires target IP\n", .{});
            return;
        }
        const target_ip = try parseIp(args[4]);
        try runClient(&global_stack, loop, target_ip, addr_v4);
    } else {
        std.debug.print("Unknown mode: {s}\n", .{mode});
    }
}

// Libev C bindings (from wrapper.c)
extern fn my_ev_default_loop() ?*anyopaque;
extern fn my_ev_io_init(w: *ev_io, cb: *const fn (?*anyopaque, *ev_io, i32) callconv(.C) void, fd: i32, events: i32) void;
extern fn my_ev_timer_init(w: *ev_timer, cb: *const fn (?*anyopaque, *ev_timer, i32) callconv(.C) void, after: f64, repeat: f64) void;
extern fn my_ev_io_start(loop: ?*anyopaque, w: *ev_io) void;
extern fn my_ev_timer_start(loop: ?*anyopaque, w: *ev_timer) void;
extern fn my_ev_run(loop: ?*anyopaque) void;

const EV_READ = 1;
const ev_io = extern struct {
    active: i32,
    next: i32,
    priority: i32,
    cb: *const fn (?*anyopaque, *ev_io, i32) callconv(.C) void,
    fd: i32,
    events: i32,
};
const ev_timer = extern struct {
    active: i32,
    next: i32,
    priority: i32,
    cb: *const fn (?*anyopaque, *ev_timer, i32) callconv(.C) void,
    at: f64,
    repeat: f64,
};

fn libev_af_packet_cb(loop: ?*anyopaque, watcher: *ev_io, revents: i32) callconv(.C) void {
    _ = loop; _ = watcher; _ = revents;
    global_af_packet.readPacket() catch |err| {
        std.debug.print("AF_PACKET read error: {}\n", .{err});
    };
}

fn libev_timer_cb(loop: ?*anyopaque, watcher: *ev_timer, revents: i32) callconv(.C) void {
    _ = loop; _ = watcher; _ = revents;
    _ = global_stack.timer_queue.tick();
}

var global_mux: ?*EventMultiplexer = null;

fn libev_mux_cb(loop: ?*anyopaque, watcher: *ev_io, revents: i32) callconv(.C) void {
    _ = loop; _ = watcher; _ = revents;
    if (global_mux) |mux| {
        const ready = mux.pollReady() catch return;
        defer mux.allocator.free(ready);
        for (ready) |entry| {
            // Trigger the callback associated with the entry
            if (entry.callback) |cb| {
                cb(entry);
            }
        }
    }
}

var mode_str: []const u8 = "";

// Server Implementation
const HttpServer = struct {
    stack_ref: *stack.Stack,
    allocator: std.mem.Allocator,
    listener: ustack.tcpip.Endpoint,
    mux: *EventMultiplexer,
    wait_entry: waiter.Entry,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*HttpServer {
        const self = try allocator.create(HttpServer);
        
        const tcp_proto = s.transport_protocols.get(6).?;
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        
        const ep = try tcp_proto.newEndpoint(s, 0x0800, wq);
        
        const local = tcpip.FullAddress{
            .nic = 0,
            .addr = .{ .v4 = .{ 0, 0, 0, 0 } },
            .port = 80,
        };
        try ep.bind(local);
        try ep.listen(10);
        
        self.* = .{
            .stack_ref = s,
            .allocator = allocator,
            .listener = ep,
            .mux = mux,
            .wait_entry = undefined,
        };
        
        self.wait_entry = waiter.Entry.init(mux, EventMultiplexer.upcall);
        self.wait_entry.context = self;
        // Override callback for multiplexing
        self.wait_entry.callback = onAccept;

        wq.eventRegister(&self.wait_entry, waiter.EventIn);
        
        return self;
    }

    fn onAccept(entry: *waiter.Entry) void {
        const self = @as(*HttpServer, @ptrCast(@alignCast(entry.context.?)));
        while (true) {
            const res = self.listener.accept() catch |err| {
                if (err == tcpip.Error.WouldBlock) return;
                std.debug.print("Accept error: {}\n", .{err});
                return;
            };
            
            std.debug.print("Accepted connection from {any}\n", .{res.ep.getRemoteAddress()});
            
            const conn = Connection.init(self.allocator, res.ep, res.wq, self.mux) catch continue;
            _ = conn;
        }
    }
};

const Connection = struct {
    allocator: std.mem.Allocator,
    ep: ustack.tcpip.Endpoint,
    wq: *waiter.Queue,
    wait_entry: waiter.Entry,
    mux: *EventMultiplexer,

    pub fn init(allocator: std.mem.Allocator, ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{
            .allocator = allocator,
            .ep = ep,
            .wq = wq,
            .wait_entry = undefined,
            .mux = mux,
        };
        self.wait_entry = waiter.Entry.init(mux, EventMultiplexer.upcall);
        self.wait_entry.context = self;
        self.wait_entry.callback = onData;

        wq.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventHUp | waiter.EventErr);
        return self;
    }

    fn onData(entry: *waiter.Entry) void {
        const self = @as(*Connection, @ptrCast(@alignCast(entry.context.?)));
        
        const buf = self.ep.read(null) catch |err| {
            if (err == tcpip.Error.WouldBlock) return;
            self.close();
            return;
        };
        
        if (buf.len == 0) {
            self.allocator.free(buf);
            self.close();
            return;
        }
        
        std.debug.print("Server received {} bytes\n", .{buf.len});
        
        const response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello World!\n";
        
        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader {
                return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
            }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
            }
        };
        var p = Payloader{ .data = response };
        _ = self.ep.write(p.payloader(), .{}) catch {};
        
        self.allocator.free(buf);
        self.close();
    }

    fn close(self: *Connection) void {
        std.debug.print("Closing connection\n", .{});
        self.wq.eventUnregister(&self.wait_entry);
        self.ep.close();
        self.allocator.destroy(self.wq); // We own the queue from accept
        self.allocator.destroy(self);
    }
};

fn runServer(s: *stack.Stack, loop: ?*anyopaque) !void {
    std.debug.print("Starting HTTP Server on port 80...\n", .{});
    
    const mux = try EventMultiplexer.init(s.allocator);
    global_mux = mux;

    // Register Mux FD
    var mux_io: ev_io = undefined;
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), EV_READ);
    my_ev_io_start(loop, &mux_io);
    
    const server = try HttpServer.init(s, s.allocator, mux);
    _ = server;

    my_ev_run(loop);
}

// Client Implementation
const HttpClient = struct {
    ep: ustack.tcpip.Endpoint,
    wq: *waiter.Queue,
    wait_entry: waiter.Entry,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    state: enum { connecting, sending, receiving, closed } = .connecting,
    
    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*HttpClient {
        const self = try allocator.create(HttpClient);
        const tcp_proto = s.transport_protocols.get(6).?;
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try tcp_proto.newEndpoint(s, 0x0800, wq);
        
        self.* = .{
            .ep = ep,
            .wq = wq,
            .wait_entry = undefined,
            .allocator = allocator,
            .mux = mux,
        };
        
        self.wait_entry = waiter.Entry.init(mux, EventMultiplexer.upcall);
        self.wait_entry.context = self;
        self.wait_entry.callback = onEvent;

        wq.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventErr);
        
        return self;
    }
    
    pub fn connect(self: *HttpClient, target: [4]u8, local_ip: [4]u8) !void {
        // Must bind first to have a local address for TCP state machine
        const local = tcpip.FullAddress{
            .nic = 0,
            .addr = .{ .v4 = local_ip },
            .port = 0,
        };
        try self.ep.bind(local);

        const remote = tcpip.FullAddress{
            .nic = 1,
            .addr = .{ .v4 = target },
            .port = 80,
        };
        _ = self.ep.connect(remote) catch |err| {
            if (err == tcpip.Error.WouldBlock) {
                // This is expected if ARP is needed
                return;
            }
            return err;
        };
    }
    
    fn onEvent(entry: *waiter.Entry) void {
        const self = @as(*HttpClient, @ptrCast(@alignCast(entry.context.?)));
        
        switch (self.state) {
            .connecting => {
                std.debug.print("Client connected!\n", .{});
                self.state = .sending;
                self.sendRequest();
            },
            .sending => {
                // If we got here, it means we are writable
                self.sendRequest();
            },
            .receiving => {
                while (true) {
                    const buf = self.ep.read(null) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        std.debug.print("Client read error: {}\n", .{err});
                        self.state = .closed;
                        return;
                    };
                    defer self.allocator.free(buf);
                    
                    if (buf.len == 0) {
                        std.debug.print("Client received EOF\n", .{});
                        self.state = .closed;
                        std.process.exit(0);
                    }
                    std.debug.print("Client received: {s}\n", .{buf});
                }
            },
            .closed => {},
        }
    }
    
    fn sendRequest(self: *HttpClient) void {
        const req = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader {
                return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
            }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
            }
        };
        var p = Payloader{ .data = req };
        
        _ = self.ep.write(p.payloader(), .{}) catch |err| {
            if (err == tcpip.Error.WouldBlock) {
                 self.state = .sending;
                 return;
            }
            std.debug.print("Write error: {}\n", .{err});
            return;
        };
        self.state = .receiving;
    }
};

fn runClient(s: *stack.Stack, loop: ?*anyopaque, target_ip: [4]u8, local_ip: [4]u8) !void {
    std.debug.print("Starting HTTP Client connecting to {d}.{d}.{d}.{d}...\n", .{target_ip[0], target_ip[1], target_ip[2], target_ip[3]});
    
    const mux = try EventMultiplexer.init(s.allocator);
    global_mux = mux;

    // Register Mux FD
    var mux_io: ev_io = undefined;
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), EV_READ);
    my_ev_io_start(loop, &mux_io);
    
    const client = try HttpClient.init(s, s.allocator, mux);
    try client.connect(target_ip, local_ip);
    
    my_ev_run(loop);
}

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |i| {
        const part = it.next() orelse return error.InvalidIP;
        out[i] = try std.fmt.parseInt(u8, part, 10);
    }
    return out;
}
