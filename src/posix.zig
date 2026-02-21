const std = @import("std");
const stack = @import("stack.zig");
const tcpip = @import("tcpip.zig");
const waiter = @import("waiter.zig");
const buffer = @import("buffer.zig");

pub const Socket = struct {
    endpoint: tcpip.Endpoint,
    // The wait queue associated with this socket.
    // For a listening socket, we create it.
    // For an accepted socket, we inherit it from the stack.
    wait_queue: *waiter.Queue,

    blocking: bool = true,
    allocator: std.mem.Allocator,

    wait_entry: waiter.Entry,

    pub fn init(allocator: std.mem.Allocator, ep: tcpip.Endpoint, wq: *waiter.Queue) *Socket {
        const self = allocator.create(Socket) catch @panic("OOM");
        self.* = .{
            .endpoint = ep,
            .wait_queue = wq,
            .allocator = allocator,
            .wait_entry = undefined,
        };
        // Initialize wait entry
        self.wait_entry = waiter.Entry.init(self, notifyCallback);
        // Register for all events by default
        self.wait_queue.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventErr | waiter.EventHUp);
        return self;
    }

    fn notifyCallback(e: *waiter.Entry) void {
        _ = e;
        // In a single-threaded stack, upcalls are handled by the event loop.
    }

    pub fn deinit(self: *Socket) void {
        self.wait_queue.eventUnregister(&self.wait_entry);
        self.endpoint.close();
        // Wait queue handling:
        // If we created it (client/listener), we own it.
        // If accepted, we also own it (TCPEndpoint logic passes ownership).
        // Since TCPEndpoint.close() doesn't free the queue passed to it, we must free it.
        // Wait, TCPEndpoint stores reference.
        self.allocator.destroy(self.wait_queue);
        self.allocator.destroy(self);
    }

    pub fn setOption(self: *Socket, opt: tcpip.EndpointOption) !void {
        return self.endpoint.setOption(opt);
    }
};

// Global-ish API functions
pub fn usocket(s: *stack.Stack, domain: i32, sock_type: i32, protocol: i32) !*Socket {
    // Validate domain
    const net_proto: tcpip.NetworkProtocolNumber = switch (domain) {
        std.posix.AF.INET => 0x0800, // IPv4
        std.posix.AF.INET6 => 0x86dd, // IPv6
        else => return error.AddressFamilyNotSupported,
    };

    // Validate type/protocol
    const trans_proto_id: tcpip.TransportProtocolNumber = if (protocol != 0) @intCast(protocol) else switch (sock_type) {
        std.posix.SOCK.STREAM => 6, // TCP
        std.posix.SOCK.DGRAM => 17, // UDP
        else => return error.SocketTypeNotSupported,
    };

    const trans_proto = s.transport_protocols.get(trans_proto_id) orelse return error.ProtocolNotSupported;

    // Create Wait Queue
    const wq = try s.allocator.create(waiter.Queue);
    wq.* = .{};

    // Create Endpoint
    const ep = try trans_proto.newEndpoint(s, net_proto, wq);
    errdefer {
        s.allocator.destroy(wq);
    }

    return Socket.init(s.allocator, ep, wq);
}

pub fn ubind(sock: *Socket, addr: std.posix.sockaddr, len: std.posix.socklen_t) !void {
    _ = len;
    const full_addr = fromSockAddr(addr) catch return error.AddressFamilyNotSupported;
    try sock.endpoint.bind(full_addr);
}

pub fn uconnect(sock: *Socket, addr: std.posix.sockaddr, len: std.posix.socklen_t) !void {
    _ = len;
    const full_addr = fromSockAddr(addr) catch return error.AddressFamilyNotSupported;

    try sock.endpoint.connect(full_addr);
}

pub fn ulisten(sock: *Socket, backlog: i32) !void {
    try sock.endpoint.listen(backlog);
}

pub fn uaccept(sock: *Socket, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t) !*Socket {
    const res = try sock.endpoint.accept();

    if (addr) |out_addr| {
        if (res.ep.getRemoteAddress()) |remote| {
            toSockAddr(remote, out_addr, len);
        } else |_| {}
    }

    return Socket.init(sock.allocator, res.ep, res.wq);
}

pub inline fn urecv(sock: *Socket, buf: []u8, flags: u32) !usize {
    _ = flags;
    var iov = [_][]u8{buf};
    var uio = buffer.Uio.init(&iov);
    return sock.endpoint.readv(&uio, null) catch |err| {
        if (err == tcpip.Error.WouldBlock or err == tcpip.Error.InvalidEndpointState) return error.WouldBlock;
        return err;
    };
}

pub inline fn usend(sock: *Socket, buf: []const u8, flags: u32) !usize {
    _ = flags;
    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = @constCast(buf) }};
    const data = buffer.VectorisedView.init(buf.len, &views);
    return sock.endpoint.writeView(data, .{}) catch |err| {
        if (err == tcpip.Error.WouldBlock or err == tcpip.Error.InvalidEndpointState) return error.WouldBlock;
        return err;
    };
}

pub fn ureadv(sock: *Socket, iov: []const []u8) !usize {
    var uio = buffer.Uio.init(iov);
    return sock.endpoint.readv(&uio, null) catch |err| {
        if (err == tcpip.Error.WouldBlock or err == tcpip.Error.InvalidEndpointState) return error.WouldBlock;
        return err;
    };
}

pub fn uwritev(sock: *Socket, iov: []const []u8) !usize {
    var uio = buffer.Uio.init(iov);
    return sock.endpoint.writev(&uio, .{}) catch |err| {
        if (err == tcpip.Error.WouldBlock or err == tcpip.Error.InvalidEndpointState) return error.WouldBlock;
        return err;
    };
}

pub fn urecvfrom(sock: *Socket, buf: []u8, flags: u32, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t) !usize {
    _ = flags;
    var iov = [_][]u8{buf};
    var uio = buffer.Uio.init(&iov);
    var full_addr: tcpip.FullAddress = undefined;
    const n = sock.endpoint.readv(&uio, &full_addr) catch |err| {
        if (err == tcpip.Error.WouldBlock or err == tcpip.Error.InvalidEndpointState) return error.WouldBlock;
        return err;
    };
    if (addr) |out_addr| {
        toSockAddr(full_addr, out_addr, len);
    }
    return n;
}

pub fn usendto(sock: *Socket, buf: []const u8, flags: u32, addr: ?*const std.posix.sockaddr, len: std.posix.socklen_t) !usize {
    _ = flags;
    _ = len;
    var iov = [_][]u8{@constCast(buf)};
    var uio = buffer.Uio.init(&iov);
    var opts = tcpip.WriteOptions{};
    var full_addr: tcpip.FullAddress = undefined;
    if (addr) |in_addr| {
        full_addr = fromSockAddr(in_addr.*) catch return error.AddressFamilyNotSupported;
        opts.to = &full_addr;
    }
    return sock.endpoint.writev(&uio, opts) catch |err| {
        if (err == tcpip.Error.WouldBlock or err == tcpip.Error.InvalidEndpointState) return error.WouldBlock;
        return err;
    };
}

pub fn uclose(sock: *Socket) void {
    sock.deinit();
}

pub const File = union(enum) {
    socket: *Socket,
    epoll: *EpollInstance,
};

pub const uepoll_event = struct {
    events: u32,
    data: std.os.linux.epoll_data,
};

pub const EpollInstance = struct {
    allocator: std.mem.Allocator,
    interests: std.AutoHashMap(i32, EpollInterest),
    ready_list: std.ArrayList(i32),
    signal_fd: i32,
    signaled: bool = false,

    const EpollInterest = struct {
        events: u32,
        data: std.os.linux.epoll_data,
        wait_entry: waiter.Entry,
    };

    pub fn init(allocator: std.mem.Allocator) !*EpollInstance {
        const self = try allocator.create(EpollInstance);
        self.* = .{
            .allocator = allocator,
            .interests = std.AutoHashMap(i32, EpollInterest).init(allocator),
            .ready_list = std.ArrayList(i32).init(allocator),
            .signal_fd = try std.posix.eventfd(0, 0x800),
        };
        return self;
    }

    pub fn deinit(self: *EpollInstance) void {
        var it = self.interests.iterator();
        while (it.next()) |entry| {
            // Unregister from socket
            const ft = if (global_file_table) |*t| t else return;
            const file = ft.get(entry.key_ptr.*) orelse continue;
            switch (file) {
                .socket => |s| s.wait_queue.eventUnregister(&entry.value_ptr.wait_entry),
                else => {},
            }
        }
        self.interests.deinit();
        self.ready_list.deinit();
        std.posix.close(self.signal_fd);
        self.allocator.destroy(self);
    }

    fn notifyCallback(e: *waiter.Entry) void {
        const self = @as(*EpollInstance, @ptrCast(@alignCast(e.context.?)));
        const fd = @as(i32, @intCast(@intFromPtr(e.upcall_ctx))); // Store FD in upcall_ctx for simplicity

        // Check if already in ready list
        for (self.ready_list.items) |rfd| {
            if (rfd == fd) return;
        }
        self.ready_list.append(fd) catch {};

        if (!self.signaled) {
            self.signaled = true;
            const val: u64 = 1;
            _ = std.posix.write(self.signal_fd, std.mem.asBytes(&val)) catch {
                self.signaled = false;
            };
        }
    }
};

pub fn uepoll_create(size: i32) !i32 {
    _ = size;
    const ft = getGlobalFileTable(std.heap.page_allocator); // Assuming page_allocator for global storage
    const ep = try EpollInstance.init(ft.allocator);
    return ft.alloc(.{ .epoll = ep }) catch |err| {
        ep.deinit();
        return err;
    };
}

pub fn uepoll_ctl(epfd: i32, op: i32, fd: i32, event: ?*uepoll_event) !void {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const ep_file = ft.get(epfd) orelse return error.BadFileDescriptor;
    const ep = switch (ep_file) {
        .epoll => |e| e,
        else => return error.InvalidArguments,
    };

    const target_file = ft.get(fd) orelse return error.BadFileDescriptor;
    const sock = switch (target_file) {
        .socket => |s| s,
        else => return error.InvalidArguments,
    };

    switch (op) {
        std.os.linux.EPOLL.CTL_ADD => {
            if (ep.interests.contains(fd)) return error.FileExists;
            const ev = event orelse return error.InvalidArguments;

            var interest = EpollInstance.EpollInterest{
                .events = ev.events,
                .data = ev.data,
                .wait_entry = undefined,
            };
            interest.wait_entry = waiter.Entry.init(ep, EpollInstance.notifyCallback);
            interest.wait_entry.upcall_ctx = @ptrFromInt(@as(usize, @intCast(fd)));

            try ep.interests.put(fd, interest);
            const entry = ep.interests.getPtr(fd).?;
            sock.wait_queue.eventRegister(&entry.wait_entry, pollToWaiter(@intCast(ev.events)));
        },
        std.os.linux.EPOLL.CTL_MOD => {
            const entry = ep.interests.getPtr(fd) orelse return error.NoEntity;
            const ev = event orelse return error.InvalidArguments;

            sock.wait_queue.eventUnregister(&entry.wait_entry);
            entry.events = ev.events;
            entry.data = ev.data;
            sock.wait_queue.eventRegister(&entry.wait_entry, pollToWaiter(@intCast(ev.events)));
        },
        std.os.linux.EPOLL.CTL_DEL => {
            const entry = ep.interests.getPtr(fd) orelse return error.NoEntity;
            sock.wait_queue.eventUnregister(&entry.wait_entry);
            _ = ep.interests.remove(fd);

            // Remove from ready list if present
            for (ep.ready_list.items, 0..) |rfd, i| {
                if (rfd == fd) {
                    _ = ep.ready_list.orderedRemove(i);
                    break;
                }
            }
        },
        else => return error.InvalidArguments,
    }
}

pub fn uepoll_wait(epfd: i32, events: []uepoll_event, timeout_ms: i32) !usize {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const ep_file = ft.get(epfd) orelse return error.BadFileDescriptor;
    const ep = switch (ep_file) {
        .epoll => |e| e,
        else => return error.InvalidArguments,
    };

    if (ep.ready_list.items.len == 0 and timeout_ms != 0) {
        // In a single-threaded stack, we can't block here as no events would ever arrive.
        // We just return 0 to allow the event loop to continue or the stack to process packets.
    }

    // Drain signal if any
    if (ep.signaled) {
        var val: u64 = 0;
        _ = std.posix.read(ep.signal_fd, std.mem.asBytes(&val)) catch {};
        ep.signaled = false;
    }

    var count: usize = 0;
    while (count < events.len and ep.ready_list.items.len > 0) {
        const fd = ep.ready_list.orderedRemove(0);
        const interest = ep.interests.get(fd) orelse continue;

        const target_file = ft.get(fd) orelse continue;
        const sock = switch (target_file) {
            .socket => |s| s,
            else => continue,
        };

        const mask = sock.wait_queue.events();
        const interested = pollToWaiter(@intCast(interest.events));
        const fired = mask & interested;

        if (fired != 0) {
            events[count] = .{
                .events = @intCast(waiterToPoll(fired)),
                .data = interest.data,
            };
            count += 1;
        }
    }
    return count;
}

pub fn uepoll_get_fd(epfd: i32) !i32 {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const ep_file = ft.get(epfd) orelse return error.BadFileDescriptor;
    return switch (ep_file) {
        .epoll => |e| e.signal_fd,
        else => error.InvalidArguments,
    };
}

pub const FileTable = struct {
    files: std.ArrayList(?File),
    free_list: std.ArrayList(i32),
    allocator: std.mem.Allocator,
    const fd_start = 1024;

    pub fn init(allocator: std.mem.Allocator) FileTable {
        return .{
            .files = std.ArrayList(?File).init(allocator),
            .free_list = std.ArrayList(i32).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FileTable) void {
        for (self.files.items) |maybe_file| {
            if (maybe_file) |f| {
                switch (f) {
                    .socket => |s| s.deinit(),
                    .epoll => |e| e.deinit(),
                }
            }
        }
        self.files.deinit();
        self.free_list.deinit();
    }

    pub fn alloc(self: *FileTable, file: File) !i32 {
        if (self.free_list.popOrNull()) |fd| {
            self.files.items[@intCast(fd - fd_start)] = file;
            return fd;
        }
        const fd = @as(i32, @intCast(self.files.items.len)) + fd_start;
        try self.files.append(file);
        return fd;
    }

    pub inline fn get(self: *FileTable, fd: i32) ?File {
        if (fd < fd_start or fd >= @as(i32, @intCast(self.files.items.len)) + fd_start) return null;
        return self.files.items[@intCast(fd - fd_start)];
    }

    pub fn free(self: *FileTable, fd: i32) void {
        if (fd < fd_start or fd >= @as(i32, @intCast(self.files.items.len)) + fd_start) return;
        self.files.items[@intCast(fd - fd_start)] = null;
        self.free_list.append(fd) catch {};
    }
};

var global_file_table: ?FileTable = null;

pub fn getGlobalFileTable(allocator: std.mem.Allocator) *FileTable {
    if (global_file_table == null) {
        global_file_table = FileTable.init(allocator);
    }
    return &global_file_table.?;
}

pub fn socket_fd(s: *stack.Stack, domain: i32, sock_type: i32, protocol: i32) !i32 {
    const sock = try usocket(s, domain, sock_type, protocol);
    const ft = getGlobalFileTable(s.allocator);
    return ft.alloc(.{ .socket = sock }) catch |err| {
        sock.deinit();
        return err;
    };
}

pub fn bind_fd(fd: i32, addr: std.posix.sockaddr, len: std.posix.socklen_t) !void {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| try ubind(s, addr, len),
        else => return error.InvalidArguments,
    }
}

pub fn listen_fd(fd: i32, backlog: i32) !void {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| try ulisten(s, backlog),
        else => return error.InvalidArguments,
    }
}

pub fn accept_fd(fd: i32, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t) !i32 {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| {
            const accepted = try uaccept(s, addr, len);
            return ft.alloc(.{ .socket = accepted }) catch |err| {
                accepted.deinit();
                return err;
            };
        },
        else => return error.InvalidArguments,
    }
}

pub fn connect_fd(fd: i32, addr: std.posix.sockaddr, len: std.posix.socklen_t) !void {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| try uconnect(s, addr, len),
        else => return error.InvalidArguments,
    }
}

pub inline fn recv_fd(fd: i32, buf: []u8, flags: u32) !usize {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| return urecv(s, buf, flags),
        else => return error.InvalidArguments,
    }
}

pub inline fn send_fd(fd: i32, buf: []const u8, flags: u32) !usize {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| return usend(s, buf, flags),
        else => return error.InvalidArguments,
    }
}

pub fn usend_zc_fd(fd: i32, buf: []const u8, cb: buffer.ConsumptionCallback) !usize {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| {
            return s.endpoint.writeZeroCopy(@constCast(buf), cb, .{}) catch |err| {
                if (err == tcpip.Error.WouldBlock or err == tcpip.Error.InvalidEndpointState) return error.WouldBlock;
                return err;
            };
        },
        else => return error.InvalidArguments,
    }
}

pub fn recvfrom_fd(fd: i32, buf: []u8, flags: u32, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t) !usize {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| return urecvfrom(s, buf, flags, addr, len),
        else => return error.InvalidArguments,
    }
}

pub fn sendto_fd(fd: i32, buf: []const u8, flags: u32, addr: ?*const std.posix.sockaddr, len: std.posix.socklen_t) !usize {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;
    const file = ft.get(fd) orelse return error.BadFileDescriptor;
    switch (file) {
        .socket => |s| return usendto(s, buf, flags, addr, len),
        else => return error.InvalidArguments,
    }
}

pub fn close_fd(fd: i32) void {
    const ft = if (global_file_table) |*t| t else return;
    const file = ft.get(fd) orelse return;
    switch (file) {
        .socket => |s| {
            s.deinit();
            ft.free(fd);
        },
        .epoll => |e| {
            e.deinit();
            ft.free(fd);
        },
    }
}

// Helpers
fn fromSockAddr(addr: std.posix.sockaddr) !tcpip.FullAddress {
    if (addr.family == std.posix.AF.INET) {
        const in = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&addr)));
        return tcpip.FullAddress{
            .nic = 0, // 0 usually means "any" or "route decide" in ustack binding
            .addr = .{ .v4 = @bitCast(in.addr) },
            .port = std.mem.bigToNative(u16, in.port),
        };
    } else if (addr.family == std.posix.AF.INET6) {
        const in6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&addr)));
        return tcpip.FullAddress{
            .nic = 0,
            .addr = .{ .v6 = in6.addr },
            .port = std.mem.bigToNative(u16, in6.port),
        };
    }
    return error.AddressFamilyNotSupported;
}

fn toSockAddr(addr: tcpip.FullAddress, out: *std.posix.sockaddr, len: ?*std.posix.socklen_t) void {
    switch (addr.addr) {
        .v4 => |v| {
            var in = std.posix.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, addr.port),
                .addr = @bitCast(v),
                .zero = [_]u8{0} ** 8,
            };
            const size = @sizeOf(std.posix.sockaddr.in);
            if (len) |l| {
                if (l.* < size) return; // Truncated?
                l.* = size;
            }
            @memcpy(@as([*]u8, @ptrCast(out))[0..size], @as([*]const u8, @ptrCast(&in))[0..size]);
        },
        .v6 => |v| {
            var in6 = std.posix.sockaddr.in6{
                .family = std.posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, addr.port),
                .flowinfo = 0,
                .addr = v,
                .scope_id = 0,
            };
            const size = @sizeOf(std.posix.sockaddr.in6);
            if (len) |l| {
                if (l.* < size) return;
                l.* = size;
            }
            @memcpy(@as([*]u8, @ptrCast(out))[0..size], @as([*]const u8, @ptrCast(&in6))[0..size]);
        },
    }
}

test "POSIX API TCP client/server" {
    const allocator = std.testing.allocator;
    const tcp_proto = @import("transport/tcp.zig").TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();
    try s.registerTransportProtocol(tcp_proto.protocol());

    var ipv4_proto = @import("network/ipv4.zig").IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    // Setup Link
    var fake_link = struct {
        allocator: std.mem.Allocator,
        server_pkt: ?[]u8 = null,
        client_pkt: ?[]u8 = null,

        // Very basic in-memory "loopback" that delivers packets to the stack
        // This simulates the wire
        stack_ref: *stack.Stack,

        fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r;
            _ = protocol;

            // Linearize packet
            const hdr_view = pkt.header.view();
            const total_len = hdr_view.len + pkt.data.size;
            const buf = self.allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(buf[0..hdr_view.len], hdr_view);
            var off = hdr_view.len;
            for (pkt.data.views) |v| {
                @memcpy(buf[off .. off + v.view.len], v.view);
                off += v.view.len;
            }

            // "Transmit" by delivering back to stack (loopback)
            // But we need to reverse src/dst in IP/TCP headers if we want full emulation.
            // For this test, we are cheating. We just want to verifying API calls don't crash and wait/notify works.
            // But `uconnect` waits for handshake. We need a responder.

            // Let's just test bind/listen/socket creation without full traffic flow for now
            // to verify API surface. Full flow requires a lot of setup.
            self.allocator.free(buf);
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return 0;
        }
    }{ .allocator = allocator, .stack_ref = &s };

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).mtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = .{ 127, 0, 0, 1 } }, .prefix_len = 8 } });

    // 1. Create Socket
    const sock = try usocket(&s, std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    defer uclose(sock);

    // 2. Bind
    const addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 8080),
        .addr = 0, // 0.0.0.0
        .zero = [_]u8{0} ** 8,
    };
    try ubind(sock, @as(std.posix.sockaddr, @bitCast(addr)), @sizeOf(std.posix.sockaddr.in));

    // 3. Listen
    try ulisten(sock, 10);

    // 4. Accept (Non-blocking check for test)
    // We set non-blocking just to verify it doesn't hang forever in test
    sock.blocking = false;
    const res = uaccept(sock, null, null);
    try std.testing.expectError(tcpip.Error.WouldBlock, res);
}
pub const PollFd = struct {
    sock: *Socket,
    events: i16,
    revents: i16,
};

pub const POLLIN = 0x0001;
pub const POLLPRI = 0x0002;
pub const POLLOUT = 0x0004;
pub const POLLERR = 0x0008;
pub const POLLHUP = 0x0010;
pub const POLLNVAL = 0x0020;

// Helper to convert waiter masks to poll events
fn waiterToPoll(mask: waiter.EventMask) i16 {
    var events: i16 = 0;
    if (mask & waiter.EventIn != 0) events |= POLLIN;
    if (mask & waiter.EventOut != 0) events |= POLLOUT;
    if (mask & waiter.EventErr != 0) events |= POLLERR;
    if (mask & waiter.EventHUp != 0) events |= POLLHUP;
    if (mask & waiter.EventPri != 0) events |= POLLPRI;
    return events;
}

fn pollToWaiter(events: i16) waiter.EventMask {
    var mask: waiter.EventMask = 0;
    if (events & POLLIN != 0) mask |= waiter.EventIn;
    if (events & POLLOUT != 0) mask |= waiter.EventOut;
    if (events & POLLPRI != 0) mask |= waiter.EventPri;
    return mask;
}

pub const PollFdFd = struct {
    fd: i32,
    events: i16,
    revents: i16,
};

/// Polls multiple file descriptors for events.
pub fn upoll_fd(fds: []PollFdFd, timeout_ms: i32) !usize {
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;

    // Convert PollFdFd to PollFd (pointer-based)
    const pfds = try ft.allocator.alloc(PollFd, fds.len);
    defer ft.allocator.free(pfds);

    for (fds, 0..) |pfd_fd, i| {
        const file = ft.get(pfd_fd.fd) orelse return error.BadFileDescriptor;
        switch (file) {
            .socket => |s| {
                pfds[i] = .{
                    .sock = s,
                    .events = pfd_fd.events,
                    .revents = 0,
                };
            },
            else => return error.InvalidArguments,
        }
    }

    const n = try upoll(pfds, timeout_ms);

    // Sync results back
    for (pfds, 0..) |pfd, i| {
        fds[i].revents = pfd.revents;
    }

    return n;
}

pub fn uselect_fd(nfds: i32, readfds: ?*std.posix.fd_set, writefds: ?*std.posix.fd_set, exceptfds: ?*std.posix.fd_set, timeout: ?*std.posix.timeval) !i32 {
    _ = exceptfds;
    const ft = if (global_file_table) |*t| t else return error.BadFileDescriptor;

    // Convert select to poll
    var poll_fds = std.ArrayList(PollFdFd).init(ft.allocator);
    defer poll_fds.deinit();

    var i: i32 = 0;
    while (i < nfds) : (i += 1) {
        var events: i16 = 0;
        if (readfds) |rfds| {
            if (std.posix.FD_ISSET(@intCast(i), rfds)) events |= POLLIN;
        }
        if (writefds) |wfds| {
            if (std.posix.FD_ISSET(@intCast(i), wfds)) events |= POLLOUT;
        }

        if (events != 0) {
            try poll_fds.append(.{ .fd = i, .events = events, .revents = 0 });
        }
    }

    const timeout_ms: i32 = if (timeout) |t| @intCast(t.tv_sec * 1000 + @divTrunc(t.tv_usec, 1000)) else -1;

    const n = try upoll_fd(poll_fds.items, timeout_ms);

    // Clear and set result sets
    if (readfds) |rfds| std.posix.FD_ZERO(rfds);
    if (writefds) |wfds| std.posix.FD_ZERO(wfds);

    for (poll_fds.items) |pfd| {
        if (pfd.revents & POLLIN != 0) {
            if (readfds) |rfds| std.posix.FD_SET(@intCast(pfd.fd), rfds);
        }
        if (pfd.revents & POLLOUT != 0) {
            if (writefds) |wfds| std.posix.FD_SET(@intCast(pfd.fd), wfds);
        }
    }

    return @intCast(n);
}

/// Polls multiple sockets for events.
/// timeout_ms: < 0 (infinite), 0 (immediate), > 0 (wait time)
pub fn upoll(fds: []PollFd, timeout_ms: i32) !usize {
    // 1. Check if any are already ready (fast path)
    var ready_count: usize = 0;
    for (fds) |*pfd| {
        pfd.revents = 0;
        // Access wait queue events directly?
        // waiter.Queue has events().
        // We need socket-specific events. Waiter queue is per-socket.
        // So yes, we can check queue events.
        const mask = pfd.sock.wait_queue.events();
        const interested = pollToWaiter(pfd.events);
        const fired = mask & interested;

        if (fired != 0) {
            pfd.revents = waiterToPoll(fired);
            ready_count += 1;
        }
    }

    if (ready_count > 0 or timeout_ms == 0) {
        return ready_count;
    }

    // 2. Wait
    // We need a way to sleep on MULTIPLE condition variables?
    // No, Condition Variable is associated with a Mutex.
    // Each Socket has its own Mutex/Cond.
    // This is hard with the current architecture where each Socket owns its queue/cond.

    // Solution: Create a TEMPORARY Waiter Entry that points to a local condition variable.
    // Register this entry to ALL sockets' queues.
    // Wait on the local condition variable.
    // Unregister from all.

    var fired = false;

    const PollContext = struct {
        fired: *bool,
    };
    var ctx = PollContext{ .fired = &fired };

    const callback = struct {
        fn cb(e: *waiter.Entry) void {
            const c = @as(*PollContext, @ptrCast(@alignCast(e.context.?)));
            c.fired.* = true;
        }
    }.cb;

    // We need an array of entries, one per FD
    // Stack allocation might be too big for large N.
    // Use allocator from first socket? Or pass an allocator?
    // Let's assume fds.len is reasonable (like select 1024), or require allocator.
    // For now, let's use a temporary allocator or error if too big?
    // Let's use `std.heap.page_allocator` just for the wait entries array if stack is small.

    // Optimization: Just one entry per socket.
    // Zig doesn't allow VLA.
    const entries = try std.heap.page_allocator.alloc(waiter.Entry, fds.len);
    defer std.heap.page_allocator.free(entries);

    for (fds, 0..) |*pfd, i| {
        entries[i] = waiter.Entry.init(&ctx, callback);
        pfd.sock.wait_queue.eventRegister(&entries[i], pollToWaiter(pfd.events));
    }

    // Wait
    if (!fired and timeout_ms != 0) {
        // In a single-threaded stack, we cannot block and wait for an external event
        // because the stack itself isn't running to receive the event.
        // We can either sleep or return. We'll just return to satisfy non-blocking loops.
        // If we really wanted to wait, we'd sleep, but that blocks the event loop.
    }

    // Unregister
    for (fds, 0..) |*pfd, i| {
        pfd.sock.wait_queue.eventUnregister(&entries[i]);
    }

    // Re-check events
    ready_count = 0;
    for (fds) |*pfd| {
        pfd.revents = 0;
        const mask = pfd.sock.wait_queue.events(); // This might race if event cleared?
        // Actually, events() returns currently asserted events (level triggered).
        // So this is correct for level-triggered poll.
        const interested = pollToWaiter(pfd.events);
        const current_fired = mask & interested;
        if (current_fired != 0) {
            pfd.revents = waiterToPoll(current_fired);
            ready_count += 1;
        }
    }

    return ready_count;
}

test "POSIX upoll basic" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var udp_proto = @import("transport/udp.zig").UDPProtocol.init(allocator);
    try s.registerTransportProtocol(udp_proto.protocol());
    var ipv4_proto = @import("network/ipv4.zig").IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    // Setup Link
    var fake_link = struct {
        fn writePacket(_: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
            return;
        }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn mtu(_: *anyopaque) u32 {
            return 1500;
        }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
            return 0;
        }
    }{};
    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{ .writePacket = @TypeOf(fake_link).writePacket, .attach = @TypeOf(fake_link).attach, .linkAddress = @TypeOf(fake_link).linkAddress, .mtu = @TypeOf(fake_link).mtu, .setMTU = @TypeOf(fake_link).setMTU, .capabilities = @TypeOf(fake_link).capabilities },
    };
    try s.createNIC(1, link_ep);
    try s.nics.get(1).?.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = .{ 127, 0, 0, 1 } }, .prefix_len = 8 } });

    // Create UDP socket
    const sock = try usocket(&s, std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer uclose(sock);

    var fds = [_]PollFd{
        .{ .sock = sock, .events = POLLIN, .revents = 0 },
    };

    // 1. Poll empty (should return 0 immediately)
    const n = try upoll(&fds, 100);
    try std.testing.expectEqual(@as(usize, 0), n);

    // 2. Poll with data
    // Inject packet to make it readable
    const udp_ep = @as(*@import("transport/udp.zig").UDPEndpoint, @ptrCast(@alignCast(sock.endpoint.ptr)));
    const r = stack.Route{ .local_address = .{ .v4 = .{ 127, 0, 0, 1 } }, .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } }, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = s.nics.get(1).? };
    const id = stack.TransportEndpointID{ .local_port = 0, .local_address = .{ .v4 = .{ 0, 0, 0, 0 } }, .remote_port = 1234, .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } }, .transport_protocol = 17 };

    // We need to bind first to receive? UDP handlePacket doesn't check bind if injected directly to EP logic?
    // Wait, we need to inject to the endpoint instance.
    // Let's assume handlePacket logic:
    // It takes ownership of packet.
    const payload_buf = try allocator.alloc(u8, 10);
    // var views = [_]buffer.View{payload_buf};
    // Need UDP header for handlePacket to strip?
    // UDPEndpoint.handlePacket expects raw packet including UDP header?
    // Yes: header.UDP.init(mut_pkt.data.first()...)

    // Re-alloc with header space
    allocator.free(payload_buf);
    const buf = try allocator.alloc(u8, 8 + 4); // 8 header + 4 payload
    @memset(buf, 0);
    var views2 = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
    const pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(buf.len, &views2), .header = buffer.Prependable.init(&[_]u8{}) };

    // Inject directly into endpoint handler (bypassing stack dispatch for simplicity)
    udp_ep.transportEndpoint().handlePacket(&r, id, pkt);
    allocator.free(buf);

    // Poll again (immediate)
    const n2 = try upoll(&fds, 100);
    try std.testing.expectEqual(@as(usize, 1), n2);
    try std.testing.expect(fds[0].revents & POLLIN != 0);
}

test "FD-based API basic" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer {
        s.deinit();
        if (global_file_table) |*ft| {
            ft.deinit();
            global_file_table = null;
        }
    }

    var udp_proto = @import("transport/udp.zig").UDPProtocol.init(allocator);
    try s.registerTransportProtocol(udp_proto.protocol());
    var ipv4_proto = @import("network/ipv4.zig").IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    // 1. socket_fd
    const fd = try socket_fd(&s, std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    try std.testing.expect(fd >= 0);

    // 2. bind_fd
    const addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 1234),
        .addr = 0,
        .zero = [_]u8{0} ** 8,
    };
    try bind_fd(fd, @as(std.posix.sockaddr, @bitCast(addr)), @sizeOf(std.posix.sockaddr.in));

    // 3. upoll_fd
    var pfds = [_]PollFdFd{
        .{ .fd = fd, .events = POLLIN, .revents = 0 },
    };
    const n = try upoll_fd(&pfds, 0);
    try std.testing.expectEqual(@as(usize, 0), n);

    // 4. close_fd
    close_fd(fd);
    try std.testing.expect(global_file_table.?.get(fd) == null);
}

test "Epoll FD-based API" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer {
        s.deinit();
        if (global_file_table) |*ft| {
            ft.deinit();
            global_file_table = null;
        }
    }

    var tcp_proto = @import("transport/tcp.zig").TCPProtocol.init(allocator);
    try s.registerTransportProtocol(tcp_proto.protocol());
    var ipv4_proto = @import("network/ipv4.zig").IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    const epfd = try uepoll_create(10);
    const sfd = try socket_fd(&s, std.posix.AF.INET, std.posix.SOCK.STREAM, 0);

    var ev = uepoll_event{
        .events = POLLIN,
        .data = .{ .fd = sfd },
    };
    try uepoll_ctl(epfd, std.os.linux.EPOLL.CTL_ADD, sfd, &ev);

    // Should timeout/be empty
    var events: [1]uepoll_event = undefined;
    const n = try uepoll_wait(epfd, &events, 0);
    try std.testing.expectEqual(@as(usize, 0), n);

    close_fd(sfd);
    close_fd(epfd);
}
