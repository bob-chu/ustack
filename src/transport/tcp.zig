const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const ipv4 = @import("../network/ipv4.zig");

const time = @import("../time.zig");

const congestion = @import("congestion/control.zig");

pub const ProtocolNumber = 6;

pub const EndpointState = enum {
    initial,
    bound,
    connecting,
    established,
    syn_sent,
    syn_recv,
    fin_wait1,
    fin_wait2,
    time_wait,
    closed,
    close_wait,
    last_ack,
    listen,
    closing,
    error_state,
};

pub const TCPProtocol = struct {
    pub fn init() TCPProtocol {
        return .{};
    }

    pub fn protocol(self: *TCPProtocol) stack.TransportProtocol {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.TransportProtocol.VTable{
        .number = number,
        .newEndpoint = newEndpoint,
        .parsePorts = parsePorts,
    };

    fn number(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        _ = ptr; _ = net_proto;
        const ep = s.allocator.create(TCPEndpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = TCPEndpoint.init(s, wait_queue) catch return tcpip.Error.OutOfMemory;
        ep.retransmit_timer.context = ep;
        return ep.endpoint();
    }

    fn handlePacket_external(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        _ = ptr;
        // Global handler for TCP packets (e.g. for SYN to listening sockets)
        // Find existing endpoint
        if (r.nic.stack.transport_endpoints.get(id)) |ep| {
            ep.handlePacket(r, id, pkt);
        }
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        const h = header.TCP.init(v);
        return .{ .src = h.sourcePort(), .dst = h.destinationPort() };
    }
};

pub const TCPEndpoint = struct {
    pub const Packet = struct {
        data: buffer.VectorisedView,
        seq: u32,
    };

    stack: *stack.Stack,
    waiter_queue: *waiter.Queue,
    owns_waiter_queue: bool = false,
    state: EndpointState = .initial,
    mutex: std.Thread.Mutex = .{},
    local_addr: ?tcpip.FullAddress = null,
    remote_addr: ?tcpip.FullAddress = null,
    
    snd_nxt: u32 = 0,
    rcv_nxt: u32 = 0,
    
    // Window Management
    rcv_wnd: u32 = 65535, // Default receive window
    snd_wnd: u32 = 65535, // Current send window (from peer)
    
    dup_ack_count: u32 = 0,
    last_ack: u32 = 0,
    rcv_packets_since_ack: u32 = 0,

    cc: congestion.CongestionControl,
    ref_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),

    accepted_queue: std.TailQueue(tcpip.AcceptReturn) = .{},
    rcv_list: std.TailQueue(Packet) = .{},
    snd_queue: std.TailQueue(Segment) = .{},
    retransmit_timer: time.Timer = undefined,

    pub const Segment = struct {
        data: buffer.VectorisedView,
        seq: u32,
        len: u32,
        flags: u8,
        timestamp: i64,
    };

    pub fn init(s: *stack.Stack, wq: *waiter.Queue) !TCPEndpoint {
        const cc = try congestion.NewReno.init(s.allocator, 1460);
        return .{
            .stack = s,
            .waiter_queue = wq,
            .snd_nxt = 1000, // Initial sequence number
            .cc = cc,
            .rcv_wnd = 65535,
            .retransmit_timer = time.Timer.init(handleRetransmitTimer, undefined), // Context set later
        };
    }

    pub fn setReceiveWindow(self: *TCPEndpoint, size: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.rcv_wnd = size;
    }

    pub fn transportEndpoint(self: *TCPEndpoint) stack.TransportEndpoint {
        return .{
            .ptr = self,
            .vtable = &TransportVTableImpl,
        };
    }

    const TransportVTableImpl = stack.TransportEndpoint.VTable{
        .handlePacket = handlePacket,
        .close = close_external,
        .incRef = incRef_external,
        .decRef = decRef_external,
    };

    pub fn endpoint(self: *TCPEndpoint) tcpip.Endpoint {
        return .{
            .ptr = self,
            .vtable = &EndpointVTableImpl,
        };
    }

    const EndpointVTableImpl = tcpip.Endpoint.VTable{
        .close = close_external,
        .read = read,
        .write = write,
        .connect = connect,
        .shutdown = shutdown,
        .listen = listen,
        .accept = accept,
        .bind = bind,
        .getLocalAddress = getLocalAddress,
        .getRemoteAddress = getRemoteAddress,
    };

    fn handleRetransmitTimer(ptr: *anyopaque) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.checkRetransmit() catch {};
        // If queue not empty, schedule next check
        self.mutex.lock();
        if (self.snd_queue.first != null) {
             self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
        }
        self.mutex.unlock();
    }

    pub fn checkRetransmit(self: *TCPEndpoint) tcpip.Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const now = std.time.milliTimestamp();
        var it = self.snd_queue.first;
        while (it) |node| {
            if (now - node.data.timestamp > 200) {
                self.cc.onLoss();

                const local_address = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
                const remote_address = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
                
                const net_proto: u16 = switch (remote_address.addr) {
                    .v4 => 0x0800,
                    .v6 => 0x86dd,
                };
                const r = try self.stack.findRoute(remote_address.nic, local_address.addr, remote_address.addr, net_proto);

                const hdr_buf = try self.stack.allocator.alloc(u8, header.ReservedHeaderSize);
                defer self.stack.allocator.free(hdr_buf);
                
                var pre = buffer.Prependable.init(hdr_buf);
                const tcp_hdr = pre.prepend(header.TCPMinimumSize).?;
                var h = header.TCP.init(tcp_hdr);
                h.encode(local_address.port, remote_address.port, node.data.seq, self.rcv_nxt, node.data.flags, @as(u16, @intCast(@min(self.rcv_wnd, 65535))));

                const views = try self.stack.allocator.alloc(buffer.View, node.data.data.views.len);
                defer self.stack.allocator.free(views);
                @memcpy(views, node.data.data.views);

                const payload_view = try node.data.data.toView(self.stack.allocator);
                defer self.stack.allocator.free(payload_view);
                h.setChecksum(h.calculateChecksum(local_address.addr.v4, remote_address.addr.v4, payload_view));

                const pb = tcpip.PacketBuffer{
                    .data = buffer.VectorisedView.init(node.data.data.size, views),
                    .header = pre,
                };

                var mut_r = r;
                try mut_r.writePacket(ProtocolNumber, pb);
                node.data.timestamp = now;
            }
            it = node.next;
        }
    }

    fn close_external(ptr: *anyopaque) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));

        if (self.local_addr) |la| {
            const id = stack.TransportEndpointID{
                .local_port = la.port,
                .local_address = la.addr,
                .remote_port = if (self.remote_addr) |ra| ra.port else 0,
                .remote_address = if (self.remote_addr) |ra| ra.addr else .{ .v4 = .{ 0, 0, 0, 0 } },
            };
            self.stack.unregisterTransportEndpoint(id);
        }

        self.decRef();
    }

    fn incRef_external(ptr: *anyopaque) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.incRef();
    }

    fn decRef_external(ptr: *anyopaque) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.decRef();
    }

    pub fn incRef(self: *TCPEndpoint) void {
        _ = self.ref_count.fetchAdd(1, .monotonic);
    }

    pub fn decRef(self: *TCPEndpoint) void {
        if (self.ref_count.fetchSub(1, .release) == 1) {
            self.ref_count.fence(.acquire);
            self.destroy();
        }
    }

    fn destroy(self: *TCPEndpoint) void {
        self.mutex.lock();
        while (self.rcv_list.popFirst()) |node| {
            node.data.data.deinit();
            self.stack.allocator.destroy(node);
        }
        while (self.accepted_queue.popFirst()) |node| {
            node.data.ep.close();
            self.stack.allocator.destroy(node);
        }
        self.mutex.unlock();
        if (self.owns_waiter_queue) {
            self.stack.allocator.destroy(self.waiter_queue);
        }
        self.stack.timer_queue.cancel(&self.retransmit_timer);
        self.cc.deinit();
        
        while (self.snd_queue.popFirst()) |node| {
            node.data.data.deinit();
            self.stack.allocator.destroy(node);
        }
        self.stack.allocator.destroy(self);
    }

    fn read(ptr: *anyopaque, addr: ?*tcpip.FullAddress) tcpip.Error!buffer.View {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const node = self.rcv_list.popFirst() orelse {
            if (self.state == .close_wait or self.state == .closed or self.state == .last_ack or self.state == .time_wait) {
                return @as(buffer.View, &[_]u8{});
            }
            return tcpip.Error.WouldBlock;
        };
        defer {
            node.data.data.deinit();
            self.stack.allocator.destroy(node);
        }

        if (addr) |a| {
            a.* = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        }

        return node.data.data.toView(self.stack.allocator) catch return tcpip.Error.NoBufferSpace;
    }

    fn write(ptr: *anyopaque, p: tcpip.Payloader, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.state != .established) return tcpip.Error.InvalidEndpointState;
        _ = opts;

        // Reset dup ACK count as we are sending new data (which will have a fresh ACK)
        self.dup_ack_count = 0;

        const payload = try p.fullPayload();
        const local_address = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const remote_address = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        
        const net_proto: u16 = switch (remote_address.addr) {
            .v4 => 0x0800,
            .v6 => 0x86dd,
        };
        const r = try self.stack.findRoute(remote_address.nic, local_address.addr, remote_address.addr, net_proto);

        const hdr_buf = try self.stack.allocator.alloc(u8, header.ReservedHeaderSize);
        defer self.stack.allocator.free(hdr_buf);
        
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize).?;
        var h = header.TCP.init(tcp_hdr);
        h.encode(local_address.port, remote_address.port, self.snd_nxt, self.rcv_nxt, header.TCPFlagAck | header.TCPFlagPsh, @as(u16, @intCast(@min(self.rcv_wnd, 65535))));
        h.setChecksum(h.calculateChecksum(local_address.addr.v4, remote_address.addr.v4, payload));

        self.rcv_packets_since_ack = 0;

        var views = [_]buffer.View{@constCast(payload)};
        var pb = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload.len, &views),
            .header = pre,
        };
        
        const data_clone = try pb.data.clone(self.stack.allocator);
        const node = try self.stack.allocator.create(std.TailQueue(Segment).Node);
        node.data = .{
            .data = data_clone,
            .seq = self.snd_nxt,
            .len = @as(u32, @intCast(payload.len)),
            .flags = header.TCPFlagAck | header.TCPFlagPsh,
            .timestamp = std.time.milliTimestamp(),
        };
        self.snd_queue.append(node);

        var mut_r = r;
        try mut_r.writePacket(ProtocolNumber, pb);
        
        self.snd_nxt += @as(u32, @intCast(payload.len));

        if (!self.retransmit_timer.active) {
            self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
        }

        return payload.len;
    }

    fn connect(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        
        self.remote_addr = addr;
        const local_address = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        
        const net_proto: u16 = switch (addr.addr) {
            .v4 => 0x0800,
            .v6 => 0x86dd,
        };
        const r = try self.stack.findRoute(addr.nic, local_address.addr, addr.addr, net_proto);
        
        self.state = .syn_sent;

        const id = stack.TransportEndpointID{
            .local_port = local_address.port,
            .local_address = local_address.addr,
            .remote_port = addr.port,
            .remote_address = addr.addr,
        };
        self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;

        const hdr_buf = self.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer self.stack.allocator.free(hdr_buf);
        
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize + 4).?;
        var h = header.TCP.init(tcp_hdr);
        h.encode(local_address.port, addr.port, 1000, 0, header.TCPFlagSyn, @as(u16, @intCast(@min(self.rcv_wnd, 65535))));
        h.data[header.TCPDataOffset] = (6 << 4); // 24 bytes header
        // MSS Option: Kind=2, Len=4, Value=1460
        h.data[20] = 2;
        h.data[21] = 4;
        std.mem.writeInt(u16, h.data[22..24], 1460, .big);
        h.setChecksum(h.calculateChecksum(local_address.addr.v4, addr.addr.v4, &[_]u8{}));

        const pb = tcpip.PacketBuffer{
            .data = .{.views = &[_]buffer.View{}, .size = 0},
            .header = pre,
        };
        
        var mut_r = r;
        try mut_r.writePacket(ProtocolNumber, pb);
        
        self.snd_nxt += 1;

        return;
    }

    fn bind(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.local_addr = addr;
        if (self.local_addr.?.port == 0) {
            // Assign ephemeral port
            self.local_addr.?.port = 10000 + @as(u16, @intCast(@mod(std.time.milliTimestamp(), 10000)));
        }
        return;
    }

    fn shutdown(ptr: *anyopaque, flags: u8) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = flags;
        
        if (self.state == .established) {
            self.state = .fin_wait1;
            try self.sendControl(header.TCPFlagFin | header.TCPFlagAck);
        } else if (self.state == .close_wait) {
            self.state = .last_ack;
            try self.sendControl(header.TCPFlagFin | header.TCPFlagAck);
        }
        return;
    }

    fn listen(ptr: *anyopaque, backlog: i32) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = backlog;
        self.state = .listen;
        
        if (self.local_addr) |addr| {
            const id = stack.TransportEndpointID{
                .local_port = addr.port,
                .local_address = addr.addr,
                .remote_port = 0,
                .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } },
            };
            self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;
        }
        
        return;
    }

    fn accept(ptr: *anyopaque) tcpip.Error!tcpip.AcceptReturn {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const node = self.accepted_queue.popFirst() orelse return tcpip.Error.WouldBlock;
        defer self.stack.allocator.destroy(node);
        
        return node.data;
    }

    fn getLocalAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.local_addr orelse tcpip.Error.InvalidEndpointState;
    }

    fn getRemoteAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.remote_addr orelse tcpip.Error.InvalidEndpointState;
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();

        const v = pkt.data.first() orelse return;
        const h = header.TCP.init(v);
        const fl = h.flags();

        std.debug.print("TCP: state={s}, flags=0x{x}, seq={}, ack={}, remote_addr={any}\n", .{@tagName(self.state), fl, h.sequenceNumber(), h.ackNumber(), id.remote_address});

        switch (self.state) {
            .listen => {
                if (fl & header.TCPFlagSyn != 0) {
                    const new_wq = self.stack.allocator.create(waiter.Queue) catch return;
                    new_wq.* = .{};
                    const new_ep = self.stack.allocator.create(TCPEndpoint) catch return;
                    new_ep.* = TCPEndpoint.init(self.stack, new_wq) catch return;
                    new_ep.retransmit_timer.context = new_ep;
                    new_ep.owns_waiter_queue = true;
                    new_ep.state = .syn_recv;
                    new_ep.rcv_nxt = h.sequenceNumber() + 1;
                    new_ep.local_addr = self.local_addr;
                    new_ep.remote_addr = .{
                        .nic = r.nic.id,
                        .addr = id.remote_address,
                        .port = h.sourcePort(),
                    };
                    
                    const new_id = stack.TransportEndpointID{
                        .local_port = new_ep.local_addr.?.port,
                        .local_address = new_ep.local_addr.?.addr,
                        .remote_port = new_ep.remote_addr.?.port,
                        .remote_address = new_ep.remote_addr.?.addr,
                    };
                    self.stack.registerTransportEndpoint(new_id, new_ep.transportEndpoint()) catch return;

                    new_ep.sendControl(header.TCPFlagSyn | header.TCPFlagAck) catch {};
                    
                    const node = self.stack.allocator.create(std.TailQueue(tcpip.AcceptReturn).Node) catch return;
                    node.data = .{ .ep = new_ep.endpoint(), .wq = new_wq };
                    self.accepted_queue.append(node);
                    self.waiter_queue.notify(waiter.EventIn);
                }
            },
            .syn_sent => {
                if ((fl & header.TCPFlagSyn != 0) and (fl & header.TCPFlagAck != 0)) {
                    if (h.ackNumber() == self.snd_nxt) {
                        self.state = .established;
                        self.rcv_nxt = h.sequenceNumber() + 1;
                        self.snd_nxt = h.ackNumber();
                        self.sendControl(header.TCPFlagAck) catch {};
                        self.waiter_queue.notify(waiter.EventOut);
                    }
                }
            },
            .syn_recv => {
                if (fl & header.TCPFlagAck != 0) {
                    if (h.ackNumber() == self.snd_nxt) {
                        self.state = .established;
                        self.snd_nxt = h.ackNumber();
                    }
                }
            },
            .established => {
                if (h.sequenceNumber() == self.rcv_nxt) {
                    const data_len = pkt.data.size - h.dataOffset();
                    if (data_len > 0) {
                        var mut_pkt = pkt;
                        mut_pkt.data.trimFront(h.dataOffset());
                        
                        const node = self.stack.allocator.create(std.TailQueue(Packet).Node) catch return;
                        node.data = .{
                            .data = mut_pkt.data.clone(self.stack.allocator) catch return,
                            .seq = h.sequenceNumber(),
                        };
                        self.rcv_list.append(node);
                        self.rcv_nxt += @as(u32, @intCast(data_len));
                        self.rcv_packets_since_ack += 1;
                        if (self.rcv_packets_since_ack >= 2) {
                            self.sendControl(header.TCPFlagAck) catch {};
                        }
                        self.waiter_queue.notify(waiter.EventIn);
                    } else if (fl & header.TCPFlagAck != 0) {
                        const ack = h.ackNumber();
                        if (ack == self.last_ack) {
                            self.dup_ack_count += 1;
                            if (self.dup_ack_count == 3) {
                                self.cc.onRetransmit();
                                if (self.snd_queue.first) |node| {
                                    const local_address = self.local_addr orelse return;
                                    const remote_address = self.remote_addr orelse return;
                                    const net_proto: u16 = switch (remote_address.addr) {
                                        .v4 => 0x0800,
                                        .v6 => 0x86dd,
                                    };
                                    const route = self.stack.findRoute(remote_address.nic, local_address.addr, remote_address.addr, net_proto) catch return;
                                    const hdr_buf = self.stack.allocator.alloc(u8, header.TCPMinimumSize) catch return;
                                    defer self.stack.allocator.free(hdr_buf);
                                    var retransmit_h = header.TCP.init(hdr_buf);
                                    retransmit_h.encode(local_address.port, remote_address.port, node.data.seq, self.rcv_nxt, node.data.flags, @as(u16, @intCast(@min(self.rcv_wnd, 65535))));
                                    const views = self.stack.allocator.alloc(buffer.View, node.data.data.views.len) catch return;
                                    defer self.stack.allocator.free(views);
                                    @memcpy(views, node.data.data.views);
                                    const pb = tcpip.PacketBuffer{
                                        .data = buffer.VectorisedView.init(node.data.data.size, views),
                                        .header = buffer.Prependable.initFull(hdr_buf),
                                    };
                                    var mut_r = route;
                                    mut_r.writePacket(ProtocolNumber, pb) catch {};
                                    node.data.timestamp = std.time.milliTimestamp();
                                    self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
                                    self.dup_ack_count = 0;
                                }
                            }
                        } else if (ack > self.last_ack) {
                            self.last_ack = ack;
                            self.dup_ack_count = 0;
                            var it = self.snd_queue.first;
                            while (it) |node| {
                                const seg_end = node.data.seq + node.data.len;
                                if (seg_end <= ack) {
                                    const next = node.next;
                                    self.snd_queue.remove(node);
                                    node.data.data.deinit();
                                    self.stack.allocator.destroy(node);
                                    it = next;
                                } else {
                                    it = node.next;
                                }
                            }
                            if (self.snd_queue.first == null) {
                                self.stack.timer_queue.cancel(&self.retransmit_timer);
                            } else {
                                self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
                            }
                            self.cc.onAck(@as(u32, @intCast(data_len)));
                        }
                    }

                    if (fl & header.TCPFlagFin != 0) {
                        self.rcv_nxt += 1;
                        self.state = .close_wait;
                        self.sendControl(header.TCPFlagAck) catch {};
                        self.rcv_packets_since_ack = 0;
                        self.waiter_queue.notify(waiter.EventIn);
                    }
                }
            },
            .fin_wait1 => {
                if (fl & header.TCPFlagAck != 0) {
                    if (h.ackNumber() == self.snd_nxt) {
                        self.state = .fin_wait2;
                    }
                }
                if (fl & header.TCPFlagFin != 0) {
                    self.rcv_nxt += 1;
                    self.sendControl(header.TCPFlagAck) catch {};
                    if (self.state == .fin_wait2) {
                        self.state = .time_wait;
                    } else {
                        self.state = .closing;
                    }
                }
            },
            .fin_wait2 => {
                if (fl & header.TCPFlagFin != 0) {
                    self.rcv_nxt += 1;
                    self.sendControl(header.TCPFlagAck) catch {};
                    self.state = .time_wait;
                }
            },
            .closing => {
                if (fl & header.TCPFlagAck != 0) {
                    if (h.ackNumber() == self.snd_nxt) {
                        self.state = .time_wait;
                    }
                }
            },
            .last_ack => {
                if (fl & header.TCPFlagAck != 0) {
                    if (h.ackNumber() == self.snd_nxt) {
                        self.state = .closed;
                    }
                }
            },
            else => {},
        }

        if (self.state == .time_wait) {
            // Simplify: just go to closed
            self.state = .closed;
        }
    }

    fn sendControl(self: *TCPEndpoint, fl: u8) tcpip.Error!void {
        const local_address = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const remote_address = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = switch (remote_address.addr) {
            .v4 => 0x0800,
            .v6 => 0x86dd,
        };
        const r = try self.stack.findRoute(remote_address.nic, local_address.addr, remote_address.addr, net_proto);
        const hdr_buf = self.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer self.stack.allocator.free(hdr_buf);
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize).?;
        var h = header.TCP.init(tcp_hdr);
        h.encode(local_address.port, remote_address.port, self.snd_nxt, self.rcv_nxt, fl, @as(u16, @intCast(@min(self.rcv_wnd, 65535))));
        h.setChecksum(h.calculateChecksum(local_address.addr.v4, remote_address.addr.v4, &[_]u8{}));
        self.rcv_packets_since_ack = 0;
        if ((fl & header.TCPFlagSyn != 0) or (fl & header.TCPFlagFin != 0)) {
            self.snd_nxt += 1;
        }
        const pb = tcpip.PacketBuffer{
            .data = .{.views = &[_]buffer.View{}, .size = 0},
            .header = pre,
        };
        var mut_r = r;
        try mut_r.writePacket(ProtocolNumber, pb);
    }
};

test "TCP retransmission" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ipv4_proto = ipv4.IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    var wq_client = waiter.Queue{};
    var ep_client = try allocator.create(TCPEndpoint);
    ep_client.* = try TCPEndpoint.init(&s, &wq_client);
    ep_client.retransmit_timer.context = ep_client;
    defer ep_client.endpoint().close();
    
    var wq_server = waiter.Queue{};
    var ep_server = try allocator.create(TCPEndpoint);
    ep_server.* = try TCPEndpoint.init(&s, &wq_server);
    ep_server.retransmit_timer.context = ep_server;
    defer ep_server.endpoint().close();

    var fake_ep = struct {
        last_pkt: ?[]u8 = null,
        allocator: std.mem.Allocator,
        drop_next: bool = false,

        fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r; _ = protocol;
            if (self.drop_next) {
                self.drop_next = false;
                return;
            }
            const hdr_view = pkt.header.view();
            const data_len = pkt.data.size;
            if (self.last_pkt) |p| self.allocator.free(p);
            self.last_pkt = self.allocator.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
            var offset = hdr_view.len;
            for (pkt.data.views) |v| {
                @memcpy(self.last_pkt.?[offset .. offset + v.len], v);
                offset += v.len;
            }
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void { _ = ptr; _ = dispatcher; }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress { _ = ptr; return [_]u8{0} ** 6; }
        fn mtu(ptr: *anyopaque) u32 { _ = ptr; return 1500; }
        fn setMTU(ptr: *anyopaque, m: u32) void { _ = ptr; _ = m; }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities { _ = ptr; return stack.CapabilityNone; }
    }{ .allocator = allocator };
    defer if (fake_ep.last_pkt) |p| allocator.free(p);

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_ep,
        .vtable = &.{
            .writePacket = @TypeOf(fake_ep).writePacket,
            .attach = @TypeOf(fake_ep).attach,
            .linkAddress = @TypeOf(fake_ep).linkAddress,
            .mtu = @TypeOf(fake_ep).mtu,
            .setMTU = @TypeOf(fake_ep).setMTU,
            .capabilities = @TypeOf(fake_ep).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };

    try nic.addAddress(.{
        .protocol = 0x0800,
        .address_with_prefix = .{ .address = client_addr.addr, .prefix_len = 24 },
    });
    try nic.addAddress(.{
        .protocol = 0x0800,
        .address_with_prefix = .{ .address = server_addr.addr, .prefix_len = 24 },
    });

    try s.addLinkAddress(server_addr.addr, [_]u8{0} ** 6);
    try s.addLinkAddress(client_addr.addr, [_]u8{0} ** 6);
    try ep_server.endpoint().bind(server_addr);
    try ep_server.endpoint().listen(10);
    try ep_client.endpoint().bind(client_addr);
    try ep_client.endpoint().connect(server_addr);
    
    var syn_views = [_]buffer.View{fake_ep.last_pkt.?[20..]};
    const syn_pkt = tcpip.PacketBuffer{ .data = .{ .views = &syn_views, .size = fake_ep.last_pkt.?.len - 20 }, .header = buffer.Prependable.init(&[_]u8{}) };
    const r_to_server = stack.Route{ .local_address = server_addr.addr, .remote_address = client_addr.addr, .local_link_address = [_]u8{0} ** 6, .net_proto = 0x0800, .nic = nic };
    const id_to_server = stack.TransportEndpointID{ .local_port = 80, .local_address = server_addr.addr, .remote_port = 1234, .remote_address = client_addr.addr };
    ep_server.transportEndpoint().handlePacket(&r_to_server, id_to_server, syn_pkt);
    const accept_res = try ep_server.endpoint().accept();
    const ep_accepted = @as(*TCPEndpoint, @ptrCast(@alignCast(accept_res.ep.ptr)));
    defer accept_res.ep.close();
    var syn_ack_views = [_]buffer.View{fake_ep.last_pkt.?[20..]};
    const syn_ack_pkt = tcpip.PacketBuffer{ .data = .{ .views = &syn_ack_views, .size = fake_ep.last_pkt.?.len - 20 }, .header = buffer.Prependable.init(&[_]u8{}) };
    const r_to_client = stack.Route{ .local_address = client_addr.addr, .remote_address = server_addr.addr, .local_link_address = [_]u8{0} ** 6, .net_proto = 0x0800, .nic = nic };
    const id_to_client = stack.TransportEndpointID{ .local_port = 1234, .local_address = client_addr.addr, .remote_port = 80, .remote_address = server_addr.addr };
    ep_client.transportEndpoint().handlePacket(&r_to_client, id_to_client, syn_ack_pkt);
    var ack_views = [_]buffer.View{fake_ep.last_pkt.?[20..]};
    const ack_pkt = tcpip.PacketBuffer{ .data = .{ .views = &ack_views, .size = fake_ep.last_pkt.?.len - 20 }, .header = buffer.Prependable.init(&[_]u8{}) };
    ep_accepted.transportEndpoint().handlePacket(&r_to_server, id_to_server, ack_pkt);

    const FakePayloader = struct {
        data: []const u8,
        pub fn payloader(self: *@This()) tcpip.Payloader { return .{ .ptr = self, .vtable = &.{ .fullPayload = fullPayload } }; }
        fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 { return @as(*@This(), @ptrCast(@alignCast(ptr))).data; }
    };
    var fp = FakePayloader{ .data = "important data" };
    fake_ep.drop_next = true;
    _ = try ep_client.endpoint().write(fp.payloader(), .{});
    std.time.sleep(210 * std.time.ns_per_ms);
    _ = s.timer_queue.tick();
    try std.testing.expect(fake_ep.last_pkt != null);
    var data_views = [_]buffer.View{fake_ep.last_pkt.?[20..]};
    const data_pkt = tcpip.PacketBuffer{ .data = .{ .views = &data_views, .size = fake_ep.last_pkt.?.len - 20 }, .header = buffer.Prependable.init(&[_]u8{}) };
    ep_accepted.transportEndpoint().handlePacket(&r_to_server, id_to_server, data_pkt);
    const rcv_view = try ep_accepted.endpoint().read(null);
    defer allocator.free(rcv_view);
    try std.testing.expectEqualStrings("important data", rcv_view);
}
