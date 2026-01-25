const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const ipv4 = @import("../network/ipv4.zig");
const log = @import("../log.zig").scoped(.tcp);
const time = @import("../time.zig");

const congestion = @import("congestion/control.zig");

pub const ProtocolNumber = 6;

fn seqBefore(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}
fn seqBeforeEq(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) <= 0;
}
fn seqAfter(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}
fn seqAfterEq(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) >= 0;
}

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

var ephemeral_counter: std.atomic.Value(u16) = std.atomic.Value(u16).init(0);

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
        .handlePacket = handlePacket_external,
    };

    fn number(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        _ = ptr;
        _ = net_proto;
        const ep = s.allocator.create(TCPEndpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = TCPEndpoint.init(s, wait_queue, 1460) catch return tcpip.Error.OutOfMemory;
        ep.retransmit_timer.context = ep;
        return ep.endpoint();
    }

    fn handlePacket_external(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        _ = ptr;
        log.debug("TCP Dispatch: Local={any}:{d} Remote={any}:{d}", .{ id.local_address, id.local_port, id.remote_address, id.remote_port });

        const ep_opt = r.nic.stack.endpoints.get(id);
        if (ep_opt) |ep| {
            ep.handlePacket(r, id, pkt);
            ep.decRef();
            return;
        }

        const listener_id = stack.TransportEndpointID{
            .local_port = id.local_port,
            .local_address = id.local_address,
            .remote_port = 0,
            .remote_address = switch (id.local_address) {
                .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                .v6 => .{ .v6 = [_]u8{0} ** 16 },
            },
        };
        if (r.nic.stack.endpoints.get(listener_id)) |ep| {
            ep.handlePacket(r, id, pkt);
            ep.decRef();
            return;
        }

        const any_id = stack.TransportEndpointID{
            .local_port = id.local_port,
            .local_address = switch (id.local_address) {
                .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                .v6 => .{ .v6 = [_]u8{0} ** 16 },
            },
            .remote_port = 0,
            .remote_address = switch (id.local_address) {
                .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                .v6 => .{ .v6 = [_]u8{0} ** 16 },
            },
        };
        if (r.nic.stack.endpoints.get(any_id)) |ep| {
            ep.handlePacket(r, id, pkt);
            ep.decRef();
            return;
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

    rcv_wnd: u32 = 10 * 1024 * 1024,
    snd_wnd: u32 = 65535,

    dup_ack_count: u32 = 0,
    last_ack: u32 = 0,
    rcv_packets_since_ack: u32 = 0,
    retransmit_count: u32 = 0,

    ts_enabled: bool = false,
    ts_recent: u32 = 0,
    max_segment_size: u16 = 1460,

    snd_wnd_scale: u8 = 0,
    rcv_wnd_scale: u8 = 14,
    rcv_wnd_max: u32 = 10 * 1024 * 1024,

    cc: congestion.CongestionControl,
    ref_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),

    accepted_queue: std.TailQueue(tcpip.AcceptReturn) = .{},
    rcv_list: std.TailQueue(Packet) = .{},
    snd_queue: std.TailQueue(Segment) = .{},
    retransmit_timer: time.Timer = undefined,

    backlog: i32 = 0,
    syncache: std.ArrayList(SyncacheEntry) = undefined,

    pub const SyncacheEntry = struct {
        remote_addr: tcpip.FullAddress,
        rcv_nxt: u32,
        snd_nxt: u32,
        ts_recent: u32,
        ts_enabled: bool,
        snd_wnd_scale: u8,
        mss: u16,
    };

    pub const Segment = struct {
        data: buffer.VectorisedView,
        seq: u32,
        len: u32,
        flags: u8,
        timestamp: i64,
    };

    pub fn init(s: *stack.Stack, wq: *waiter.Queue, mss: u16) !TCPEndpoint {
        const cc = try congestion.NewReno.init(s.allocator, mss);
        return .{
            .stack = s,
            .waiter_queue = wq,
            .snd_nxt = 1000,
            .cc = cc,
            .rcv_wnd = 10 * 1024 * 1024,
            .max_segment_size = mss,
            .retransmit_timer = time.Timer.init(handleRetransmitTimer, undefined),
            .syncache = std.ArrayList(SyncacheEntry).init(s.allocator),
        };
    }

    pub fn transportEndpoint(self: *TCPEndpoint) stack.TransportEndpoint {
        return .{ .ptr = self, .vtable = &TransportVTableImpl };
    }

    const TransportVTableImpl = stack.TransportEndpoint.VTable{
        .handlePacket = handlePacket_wrapper,
        .close = close_external,
        .incRef = incRef_external,
        .decRef = decRef_external,
    };

    fn handlePacket_wrapper(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.handlePacket(r, id, pkt);
    }

    pub fn endpoint(self: *TCPEndpoint) tcpip.Endpoint {
        return .{ .ptr = self, .vtable = &EndpointVTableImpl };
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
        .setOption = setOption,
        .getOption = getOption,
    };

    fn setOption(ptr: *anyopaque, opt: tcpip.EndpointOption) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock();
        switch (opt) { .ts_enabled => |v| self.ts_enabled = v }
    }

    fn getOption(ptr: *anyopaque, opt_type: tcpip.EndpointOptionType) tcpip.EndpointOption {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock();
        return switch (opt_type) { .ts_enabled => .{ .ts_enabled = self.ts_enabled } };
    }

    fn handleRetransmitTimer(ptr: *anyopaque) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.checkRetransmit() catch {};
        self.mutex.lock();
        if (self.snd_queue.first != null) self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
        self.mutex.unlock();
    }

    pub fn checkRetransmit(self: *TCPEndpoint) tcpip.Error!void {
        self.mutex.lock();
        var notify_mask: waiter.EventMask = 0;
        defer { self.mutex.unlock(); if (notify_mask != 0) self.waiter_queue.notify(notify_mask); }

        const now = std.time.milliTimestamp();
        var it = self.snd_queue.first;
        if (it != null) {
            self.retransmit_count += 1;
            if (self.retransmit_count > 30) {
                self.state = .error_state;
                while (self.snd_queue.popFirst()) |node| { node.data.data.deinit(); self.stack.allocator.destroy(node); }
                notify_mask = waiter.EventErr;
                return;
            }
        } else self.retransmit_count = 0;

        while (it) |node| {
            if (now - node.data.timestamp > 200) {
                self.cc.onLoss();
                const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
                const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
                const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
                const r = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
                const hdr_buf = try self.stack.allocator.alloc(u8, header.ReservedHeaderSize);
                defer self.stack.allocator.free(hdr_buf);
                var pre = buffer.Prependable.init(hdr_buf);
                const tcp_hdr = pre.prepend(header.TCPMinimumSize).?;
                var retransmit_h = header.TCP.init(tcp_hdr);
                retransmit_h.encode(la.port, ra.port, node.data.seq, self.rcv_nxt, node.data.flags, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.snd_wnd_scale)), 65535))));
                const views = self.stack.allocator.alloc(buffer.View, node.data.data.views.len) catch return;
                defer self.stack.allocator.free(views);
                @memcpy(views, node.data.data.views);
                const payload_view = node.data.data.toView(self.stack.allocator) catch return;
                defer self.stack.allocator.free(payload_view);
                retransmit_h.setChecksum(retransmit_h.calculateChecksum(la.addr.v4, ra.addr.v4, payload_view));
                const pb = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(node.data.data.size, views), .header = pre };
                var mut_r = r;
                mut_r.writePacket(ProtocolNumber, pb) catch {};
                node.data.timestamp = now;
            }
            it = node.next;
        }
    }

    fn close_external(ptr: *anyopaque) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        if (self.local_addr) |la| {
            const id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = if (self.remote_addr) |ra| ra.port else 0, .remote_address = if (self.remote_addr) |ra| ra.addr else .{ .v4 = .{ 0, 0, 0, 0 } } };
            self.stack.unregisterTransportEndpoint(id);
        }
        self.decRef();
    }

    fn incRef_external(ptr: *anyopaque) void { const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr))); self.incRef(); }
    fn decRef_external(ptr: *anyopaque) void { const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr))); self.decRef(); }
    pub fn incRef(self: *TCPEndpoint) void { _ = self.ref_count.fetchAdd(1, .monotonic); }
    pub fn decRef(self: *TCPEndpoint) void {
        if (self.ref_count.fetchSub(1, .release) == 1) {
            self.ref_count.fence(.acquire);
            self.destroy();
        }
    }

    fn destroy(self: *TCPEndpoint) void {
        self.mutex.lock();
        self.syncache.deinit();
        while (self.rcv_list.popFirst()) |node| { node.data.data.deinit(); self.stack.allocator.destroy(node); }
        while (self.accepted_queue.popFirst()) |node| { node.data.ep.close(); self.stack.allocator.destroy(node); }
        self.mutex.unlock();
        if (self.owns_waiter_queue) self.stack.allocator.destroy(self.waiter_queue);
        self.stack.timer_queue.cancel(&self.retransmit_timer);
        self.cc.deinit();
        while (self.snd_queue.popFirst()) |node| { node.data.data.deinit(); self.stack.allocator.destroy(node); }
        self.stack.allocator.destroy(self);
    }

    fn read(ptr: *anyopaque, addr: ?*tcpip.FullAddress) tcpip.Error!buffer.View {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock();
        if (self.rcv_list.first == null) return if (self.state == .closed or self.state == .close_wait) @as(buffer.View, &[_]u8{}) else tcpip.Error.WouldBlock;
        if (addr) |a| a.* = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        var total_size: usize = 0;
        var it = self.rcv_list.first;
        while (it) |node| { total_size += node.data.data.size; it = node.next; }
        const out = self.stack.allocator.alloc(u8, total_size) catch return tcpip.Error.NoBufferSpace;
        var offset: usize = 0;
        while (self.rcv_list.popFirst()) |node| {
            const view = node.data.data.toView(self.stack.allocator) catch { self.stack.allocator.free(out); return tcpip.Error.NoBufferSpace; };
            @memcpy(out[offset .. offset + view.len], view); offset += view.len;
            var mut_data = node.data.data; mut_data.deinit(); self.stack.allocator.destroy(node);
        }
        return out;
    }

    fn write(ptr: *anyopaque, p: tcpip.Payloader, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        _ = opts;
        self.mutex.lock(); defer self.mutex.unlock();
        const payload_raw = try p.fullPayload();
        var total_sent: usize = 0;
        var packets = std.ArrayList(tcpip.PacketBuffer).init(self.stack.allocator);
        defer packets.deinit();
        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
        const r = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
        while (total_sent < payload_raw.len) {
            const in_flight = @as(i64, @intCast(self.snd_nxt -% self.last_ack));
            const effective_wnd = @min(self.snd_wnd, self.cc.getCwnd());
            const avail_signed = @as(i64, @intCast(effective_wnd)) - in_flight;
            const avail = if (avail_signed > 0) @as(u32, @intCast(avail_signed)) else 0;
            const payload_len = @min(@min(payload_raw.len - total_sent, avail), @as(u32, self.max_segment_size));
            if (payload_len == 0) break;
            const payload = payload_raw[total_sent .. total_sent + payload_len];
            const options_len: u8 = if (self.ts_enabled) 12 else 0;
            const hdr_buf = try self.stack.allocator.alloc(u8, header.ReservedHeaderSize);
            var pre = buffer.Prependable.init(hdr_buf);
            const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
            var h = header.TCP.init(tcp_hdr);
            h.encode(la.port, ra.port, self.snd_nxt, self.rcv_nxt, header.TCPFlagAck | header.TCPFlagPsh, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
            if (self.ts_enabled) {
                h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                h.data[20] = 1; h.data[21] = 1; h.data[22] = 8; h.data[23] = 10;
                std.mem.writeInt(u32, h.data[24..28], @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0xFFFFFFFF))), .big);
                std.mem.writeInt(u32, h.data[28..32], self.ts_recent, .big);
            }
            h.setChecksum(h.calculateChecksum(la.addr.v4, ra.addr.v4, payload));
            self.rcv_packets_since_ack = 0;
            const rcv_used = @as(u32, @intCast(self.rcv_list.len)) * @as(u32, self.max_segment_size);
            self.rcv_wnd = if (rcv_used < self.rcv_wnd_max) self.rcv_wnd_max - rcv_used else 0;
            const views = try self.stack.allocator.alloc(buffer.View, 1);
            views[0] = @constCast(payload);
            var pb = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(payload.len, views), .header = pre };
            const data_clone = try pb.data.clone(self.stack.allocator);
            const node = try self.stack.allocator.create(std.TailQueue(Segment).Node);
            node.data = .{ .data = data_clone, .seq = self.snd_nxt, .len = @as(u32, @intCast(payload.len)), .flags = header.TCPFlagAck | header.TCPFlagPsh, .timestamp = std.time.milliTimestamp() };
            self.snd_queue.append(node);
            try packets.append(pb);
            self.snd_nxt += @as(u32, @intCast(payload.len));
            total_sent += payload_len;
        }
        if (packets.items.len > 0) {
            const net_ep = r.nic.network_endpoints.get(r.net_proto) orelse return tcpip.Error.NoRoute;
            try net_ep.writePackets(&r, ProtocolNumber, packets.items);
            for (packets.items) |pkt| { self.stack.allocator.free(pkt.header.buf); self.stack.allocator.free(pkt.data.views); }
        }
        if (total_sent == 0) return tcpip.Error.WouldBlock;
        if (!self.retransmit_timer.active) self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
        return total_sent;
    }

    fn connect(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock();
        if (self.state != .initial and self.state != .bound) return;
        self.remote_addr = addr;
        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        self.state = .syn_sent;
        self.snd_nxt = @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0x7FFFFFFF)));
        self.last_ack = self.snd_nxt;
        const initial_seq = self.snd_nxt;
        self.snd_nxt += 1;
        const id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = addr.port, .remote_address = addr.addr };
        self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;
        const net_proto: u16 = if (addr.addr == .v4) 0x0800 else 0x86dd;
        const r = try self.stack.findRoute(addr.nic, la.addr, addr.addr, net_proto);
        const options_len: u8 = if (self.ts_enabled) 20 else 8;
        const hdr_buf = self.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer self.stack.allocator.free(hdr_buf);
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
        var h = header.TCP.init(tcp_hdr);
        h.encode(la.port, addr.port, initial_seq, 0, header.TCPFlagSyn, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
        h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
        var opt_ptr = h.data[20..];
        opt_ptr[0] = 2; opt_ptr[1] = 4; std.mem.writeInt(u16, opt_ptr[2..4], self.max_segment_size, .big);
        opt_ptr = opt_ptr[4..];
        opt_ptr[0] = 1; opt_ptr[1] = 3; opt_ptr[2] = 3; opt_ptr[3] = self.rcv_wnd_scale;
        opt_ptr = opt_ptr[4..];
        if (self.ts_enabled) {
            opt_ptr[0] = 1; opt_ptr[1] = 1; opt_ptr[2] = 8; opt_ptr[3] = 10;
            std.mem.writeInt(u32, opt_ptr[4..8], @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0xFFFFFFFF))), .big);
            std.mem.writeInt(u32, opt_ptr[8..12], 0, .big);
        }
        h.setChecksum(h.calculateChecksum(la.addr.v4, addr.addr.v4, &[_]u8{}));
        const pb = tcpip.PacketBuffer{ .data = .{ .views = &[_]buffer.View{}, .size = 0 }, .header = pre };
        const node = try self.stack.allocator.create(std.TailQueue(Segment).Node);
        node.data = .{ .data = try pb.data.clone(self.stack.allocator), .seq = initial_seq, .len = 0, .flags = header.TCPFlagSyn, .timestamp = std.time.milliTimestamp() };
        self.snd_queue.append(node);
        if (!self.retransmit_timer.active) self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
        var mut_r = r; try mut_r.writePacket(ProtocolNumber, pb);
    }

    fn shutdown(ptr: *anyopaque, flags: u8) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock(); _ = flags;
        if (self.state == .established) { self.state = .fin_wait1; try self.sendControl(header.TCPFlagFin | header.TCPFlagAck); }
        else if (self.state == .close_wait) { self.state = .last_ack; try self.sendControl(header.TCPFlagFin | header.TCPFlagAck); }
    }

    fn listen(ptr: *anyopaque, backlog: i32) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock();
        self.backlog = if (backlog > 0) backlog else 128; self.state = .listen;
        if (self.local_addr) |la| {
            const id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = 0, .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } } };
            self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;
        }
    }

    fn accept(ptr: *anyopaque) tcpip.Error!tcpip.AcceptReturn {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock();
        const node = self.accepted_queue.popFirst() orelse return tcpip.Error.WouldBlock;
        defer self.stack.allocator.destroy(node);
        return node.data;
    }

    fn bind(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock();
        self.local_addr = addr;
        if (self.local_addr.?.port == 0) {
            const off = ephemeral_counter.fetchAdd(1, .monotonic);
            self.local_addr.?.port = 30000 + @as(u16, @intCast((@as(u64, @intCast(std.time.milliTimestamp())) + off) % 20000));
        }
    }

    fn getLocalAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.local_addr orelse tcpip.Error.InvalidEndpointState;
    }

    fn getRemoteAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.remote_addr orelse tcpip.Error.InvalidEndpointState;
    }

    pub fn handlePacket(self: *TCPEndpoint, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        self.mutex.lock();
        var notify_mask: waiter.EventMask = 0;
        defer { self.mutex.unlock(); if (notify_mask != 0) self.waiter_queue.notify(notify_mask); }

        const v = pkt.data.first() orelse return;
        const h = header.TCP.init(v);
        const fl = h.flags();
        
        if (fl & header.TCPFlagRst != 0) { self.state = .error_state; notify_mask |= waiter.EventErr; return; }

        const hlen = h.dataOffset();
        if (hlen > header.TCPMinimumSize) {
            var opt_idx: usize = 20;
            while (opt_idx < hlen) {
                const kind = v[opt_idx];
                if (kind == 0) break;
                if (kind == 1) { opt_idx += 1; continue; }
                const len = v[opt_idx + 1];
                if (kind == 8 and len == 10) { self.ts_recent = std.mem.readInt(u32, v[opt_idx + 2 .. opt_idx + 6][0..4], .big); if (fl & header.TCPFlagSyn != 0) self.ts_enabled = true; }
                opt_idx += len;
            }
        }

        switch (self.state) {
            .listen => {
                if (fl & header.TCPFlagSyn != 0) {
                    if (self.syncache.items.len + self.accepted_queue.len >= self.backlog) return;
                    const entry = SyncacheEntry{ .remote_addr = .{ .nic = r.nic.id, .addr = id.remote_address, .port = h.sourcePort() }, .rcv_nxt = h.sequenceNumber() + 1, .snd_nxt = @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0x7FFFFFFF))), .ts_recent = self.ts_recent, .ts_enabled = self.ts_enabled, .snd_wnd_scale = 0, .mss = self.max_segment_size };
                    var opt_idx: usize = 20;
                    while (opt_idx < hlen) {
                        const kind = v[opt_idx];
                        if (kind == 0) break;
                        if (kind == 1) { opt_idx += 1; continue; }
                        const len = v[opt_idx + 1];
                        if (kind == 2 and len == 4) @constCast(&entry).mss = std.mem.readInt(u16, v[opt_idx + 2 .. opt_idx + 4][0..2], .big)
                        else if (kind == 3 and len == 3) @constCast(&entry).snd_wnd_scale = v[opt_idx + 2];
                        opt_idx += len;
                    }
                    self.syncache.append(entry) catch return;
                    const options_len: u8 = if (entry.ts_enabled) 20 else 8;
                    const hdr_buf = self.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
                    defer self.stack.allocator.free(hdr_buf);
                    var pre = buffer.Prependable.init(hdr_buf);
                    const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
                    var reply_h = header.TCP.init(tcp_hdr);
                    reply_h.encode(id.local_port, id.remote_port, entry.snd_nxt, entry.rcv_nxt, header.TCPFlagSyn | header.TCPFlagAck, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
                    reply_h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                    var opt_ptr = reply_h.data[20..];
                    opt_ptr[0] = 2; opt_ptr[1] = 4; std.mem.writeInt(u16, opt_ptr[2..4], self.max_segment_size, .big);
                    opt_ptr = opt_ptr[4..];
                    opt_ptr[0] = 1; opt_ptr[1] = 3; opt_ptr[2] = 3; opt_ptr[3] = self.rcv_wnd_scale;
                    if (entry.ts_enabled) {
                        opt_ptr = opt_ptr[4..]; opt_ptr[0] = 1; opt_ptr[1] = 1; opt_ptr[2] = 8; opt_ptr[3] = 10;
                        std.mem.writeInt(u32, opt_ptr[4..8], @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0xFFFFFFFF))), .big);
                        std.mem.writeInt(u32, opt_ptr[8..12], entry.ts_recent, .big);
                    }
                    reply_h.setChecksum(reply_h.calculateChecksum(id.local_address.v4, id.remote_address.v4, &[_]u8{}));
                    const pb = tcpip.PacketBuffer{ .data = .{ .views = &[_]buffer.View{}, .size = 0 }, .header = pre };
                    var mut_r = r.*; mut_r.writePacket(ProtocolNumber, pb) catch {};
                } else if (fl & header.TCPFlagAck != 0) {
                    var found_idx: ?usize = null;
                    for (self.syncache.items, 0..) |entry, i| { if (entry.remote_addr.addr.eq(id.remote_address) and entry.remote_addr.port == h.sourcePort() and h.ackNumber() == entry.snd_nxt + 1) { found_idx = i; break; } }
                    if (found_idx) |idx| {
                        const entry = self.syncache.swapRemove(idx);
                        const new_ep = self.stack.allocator.create(TCPEndpoint) catch return;
                        const new_wq = self.stack.allocator.create(waiter.Queue) catch return;
                        new_wq.* = .{}; new_ep.* = TCPEndpoint.init(self.stack, new_wq, entry.mss) catch return;
                        new_ep.retransmit_timer.context = new_ep; new_ep.owns_waiter_queue = true; new_ep.state = .established;
                        new_ep.rcv_nxt = entry.rcv_nxt; new_ep.snd_nxt = entry.snd_nxt + 1; new_ep.last_ack = new_ep.snd_nxt;
                        new_ep.local_addr = .{ .nic = r.nic.id, .addr = id.local_address, .port = id.local_port };
                        new_ep.remote_addr = entry.remote_addr; new_ep.ts_enabled = entry.ts_enabled; new_ep.ts_recent = entry.ts_recent;
                        new_ep.snd_wnd_scale = entry.snd_wnd_scale; new_ep.max_segment_size = entry.mss;
                        new_ep.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(entry.snd_wnd_scale));
                        const new_id = stack.TransportEndpointID{ .local_port = new_ep.local_addr.?.port, .local_address = new_ep.local_addr.?.addr, .remote_port = new_ep.remote_addr.?.port, .remote_address = new_ep.remote_addr.?.addr };
                        self.stack.registerTransportEndpoint(new_id, new_ep.transportEndpoint()) catch return;
                        const node = self.stack.allocator.create(std.TailQueue(tcpip.AcceptReturn).Node) catch return;
                        node.data = .{ .ep = new_ep.endpoint(), .wq = new_wq }; self.accepted_queue.append(node); notify_mask |= waiter.EventIn;
                    }
                }
            },
            .syn_sent => {
                if ((fl & header.TCPFlagSyn != 0) and (fl & header.TCPFlagAck != 0)) {
                    if (h.ackNumber() == self.snd_nxt) {
                        self.state = .established; self.rcv_nxt = h.sequenceNumber() + 1; self.snd_nxt = h.ackNumber(); self.last_ack = self.snd_nxt;
                        if (self.snd_queue.popFirst()) |node| { node.data.data.deinit(); self.stack.allocator.destroy(node); }
                        self.stack.timer_queue.cancel(&self.retransmit_timer);
                        var opt_idx: usize = 20;
                        while (opt_idx < hlen) {
                            const kind = v[opt_idx];
                            if (kind == 0) break;
                            if (kind == 1) { opt_idx += 1; continue; }
                            const len = v[opt_idx + 1];
                            if (kind == 2 and len == 4) self.max_segment_size = std.mem.readInt(u16, v[opt_idx + 2 .. opt_idx + 4][0..2], .big)
                            else if (kind == 3 and len == 3) self.snd_wnd_scale = v[opt_idx + 2];
                            opt_idx += len;
                        }
                        self.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(self.snd_wnd_scale));
                        self.sendControl(header.TCPFlagAck) catch {}; notify_mask |= waiter.EventOut;
                    }
                }
            },
            .established => {
                if (h.sequenceNumber() == self.rcv_nxt) {
                    const data_len = pkt.data.size - h.dataOffset();
                    if (data_len > 0) {
                        var mut_pkt = pkt; mut_pkt.data.trimFront(h.dataOffset());
                        const node = self.stack.allocator.create(std.TailQueue(Packet).Node) catch return;
                        node.data = .{ .data = mut_pkt.data.clone(self.stack.allocator) catch return, .seq = h.sequenceNumber() };
                        self.rcv_list.append(node); self.rcv_nxt += @as(u32, @intCast(data_len)); self.rcv_packets_since_ack += 1;
                        if (self.rcv_packets_since_ack >= 2) self.sendControl(header.TCPFlagAck) catch {};
                        notify_mask |= waiter.EventIn;
                    }
                    if (fl & header.TCPFlagFin != 0) { self.rcv_nxt += 1; self.state = .close_wait; self.sendControl(header.TCPFlagAck) catch {}; self.rcv_packets_since_ack = 0; notify_mask |= waiter.EventIn | waiter.EventHUp; }
                } else if (fl & header.TCPFlagRst == 0) self.sendControl(header.TCPFlagAck) catch {};

                if (fl & header.TCPFlagAck != 0) {
                    const ack = h.ackNumber();
                    if (seqBeforeEq(ack, self.snd_nxt) and seqAfterEq(ack, self.last_ack)) {
                        self.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(self.snd_wnd_scale));
                        if (ack == self.last_ack) {
                            self.dup_ack_count += 1;
                            if (self.dup_ack_count == 3) {
                                self.cc.onRetransmit();
                                if (self.snd_queue.first) |node| {
                                    const la = self.local_addr orelse return;
                                    const ra = self.remote_addr orelse return;
                                    const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
                                    const route = self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto) catch return;
                                    const hdr_buf = self.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
                                    defer self.stack.allocator.free(hdr_buf);
                                    var pre = buffer.Prependable.init(hdr_buf);
                                    const tcp_hdr = pre.prepend(header.TCPMinimumSize).?;
                                    var retransmit_h = header.TCP.init(tcp_hdr);
                                    retransmit_h.encode(la.port, ra.port, node.data.seq, self.rcv_nxt, node.data.flags, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.snd_wnd_scale)), 65535))));
                                    const views = self.stack.allocator.alloc(buffer.View, node.data.data.views.len) catch return;
                                    defer self.stack.allocator.free(views); @memcpy(views, node.data.data.views);
                                    const payload_view = node.data.data.toView(self.stack.allocator) catch return;
                                    defer self.stack.allocator.free(payload_view);
                                    retransmit_h.setChecksum(retransmit_h.calculateChecksum(la.addr.v4, ra.addr.v4, payload_view));
                                    const pb = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(node.data.data.size, views), .header = pre };
                                    var mut_r = route; mut_r.writePacket(ProtocolNumber, pb) catch {};
                                    node.data.timestamp = std.time.milliTimestamp();
                                    self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
                                    self.dup_ack_count = 0;
                                }
                            }
                        } else {
                            const diff = ack - self.last_ack; self.last_ack = ack; self.dup_ack_count = 0; self.retransmit_count = 0;
                            var it_node = self.snd_queue.first;
                            while (it_node) |node| {
                                const flag_len: u32 = if ((node.data.flags & (header.TCPFlagSyn | header.TCPFlagFin)) != 0) 1 else 0;
                                const seg_end = node.data.seq + node.data.len + flag_len;
                                if (seqBeforeEq(seg_end, ack)) {
                                    const next = node.next; self.snd_queue.remove(node); node.data.data.deinit(); self.stack.allocator.destroy(node); it_node = next;
                                } else it_node = node.next;
                            }
                            if (self.snd_queue.first == null) self.stack.timer_queue.cancel(&self.retransmit_timer) else self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
                            self.cc.onAck(diff); notify_mask |= waiter.EventOut;
                        }
                    }
                }
            },
            .fin_wait1 => {
                if (fl & header.TCPFlagAck != 0 and h.ackNumber() == self.snd_nxt) self.state = .fin_wait2;
                if (fl & header.TCPFlagFin != 0) { self.rcv_nxt += 1; self.sendControl(header.TCPFlagAck) catch {}; self.state = if (self.state == .fin_wait2) .time_wait else .closing; }
            },
            .fin_wait2 => { if (fl & header.TCPFlagFin != 0) { self.rcv_nxt += 1; self.sendControl(header.TCPFlagAck) catch {}; self.state = .time_wait; } },
            .closing => { if (fl & header.TCPFlagAck != 0 and h.ackNumber() == self.snd_nxt) self.state = .time_wait; },
            .last_ack => { if (fl & header.TCPFlagAck != 0 and h.ackNumber() == self.snd_nxt) { self.state = .closed; notify_mask |= waiter.EventHUp; } },
            else => {},
        }
        if (self.state == .time_wait) { self.state = .closed; notify_mask |= waiter.EventHUp; }
    }

    fn sendControl(self: *TCPEndpoint, fl: u8) tcpip.Error!void {
        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
        const r = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
        const hdr_buf = self.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer self.stack.allocator.free(hdr_buf);
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize).?;
        var h = header.TCP.init(tcp_hdr);
        h.encode(la.port, ra.port, self.snd_nxt, self.rcv_nxt, fl, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
        h.setChecksum(h.calculateChecksum(la.addr.v4, ra.addr.v4, &[_]u8{}));
        self.rcv_packets_since_ack = 0;
        const rcv_used = @as(u32, @intCast(self.rcv_list.len)) * @as(u32, self.max_segment_size);
        self.rcv_wnd = if (rcv_used < self.rcv_wnd_max) self.rcv_wnd_max - rcv_used else 0;
        if ((fl & header.TCPFlagSyn != 0) or (fl & header.TCPFlagFin != 0)) self.snd_nxt += 1;
        const pb = tcpip.PacketBuffer{ .data = .{ .views = &[_]buffer.View{}, .size = 0 }, .header = pre };
        var mut_r = r; try mut_r.writePacket(ProtocolNumber, pb);
    }
};

test "TCP Fast Retransmit" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator); defer s.deinit();
    var ipv4_proto = ipv4.IPv4Protocol.init(); try s.registerNetworkProtocol(ipv4_proto.protocol());
    var wq_server = waiter.Queue{}; var ep_server = try allocator.create(TCPEndpoint);
    ep_server.* = try TCPEndpoint.init(&s, &wq_server, 1460); ep_server.retransmit_timer.context = ep_server; defer ep_server.decRef();
    const ca = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const sa = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try s.addLinkAddress(ca.addr, .{ .addr = [_]u8{0} ** 6 }); try s.addLinkAddress(sa.addr, .{ .addr = [_]u8{0} ** 6 });
    try ep_server.endpoint().bind(sa); try ep_server.endpoint().listen(10);
    const syn_buf = try allocator.alloc(u8, header.TCPMinimumSize); defer allocator.free(syn_buf); @memset(syn_buf, 0);
    var syn = header.TCP.init(syn_buf); syn.encode(ca.port, sa.port, 1000, 0, header.TCPFlagSyn, 65535);
    var syn_views = [_]buffer.View{@constCast(syn_buf)};
    const syn_pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(header.TCPMinimumSize, &syn_views), .header = buffer.Prependable.init(&[_]u8{}) };
    var fake_link = struct { notified: bool = false, fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void { const self = @as(*@This(), @ptrCast(@alignCast(ptr))); self.notified = true; return; } }{};
    const link_ep = stack.LinkEndpoint{ 
        .ptr = &fake_link, 
        .vtable = &.{ 
            .writePacket = @TypeOf(fake_link).writePacket, 
            .writePackets = null, 
            .attach = (struct { fn f(_: *anyopaque, _: *stack.NetworkDispatcher) void {} }).f,
            .linkAddress = (struct { fn f(_: *anyopaque) tcpip.LinkAddress { return .{ .addr = [_]u8{0} ** 6 }; } }).f,
            .mtu = (struct { fn f(_: *anyopaque) u32 { return 1500; } }).f,
            .setMTU = (struct { fn f(_: *anyopaque, _: u32) void {} }).f,
            .capabilities = (struct { fn f(_: *anyopaque) stack.LinkEndpointCapabilities { return 0; } }).f,
        } 
    };
    try s.createNIC(1, link_ep); const nic = s.nics.get(1).?;
    const r_to_server = stack.Route{ .local_address = sa.addr, .remote_address = ca.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_server = stack.TransportEndpointID{ .local_port = 80, .local_address = sa.addr, .remote_port = 1234, .remote_address = ca.addr };
    ep_server.handlePacket(&r_to_server, id_to_server, syn_pkt);
}

test "TCP Connection Setup and Data" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator); defer s.deinit();
    var ipv4_proto = ipv4.IPv4Protocol.init(); try s.registerNetworkProtocol(ipv4_proto.protocol());
    var wq_client = waiter.Queue{}; var ep_client = try allocator.create(TCPEndpoint);
    ep_client.* = try TCPEndpoint.init(&s, &wq_client, 1460); ep_client.retransmit_timer.context = ep_client; defer ep_client.decRef();
    var wq_server = waiter.Queue{}; var ep_server = try allocator.create(TCPEndpoint);
    ep_server.* = try TCPEndpoint.init(&s, &wq_server, 1460); ep_server.retransmit_timer.context = ep_server; defer ep_server.decRef();
    var fake_ep = struct { last_pkt: ?[]u8 = null, allocator: std.mem.Allocator, fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void { const self = @as(*@This(), @ptrCast(@alignCast(ptr))); const hdr_view = pkt.header.view(); const data_len = pkt.data.size; if (self.last_pkt) |p| self.allocator.free(p); self.last_pkt = self.allocator.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace; @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view); var offset = hdr_view.len; for (pkt.data.views) |v| { @memcpy(self.last_pkt.?[offset .. offset + v.len], v); offset += v.len; } }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress { return .{ .addr = [_]u8{0} ** 6 }; }
        fn mtu(_: *anyopaque) u32 { return 1500; }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities { return stack.CapabilityNone; }
    }{ .allocator = allocator };
    defer if (fake_ep.last_pkt) |p| allocator.free(p);
    const link_ep = stack.LinkEndpoint{ .ptr = &fake_ep, .vtable = &.{ .writePacket = @TypeOf(fake_ep).writePacket, .writePackets = null, .attach = @TypeOf(fake_ep).attach, .linkAddress = @TypeOf(fake_ep).linkAddress, .mtu = @TypeOf(fake_ep).mtu, .setMTU = @TypeOf(fake_ep).setMTU, .capabilities = @TypeOf(fake_ep).capabilities } };
    try s.createNIC(1, link_ep); const nic = s.nics.get(1).?;
    const ca = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const sa = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = ca.addr, .prefix_len = 24 } });
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = sa.addr, .prefix_len = 24 } });
    try s.addLinkAddress(sa.addr, .{ .addr = [_]u8{0} ** 6 }); try s.addLinkAddress(ca.addr, .{ .addr = [_]u8{0} ** 6 });
    try ep_server.endpoint().bind(sa); try ep_server.endpoint().listen(10); try ep_client.endpoint().bind(ca); try ep_client.endpoint().connect(sa);
    var syn_views = [_]buffer.View{@constCast(fake_ep.last_pkt.?[20..])};
    const syn_pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(fake_ep.last_pkt.?.len - 20, &syn_views), .header = buffer.Prependable.init(&[_]u8{}) };
    const r_to_server = stack.Route{ .local_address = sa.addr, .remote_address = ca.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_server = stack.TransportEndpointID{ .local_port = 80, .local_address = sa.addr, .remote_port = 1234, .remote_address = ca.addr };
    ep_server.handlePacket(&r_to_server, id_to_server, syn_pkt);
    var syn_ack_views = [_]buffer.View{@constCast(fake_ep.last_pkt.?[20..])};
    const syn_ack_pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(fake_ep.last_pkt.?.len - 20, &syn_ack_views), .header = buffer.Prependable.init(&[_]u8{}) };
    const r_to_client = stack.Route{ .local_address = ca.addr, .remote_address = sa.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_client = stack.TransportEndpointID{ .local_port = 1234, .local_address = ca.addr, .remote_port = 80, .remote_address = sa.addr };
    ep_client.handlePacket(&r_to_client, id_to_client, syn_ack_pkt);
    try std.testing.expect(ep_client.state == .established);
}

test "TCP Retransmission" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator); defer s.deinit();
    var ipv4_proto = ipv4.IPv4Protocol.init(); try s.registerNetworkProtocol(ipv4_proto.protocol());
    var fake_ep = struct { last_pkt: ?[]u8 = null, allocator: std.mem.Allocator, drop_next: bool = false, fn writePacket(ptr: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void { const self = @as(*@This(), @ptrCast(@alignCast(ptr))); if (self.drop_next) { self.drop_next = false; return; } const hdr_view = pkt.header.view(); const data_len = pkt.data.size; if (self.last_pkt) |p| self.allocator.free(p); self.last_pkt = self.allocator.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace; @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view); var offset = hdr_view.len; for (pkt.data.views) |v| { @memcpy(self.last_pkt.?[offset .. offset + v.len], v); offset += v.len; } }
        fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
        fn linkAddress(_: *anyopaque) tcpip.LinkAddress { return .{ .addr = [_]u8{0} ** 6 }; }
        fn mtu(_: *anyopaque) u32 { return 1500; }
        fn setMTU(_: *anyopaque, _: u32) void {}
        fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities { return stack.CapabilityNone; }
    }{ .allocator = allocator };
    defer if (fake_ep.last_pkt) |p| allocator.free(p);
    const link_ep = stack.LinkEndpoint{ .ptr = &fake_ep, .vtable = &.{ .writePacket = @TypeOf(fake_ep).writePacket, .writePackets = null, .attach = @TypeOf(fake_ep).attach, .linkAddress = @TypeOf(fake_ep).linkAddress, .mtu = @TypeOf(fake_ep).mtu, .setMTU = @TypeOf(fake_ep).setMTU, .capabilities = @TypeOf(fake_ep).capabilities } };
    try s.createNIC(1, link_ep); const nic = s.nics.get(1).?;
    const ca = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const sa = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = sa.addr, .prefix_len = 24 } });
    try s.addLinkAddress(ca.addr, .{ .addr = [_]u8{0} ** 6 });
    var wq_server = waiter.Queue{}; var ep_server = try allocator.create(TCPEndpoint);
    ep_server.* = try TCPEndpoint.init(&s, &wq_server, 1460); ep_server.retransmit_timer.context = ep_server; defer ep_server.decRef();
    try ep_server.endpoint().bind(sa); try ep_server.endpoint().listen(10);
    const syn_buf = try allocator.alloc(u8, header.TCPMinimumSize); defer allocator.free(syn_buf); @memset(syn_buf, 0);
    var syn = header.TCP.init(syn_buf); syn.encode(ca.port, sa.port, 1000, 0, header.TCPFlagSyn, 65535);
    var syn_views = [_]buffer.View{@constCast(syn_buf)};
    const syn_pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(header.TCPMinimumSize, &syn_views), .header = buffer.Prependable.init(&[_]u8{}) };
    const r_to_server = stack.Route{ .local_address = sa.addr, .remote_address = ca.addr, .local_link_address = .{ .addr = [_]u8{0} ** 6 }, .net_proto = 0x0800, .nic = nic };
    const id_to_server = stack.TransportEndpointID{ .local_port = 80, .local_address = sa.addr, .remote_port = 1234, .remote_address = ca.addr };
    ep_server.handlePacket(&r_to_server, id_to_server, syn_pkt);
    const ack_buf = try allocator.alloc(u8, header.TCPMinimumSize); defer allocator.free(ack_buf); @memset(ack_buf, 0);
    var ack = header.TCP.init(ack_buf); const server_initial_seq = header.TCP.init(fake_ep.last_pkt.?[20..]).sequenceNumber();
    ack.encode(ca.port, sa.port, 1001, server_initial_seq + 1, header.TCPFlagAck, 65535);
    var ack_views = [_]buffer.View{@constCast(ack_buf)};
    const ack_pkt = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(header.TCPMinimumSize, &ack_views), .header = buffer.Prependable.init(&[_]u8{}) };
    ep_server.handlePacket(&r_to_server, id_to_server, ack_pkt);
    const accept_res = try ep_server.endpoint().accept(); const ep_accepted = @as(*TCPEndpoint, @ptrCast(@alignCast(accept_res.ep.ptr))); defer accept_res.ep.close();
    const FakePayloader = struct { data: []const u8, pub fn payloader(self: *const @This()) tcpip.Payloader { return .{ .ptr = @constCast(self), .vtable = &.{ .fullPayload = fullPayload } }; } fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 { return @as(*@This(), @ptrCast(@alignCast(ptr))).data; } };
    var fp = FakePayloader{ .data = "important data" };
    fake_ep.drop_next = true; _ = try ep_accepted.endpoint().write(fp.payloader(), .{});
    try std.testing.expect(fake_ep.drop_next == false);
}

test "TCP CWND Enforcement" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator); defer s.deinit();
    var ipv4_proto = ipv4.IPv4Protocol.init(); try s.registerNetworkProtocol(ipv4_proto.protocol());
    var fake_link = struct { fn writePacket(_: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void { return; } fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {} fn linkAddress(_: *anyopaque) tcpip.LinkAddress { return .{ .addr = [_]u8{0} ** 6 }; } fn mtu(_: *anyopaque) u32 { return 1500; } fn setMTU(_: *anyopaque, _: u32) void {} fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities { return 0; } }{};
    const link_ep = stack.LinkEndpoint{ .ptr = &fake_link, .vtable = &.{ .writePacket = @TypeOf(fake_link).writePacket, .writePackets = null, .attach = @TypeOf(fake_link).attach, .linkAddress = @TypeOf(fake_link).linkAddress, .mtu = @TypeOf(fake_link).mtu, .setMTU = @TypeOf(fake_link).setMTU, .capabilities = @TypeOf(fake_link).capabilities } };
    try s.createNIC(1, link_ep); const nic = s.nics.get(1).?;
    var wq = waiter.Queue{}; var ep = try allocator.create(TCPEndpoint);
    ep.* = try TCPEndpoint.init(&s, &wq, 1460); ep.retransmit_timer.context = ep; defer ep.decRef();
    ep.state = .established; ep.local_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 80 }; ep.remote_addr = .{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 1234 };
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = ep.local_addr.?.addr, .prefix_len = 24 } });
    ep.snd_nxt = 1000; ep.last_ack = 1000; ep.snd_wnd = 10000;
    const FakePayloader = struct { data: []const u8, pub fn payloader(self: *const @This()) tcpip.Payloader { return .{ .ptr = @constCast(self), .vtable = &.{ .fullPayload = fullPayload } }; } fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 { return @as(*@This(), @ptrCast(@alignCast(ptr))).data; } };
    var fp = FakePayloader{ .data = "a" ** 3000 }; try s.addLinkAddress(ep.remote_addr.?.addr, .{ .addr = [_]u8{0} ** 6 });
    const n = try ep.endpoint().write(fp.payloader(), .{}); try std.testing.expectEqual(@as(usize, 3000), n);
}
