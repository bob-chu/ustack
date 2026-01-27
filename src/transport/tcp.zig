const std = @import("std");
const builtin = @import("builtin");
const stack = @import("../stack.zig");
const tcpip = @import("../tcpip.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const ipv4 = @import("../network/ipv4.zig");
const log = @import("../log.zig").scoped(.tcp);
const time = @import("../time.zig");

const congestion = @import("congestion/control.zig");

pub const ProtocolNumber = 6;

pub const TCPProtocol = struct {
    allocator: std.mem.Allocator,
    view_pool: buffer.BufferPool,
    header_pool: buffer.BufferPool,
    segment_node_pool: buffer.Pool(std.TailQueue(TCPEndpoint.Segment).Node),
    packet_node_pool: buffer.Pool(std.TailQueue(TCPEndpoint.Packet).Node),
    accept_node_pool: buffer.Pool(std.TailQueue(tcpip.AcceptReturn).Node),

    pub fn init(allocator: std.mem.Allocator) *TCPProtocol {
        const self = allocator.create(TCPProtocol) catch unreachable;
        self.* = .{
            .allocator = allocator,
            .view_pool = buffer.BufferPool.init(allocator, @sizeOf(buffer.ClusterView) * header.MaxViewsPerPacket, 131072),
            .header_pool = buffer.BufferPool.init(allocator, header.ReservedHeaderSize, 131072),
            .segment_node_pool = buffer.Pool(std.TailQueue(TCPEndpoint.Segment).Node).init(allocator, 131072),
            .packet_node_pool = buffer.Pool(std.TailQueue(TCPEndpoint.Packet).Node).init(allocator, 131072),
            .accept_node_pool = buffer.Pool(std.TailQueue(tcpip.AcceptReturn).Node).init(allocator, 4096),
        };
        return self;
    }

    pub fn deinit(self: *TCPProtocol) void {
        self.view_pool.deinit();
        self.header_pool.deinit();
        self.segment_node_pool.deinit();
        self.packet_node_pool.deinit();
        self.accept_node_pool.deinit();
        self.allocator.destroy(self);
    }

    pub fn protocol(self: *TCPProtocol) stack.TransportProtocol {
        return .{ .ptr = self, .vtable = &VTableImpl };
    }

    const VTableImpl = stack.TransportProtocol.VTable{
        .number = number,
        .newEndpoint = newEndpoint,
        .parsePorts = parsePorts,
        .handlePacket = handlePacket_external,
    };

    fn number(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr; return ProtocolNumber;
    }

    fn newEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        const self = @as(*TCPProtocol, @ptrCast(@alignCast(ptr)));
        _ = net_proto;
        const ep = s.allocator.create(TCPEndpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = try TCPEndpoint.init(s, self, wait_queue, 1460);
        ep.retransmit_timer.context = ep;
        return ep.endpoint();
    }

    fn handlePacket_external(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        _ = ptr;
        const ep_opt = r.nic.stack.endpoints.get(id);
        if (ep_opt) |ep| {
            const tcp_ep = @as(*TCPEndpoint, @ptrCast(@alignCast(ep.ptr)));
            tcp_ep.handlePacket(r, id, pkt);
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
            const tcp_ep = @as(*TCPEndpoint, @ptrCast(@alignCast(ep.ptr)));
            tcp_ep.handlePacket(r, id, pkt);
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
            const tcp_ep = @as(*TCPEndpoint, @ptrCast(@alignCast(ep.ptr)));
            tcp_ep.handlePacket(r, id, pkt);
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
    proto: *TCPProtocol,
    waiter_queue: *waiter.Queue,
    owns_waiter_queue: bool = false,
    state: EndpointState = .initial,
    mutex: std.Thread.Mutex = .{},
    local_addr: ?tcpip.FullAddress = null,
    remote_addr: ?tcpip.FullAddress = null,

    snd_nxt: u32 = 0,
    rcv_nxt: u32 = 0,

    snd_wnd_scale: u8 = 0,
    rcv_wnd_scale: u8 = 14,
    rcv_wnd_max: u32 = 64 * 1024 * 1024,
    rcv_buf_used: usize = 0,
    rcv_view_count: usize = 0,
    rcv_wnd: u32 = 0,
    snd_wnd: u32 = 65535,

    cc: congestion.CongestionControl,
    ref_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),

    accepted_queue: std.TailQueue(tcpip.AcceptReturn) = .{},
    rcv_list: std.TailQueue(Packet) = .{},
    ooo_list: std.TailQueue(Packet) = .{},
    snd_queue: std.TailQueue(Segment) = .{},
    retransmit_timer: time.Timer = undefined,

    sack_enabled: bool = false,
    sack_blocks: std.ArrayList(SackBlock) = undefined,
    peer_sack_blocks: std.ArrayList(SackBlock) = undefined,

    backlog: i32 = 0,
    syncache: std.ArrayList(SyncacheEntry) = undefined,

    dup_ack_count: u32 = 0,
    last_ack: u32 = 0,
    rcv_packets_since_ack: u32 = 0,
    retransmit_count: u32 = 0,

    ts_enabled: bool = false,
    ts_recent: u32 = 0,
    max_segment_size: u16 = 1460,

    pub const SackBlock = struct {
        start: u32,
        end: u32,
    };

    pub const SyncacheEntry = struct {
        remote_addr: tcpip.FullAddress,
        rcv_nxt: u32,
        snd_nxt: u32,
        ts_recent: u32,
        ts_enabled: bool,
        sack_enabled: bool,
        ws_negotiated: bool,
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

    pub fn init(s: *stack.Stack, proto: *TCPProtocol, wq: *waiter.Queue, mss: u16) !TCPEndpoint {
        const cc = try congestion.NewReno.init(s.allocator, mss);
        var self = TCPEndpoint{
            .stack = s,
            .proto = proto,
            .waiter_queue = wq,
            .snd_nxt = 1000,
            .cc = cc,
            .max_segment_size = mss,
            .retransmit_timer = time.Timer.init(handleRetransmitTimer, undefined),
            .sack_blocks = std.ArrayList(SackBlock).init(s.allocator),
            .peer_sack_blocks = std.ArrayList(SackBlock).init(s.allocator),
            .syncache = std.ArrayList(SyncacheEntry).init(s.allocator),
        };
        self.rcv_wnd = self.rcv_wnd_max;
        return self;
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
        .bind = bind,
        .listen = listen,
        .accept = accept,
        .connect = connect,
        .write = write,
        .read = read,
        .shutdown = shutdown,
        .close = close,
        .setOption = setOption,
        .getOption = getOption,
        .getLocalAddress = getLocalAddress,
        .getRemoteAddress = getRemoteAddress,
    };

    fn getLocalAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.local_addr orelse tcpip.Error.InvalidEndpointState;
    }

    fn getRemoteAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.remote_addr orelse tcpip.Error.InvalidEndpointState;
    }

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
        self.incRef();
        defer self.decRef();
        self.checkRetransmit() catch {};
        self.mutex.lock();
        if (self.snd_queue.first != null and self.state != .error_state and self.state != .closed) {
            self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
        }
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
                while (self.snd_queue.popFirst()) |node| { node.data.data.deinit(); self.proto.segment_node_pool.release(node); }
                notify_mask = waiter.EventErr;
                return;
            }
        } else self.retransmit_count = 0;

        while (it) |node| {
            var sacked = false;
            for (self.peer_sack_blocks.items) |block| {
                const flag_len: u32 = if ((node.data.flags & (header.TCPFlagSyn | header.TCPFlagFin)) != 0) 1 else 0;
                const seg_end = node.data.seq + node.data.len + flag_len;
                if (seqAfterEq(node.data.seq, block.start) and seqBeforeEq(seg_end, block.end)) { sacked = true; break; }
            }
            if (sacked) { it = node.next; continue; }
            if (now - node.data.timestamp > 200) {
                self.cc.onLoss();
                const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
                const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
                const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
                const r = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
                const hdr_buf = self.proto.header_pool.acquire() catch return;
                defer self.proto.header_pool.release(hdr_buf);
                var pre = buffer.Prependable.init(hdr_buf);
                const options_len: u8 = if (node.data.flags & header.TCPFlagSyn != 0) 12 else 0;
                const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
                @memset(tcp_hdr, 0);
                var retransmit_h = header.TCP.init(tcp_hdr);
                retransmit_h.encode(la.port, ra.port, node.data.seq, self.rcv_nxt, node.data.flags, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
                if (options_len > 0) {
                    retransmit_h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                    var opt_ptr = retransmit_h.data[20..];
                    opt_ptr[0] = 2; opt_ptr[1] = 4; std.mem.writeInt(u16, opt_ptr[2..4], self.max_segment_size, .big);
                    opt_ptr = opt_ptr[4..];
                    opt_ptr[0] = 1; opt_ptr[1] = 3; opt_ptr[2] = 3; opt_ptr[3] = self.rcv_wnd_scale;
                    opt_ptr = opt_ptr[4..];
                    opt_ptr[0] = 4; opt_ptr[1] = 2; opt_ptr[2] = 1; opt_ptr[3] = 1;
                }

                const view_mem = self.proto.view_pool.acquire() catch return;
                const views = @as([]buffer.ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem))));
                for (views[0..node.data.data.views.len], node.data.data.views) |*dst, src| {
                    dst.* = src;
                    if (src.cluster) |c| c.acquire();
                }
                const payload_view = node.data.data.toView(self.stack.allocator) catch return;
                defer self.stack.allocator.free(payload_view);
                retransmit_h.setChecksum(retransmit_h.calculateChecksum(la.addr.v4, ra.addr.v4, payload_view));
                const pb = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(node.data.data.size, views[0..node.data.data.views.len]), .header = pre };
                var mut_pb = pb; mut_pb.data.original_views = views; mut_pb.data.view_pool = &self.proto.view_pool;
                var mut_r = r; mut_r.writePacket(ProtocolNumber, mut_pb) catch {};
                mut_pb.data.deinit(); node.data.timestamp = now;
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
        self.sack_blocks.deinit();
        self.peer_sack_blocks.deinit();
        while (self.rcv_list.popFirst()) |node| { node.data.data.deinit(); self.proto.packet_node_pool.release(node); }
        while (self.ooo_list.popFirst()) |node| { node.data.data.deinit(); self.proto.packet_node_pool.release(node); }
        while (self.accepted_queue.popFirst()) |node| { node.data.ep.close(); self.proto.accept_node_pool.release(node); }
        self.mutex.unlock();
        if (self.owns_waiter_queue) self.stack.allocator.destroy(self.waiter_queue);
        self.stack.timer_queue.cancel(&self.retransmit_timer);
        self.cc.deinit();
        while (self.snd_queue.popFirst()) |node| { node.data.data.deinit(); self.proto.segment_node_pool.release(node); }
        self.stack.allocator.destroy(self);
    }

    fn read(ptr: *anyopaque, addr: ?*tcpip.FullAddress) tcpip.Error!buffer.VectorisedView {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.rcv_list.first == null) return if (self.state == .closed or self.state == .close_wait) buffer.VectorisedView.empty() else tcpip.Error.WouldBlock;
        if (addr) |a| a.* = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;

        const num_views = self.rcv_view_count;
        const total_size = self.rcv_buf_used;
        var v_idx: usize = 0;

        var views: []buffer.ClusterView = undefined;
        var original_views: []buffer.ClusterView = &[_]buffer.ClusterView{};
        var view_pool_used: ?*buffer.BufferPool = null;

        if (num_views <= header.MaxViewsPerPacket) {
            const view_mem = self.proto.view_pool.acquire() catch return tcpip.Error.OutOfMemory;
            original_views = @as([]buffer.ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem))));
            views = original_views[0..num_views];
            view_pool_used = &self.proto.view_pool;
        } else {
            views = self.stack.allocator.alloc(buffer.ClusterView, num_views) catch return tcpip.Error.OutOfMemory;
            original_views = views;
        }

        while (self.rcv_list.popFirst()) |node| {
            for (node.data.data.views) |cv| {
                views[v_idx] = cv;
                v_idx += 1;
            }
            if (node.data.data.view_pool) |pool| {
                pool.release(std.mem.sliceAsBytes(node.data.data.original_views));
            } else if (node.data.data.allocator) |alloc| {
                alloc.free(node.data.data.original_views);
            }
            self.proto.packet_node_pool.release(node);
        }
        const old_rcv_wnd = self.rcv_wnd;
        self.rcv_buf_used = 0;
        self.rcv_view_count = 0;
        self.rcv_wnd = self.rcv_wnd_max;

        if ((old_rcv_wnd == 0) or (self.rcv_wnd -% old_rcv_wnd >= self.rcv_wnd_max / 4)) {
            self.sendControl(header.TCPFlagAck) catch {};
        }

        var res = buffer.VectorisedView.init(total_size, views);
        res.original_views = original_views;
        if (view_pool_used) |pool| {
            res.view_pool = pool;
        } else {
            res.allocator = self.stack.allocator;
        }
        return res;
    }

    fn write(ptr: *anyopaque, p: tcpip.Payloader, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        _ = opts;
        self.mutex.lock();
        defer self.mutex.unlock();
        const payload_raw = try p.fullPayload();
        var total_sent: usize = 0;
        var packet_batch: [64]tcpip.PacketBuffer = undefined;
        var batch_count: usize = 0;

        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
        const r = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);

        self.rcv_packets_since_ack = 0;
        const rcv_used = @as(u32, @intCast(self.rcv_buf_used));
        self.rcv_wnd = if (rcv_used < self.rcv_wnd_max) self.rcv_wnd_max - rcv_used else 0;

        while (total_sent < payload_raw.len) {
            const in_flight = @as(i64, @intCast(self.snd_nxt -% self.last_ack));
            const effective_wnd = @min(self.snd_wnd, self.cc.getCwnd());
            var avail = if (effective_wnd > in_flight) @as(u32, @intCast(effective_wnd - in_flight)) else 0;

            if (avail == 0 and self.snd_wnd == 0 and self.snd_queue.first == null and total_sent == 0) {
                avail = 1;
            }

            const payload_len = @min(@min(payload_raw.len - total_sent, avail), @as(u32, self.max_segment_size));

            if (payload_len == 0) break;
            const payload = payload_raw[total_sent .. total_sent + payload_len];

            const cluster = try self.stack.cluster_pool.acquire();
            @memcpy(cluster.data[0..payload_len], payload);

            const view_mem = try self.proto.view_pool.acquire();
            const original_views = @as([]buffer.ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem))));
            original_views[0] = .{ .cluster = cluster, .view = cluster.data[0..payload_len] };

            var pb_data = buffer.VectorisedView.init(payload_len, original_views[0..1]);
            pb_data.original_views = original_views;
            pb_data.view_pool = &self.proto.view_pool;

            const ts_len: u8 = if (self.ts_enabled) 12 else 0;
            const sack_len_unpadded: u8 = if (self.sack_enabled and self.sack_blocks.items.len > 0) @as(u8, @intCast(2 + self.sack_blocks.items.len * 8)) else 0;
            const sack_len = (sack_len_unpadded + 3) & ~@as(u8, 3);
            const options_len = ts_len + sack_len;
            const hdr_buf = self.proto.header_pool.acquire() catch {
                log.warn("TCP: header_pool exhausted", .{});
                break;
            };

            var pre = buffer.Prependable.init(hdr_buf);
            const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
            @memset(tcp_hdr, 0);
            var h = header.TCP.init(tcp_hdr);
            h.encode(la.port, ra.port, self.snd_nxt, self.rcv_nxt, header.TCPFlagAck | header.TCPFlagPsh, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
            var opt_ptr = h.data[20..];
            if (self.ts_enabled) {
                h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                opt_ptr[0] = 1; opt_ptr[1] = 1; opt_ptr[2] = 8; opt_ptr[3] = 10;
                std.mem.writeInt(u32, opt_ptr[4..8], @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0xFFFFFFFF))), .big);
                std.mem.writeInt(u32, opt_ptr[8..12], self.ts_recent, .big);
                opt_ptr = opt_ptr[12..];
            }
            if (sack_len > 0) {
                h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                opt_ptr[0] = 5; opt_ptr[1] = sack_len_unpadded;
                for (self.sack_blocks.items, 0..) |block, j| {
                    std.mem.writeInt(u32, opt_ptr[2 + j * 8 .. 2 + j * 8 + 4][0..4], block.start, .big);
                    std.mem.writeInt(u32, opt_ptr[6 + j * 8 .. 6 + j * 8 + 4][0..4], block.end, .big);
                }
                var k: usize = sack_len_unpadded;
                while (k < sack_len) : (k += 1) opt_ptr[k] = 1;
            }

            var pb = tcpip.PacketBuffer{ .data = pb_data, .header = pre };
            h.setChecksum(h.calculateChecksumVectorised(la.addr.v4, ra.addr.v4, pb.data));

            const node = self.proto.segment_node_pool.acquire() catch {
                log.warn("TCP: segment_node_pool exhausted", .{});
                break;
            };
            // Use the data directly instead of cloning, it will be deinitialized after sending
            // and we also hold a reference in snd_queue.
            // Wait, we need a separate view for snd_queue because we will deinit pb.data in the batch loop.
            node.data = .{ .data = try pb.data.cloneInPool(&self.proto.view_pool), .seq = self.snd_nxt, .len = @as(u32, @intCast(payload.len)), .flags = header.TCPFlagAck | header.TCPFlagPsh, .timestamp = std.time.milliTimestamp() };
            self.snd_queue.append(node);
            packet_batch[batch_count] = pb;
            batch_count += 1;
            self.snd_nxt += @as(u32, @intCast(payload.len));
            total_sent += payload_len;

            if (batch_count == 64) {
                const net_ep_opt = r.nic.network_endpoints.get(r.net_proto);
                if (net_ep_opt == null) return tcpip.Error.NoRoute;
                const net_ep = net_ep_opt.?;
                
                self.mutex.unlock();
                net_ep.writePackets(&r, ProtocolNumber, packet_batch[0..batch_count]) catch |err| {
                    self.mutex.lock();
                    return err;
                };
                self.mutex.lock();

                for (packet_batch[0..batch_count]) |pkt| {
                    self.proto.header_pool.release(pkt.header.buf);
                    var mut_pkt = pkt;
                    mut_pkt.data.deinit();
                }
                batch_count = 0;
            }
        }
        if (batch_count > 0) {
            const net_ep_opt = r.nic.network_endpoints.get(r.net_proto);
            if (net_ep_opt == null) return tcpip.Error.NoRoute;
            const net_ep = net_ep_opt.?;

            self.mutex.unlock();
            net_ep.writePackets(&r, ProtocolNumber, packet_batch[0..batch_count]) catch |err| {
                self.mutex.lock();
                return err;
            };
            self.mutex.lock();

            for (packet_batch[0..batch_count]) |pkt| {
                self.proto.header_pool.release(pkt.header.buf);
                var mut_pkt = pkt;
                mut_pkt.data.deinit();
            }
            batch_count = 0;
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
        const options_len: u8 = if (self.ts_enabled) 24 else 12;
        const hdr_buf = self.proto.header_pool.acquire() catch return tcpip.Error.OutOfMemory;
        defer self.proto.header_pool.release(hdr_buf);
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
        @memset(tcp_hdr, 0);
        var h = header.TCP.init(tcp_hdr);
        h.encode(la.port, addr.port, initial_seq, 0, header.TCPFlagSyn, @as(u16, @intCast(@min(self.rcv_wnd, 65535))));
        h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
        var opt_ptr = h.data[20..];
        opt_ptr[0] = 2; opt_ptr[1] = 4; std.mem.writeInt(u16, opt_ptr[2..4], self.max_segment_size, .big);
        opt_ptr = opt_ptr[4..];
        opt_ptr[0] = 1; opt_ptr[1] = 3; opt_ptr[2] = 3; opt_ptr[3] = self.rcv_wnd_scale;
        opt_ptr = opt_ptr[4..];
        opt_ptr[0] = 4; opt_ptr[1] = 2; opt_ptr[2] = 1; opt_ptr[3] = 1; 
        opt_ptr = opt_ptr[4..];
        if (self.ts_enabled) {
            opt_ptr[0] = 8; opt_ptr[1] = 10;
            std.mem.writeInt(u32, opt_ptr[2..6], @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0xFFFFFFFF))), .big);
            std.mem.writeInt(u32, opt_ptr[6..10], 0, .big);
            opt_ptr[10] = 1; opt_ptr[11] = 1;
        }
        h.setChecksum(h.calculateChecksum(la.addr.v4, addr.addr.v4, &[_]u8{}));
        const pb = tcpip.PacketBuffer{ .data = buffer.VectorisedView.empty(), .header = pre };
        const node = self.proto.segment_node_pool.acquire() catch return tcpip.Error.OutOfMemory;
        node.data = .{ .data = pb.data.clone(self.stack.allocator) catch {
            self.proto.segment_node_pool.release(node);
            return tcpip.Error.OutOfMemory;
        }, .seq = initial_seq, .len = 0, .flags = header.TCPFlagSyn, .timestamp = std.time.milliTimestamp() };
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
        defer self.proto.accept_node_pool.release(node); return node.data;
    }

    fn bind(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock(); defer self.mutex.unlock();
        if (self.state != .initial) return tcpip.Error.InvalidEndpointState;
        var final_addr = addr;
        if (final_addr.port == 0) {
            final_addr.port = self.stack.getNextEphemeralPort();
        }
        const id = stack.TransportEndpointID{ .local_port = final_addr.port, .local_address = final_addr.addr, .remote_port = 0, .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } } };
        self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;
        self.local_addr = final_addr; self.state = .bound;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*TCPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        if (self.state == .established) { self.state = .fin_wait1; self.sendControl(header.TCPFlagFin | header.TCPFlagAck) catch {}; }
        self.mutex.unlock(); self.decRef();
    }

    pub fn handlePacket(self: *TCPEndpoint, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        self.mutex.lock();
        var notify_mask: waiter.EventMask = 0;
        defer { self.mutex.unlock(); if (notify_mask != 0) self.waiter_queue.notify(notify_mask); }

        const now = std.time.milliTimestamp();
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
                else if (kind == 4 and len == 2) { if (fl & header.TCPFlagSyn != 0) self.sack_enabled = true; }
                else if (kind == 5 and len >= 10) {
                    const num_blocks = (len - 2) / 8;
                    self.peer_sack_blocks.clearRetainingCapacity();
                    for (0..num_blocks) |b| {
                        const start = std.mem.readInt(u32, v[opt_idx + 2 + b * 8 .. opt_idx + 6 + b * 8][0..4], .big);
                        const end = std.mem.readInt(u32, v[opt_idx + 6 + b * 8 .. opt_idx + 10 + b * 8][0..4], .big);
                        self.peer_sack_blocks.append(.{ .start = start, .end = end }) catch {};
                    }
                }
                opt_idx += len;
            }
        }

        switch (self.state) {
            .listen => {
                if (fl & header.TCPFlagSyn != 0) {
                    if (self.syncache.items.len + self.accepted_queue.len >= self.backlog) return;
                    var entry = SyncacheEntry{ .remote_addr = .{ .nic = r.nic.id, .addr = id.remote_address, .port = h.sourcePort() }, .rcv_nxt = h.sequenceNumber() + 1, .snd_nxt = @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0x7FFFFFFF))), .ts_recent = self.ts_recent, .ts_enabled = self.ts_enabled, .sack_enabled = false, .ws_negotiated = false, .snd_wnd_scale = 0, .mss = self.max_segment_size };
                    var opt_idx: usize = 20;
                    while (opt_idx < hlen) {
                        const kind = v[opt_idx];
                        if (kind == 0) break;
                        if (kind == 1) { opt_idx += 1; continue; }
                        const len = v[opt_idx + 1];
                        if (kind == 2 and len == 4) entry.mss = std.mem.readInt(u16, v[opt_idx + 2 .. opt_idx + 4][0..2], .big)
                        else if (kind == 3 and len == 3) {
                            entry.snd_wnd_scale = v[opt_idx + 2];
                            entry.ws_negotiated = true;
                        }
                        else if (kind == 4 and len == 2) entry.sack_enabled = true;
                        opt_idx += len;
                    }
                    self.syncache.append(entry) catch return;
                    const options_len: u8 = (if (entry.ts_enabled) @as(u8, 12) else 0) + (if (entry.ws_negotiated) @as(u8, 4) else 0) + (if (entry.sack_enabled) @as(u8, 4) else 0) + 4;
                    const hdr_buf = self.proto.header_pool.acquire() catch return;
                    defer self.proto.header_pool.release(hdr_buf);
                    var pre = buffer.Prependable.init(hdr_buf);
                    const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
                    @memset(tcp_hdr, 0);
                    var reply_h = header.TCP.init(tcp_hdr);
                    reply_h.encode(id.local_port, id.remote_port, entry.snd_nxt, entry.rcv_nxt, header.TCPFlagSyn | header.TCPFlagAck, @as(u16, @intCast(@min(self.rcv_wnd, 65535))));
                    reply_h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                    var opt_ptr = reply_h.data[20..];
                    opt_ptr[0] = 2; opt_ptr[1] = 4; std.mem.writeInt(u16, opt_ptr[2..4], self.max_segment_size, .big);
                    opt_ptr = opt_ptr[4..];
                    if (entry.ws_negotiated) { opt_ptr[0] = 3; opt_ptr[1] = 3; opt_ptr[2] = self.rcv_wnd_scale; opt_ptr = opt_ptr[3..]; opt_ptr[0] = 1; opt_ptr = opt_ptr[1..]; }
                    if (entry.sack_enabled) { opt_ptr[0] = 4; opt_ptr[1] = 2; opt_ptr[2] = 1; opt_ptr[3] = 1; opt_ptr = opt_ptr[4..]; }
                    if (entry.ts_enabled) {
                        opt_ptr[0] = 8; opt_ptr[1] = 10;
                        std.mem.writeInt(u32, opt_ptr[2..6], @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0xFFFFFFFF))), .big);
                        std.mem.writeInt(u32, opt_ptr[6..10], entry.ts_recent, .big);
                        opt_ptr[10] = 1; opt_ptr[11] = 1;
                    }
                    reply_h.setChecksum(reply_h.calculateChecksum(id.local_address.v4, id.remote_address.v4, &[_]u8{}));
                    const pb = tcpip.PacketBuffer{ .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 }, .header = pre };
                    var mut_r = r.*; mut_r.writePacket(ProtocolNumber, pb) catch {};
                } else if (fl & header.TCPFlagAck != 0) {
                    var found_idx: ?usize = null;
                    for (self.syncache.items, 0..) |entry, i| { if (entry.remote_addr.addr.eq(id.remote_address) and entry.remote_addr.port == h.sourcePort() and h.ackNumber() == entry.snd_nxt + 1) { found_idx = i; break; } }
                    if (found_idx) |idx| {
                        const entry = self.syncache.swapRemove(idx);
                        const new_ep = self.stack.allocator.create(TCPEndpoint) catch return;
                        const new_wq = self.stack.allocator.create(waiter.Queue) catch { self.stack.allocator.destroy(new_ep); return; };
                        new_wq.* = .{}; new_ep.* = TCPEndpoint.init(self.stack, self.proto, new_wq, entry.mss) catch { self.stack.allocator.destroy(new_wq); self.stack.allocator.destroy(new_ep); return; };
                        new_ep.retransmit_timer.context = new_ep; new_ep.owns_waiter_queue = true; new_ep.state = .established;
                        new_ep.rcv_nxt = entry.rcv_nxt; new_ep.snd_nxt = entry.snd_nxt + 1; new_ep.last_ack = new_ep.snd_nxt;
                        new_ep.local_addr = .{ .nic = r.nic.id, .addr = id.local_address, .port = id.local_port };
                        new_ep.remote_addr = entry.remote_addr; new_ep.ts_enabled = entry.ts_enabled; new_ep.ts_recent = entry.ts_recent;
                        new_ep.sack_enabled = entry.sack_enabled; new_ep.snd_wnd_scale = entry.snd_wnd_scale; if (!entry.ws_negotiated) new_ep.rcv_wnd_scale = 0;
                        new_ep.max_segment_size = entry.mss; new_ep.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(entry.snd_wnd_scale));
                        const new_id = stack.TransportEndpointID{ .local_port = new_ep.local_addr.?.port, .local_address = new_ep.local_addr.?.addr, .remote_port = new_ep.remote_addr.?.port, .remote_address = new_ep.remote_addr.?.addr };
                        self.stack.registerTransportEndpoint(new_id, new_ep.transportEndpoint()) catch { new_ep.decRef(); return; };
                        const node = self.stack.allocator.create(std.TailQueue(tcpip.AcceptReturn).Node) catch { new_ep.decRef(); return; };
                        node.data = .{ .ep = new_ep.endpoint(), .wq = new_wq }; self.accepted_queue.append(node); notify_mask |= waiter.EventIn;
                    }
                }
            },
            .syn_sent => {
                if ((fl & header.TCPFlagSyn != 0) and (fl & header.TCPFlagAck != 0)) {
                    if (h.ackNumber() == self.snd_nxt) {
                        self.state = .established; self.rcv_nxt = h.sequenceNumber() + 1; self.snd_nxt = h.ackNumber(); self.last_ack = self.snd_nxt;
                        if (self.snd_queue.popFirst()) |node| { node.data.data.deinit(); self.proto.segment_node_pool.release(node); }
                        self.stack.timer_queue.cancel(&self.retransmit_timer);
                        var opt_idx: usize = 20; var ws_negotiated = false;
                        while (opt_idx < hlen) {
                            const kind = v[opt_idx];
                            if (kind == 0) break;
                            if (kind == 1) { opt_idx += 1; continue; }
                            const len = v[opt_idx + 1];
                            if (kind == 2 and len == 4) self.max_segment_size = std.mem.readInt(u16, v[opt_idx + 2 .. opt_idx + 4][0..2], .big)
                            else if (kind == 3 and len == 3) { self.snd_wnd_scale = v[opt_idx + 2]; ws_negotiated = true; }
                            else if (kind == 4 and len == 2) self.sack_enabled = true;
                            opt_idx += len;
                        }
                        if (!ws_negotiated) self.rcv_wnd_scale = 0;
                        self.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(self.snd_wnd_scale));
                        self.sendControl(header.TCPFlagAck) catch {}; notify_mask |= waiter.EventOut;
                    }
                }
            },
            .established => {
                const data_len = pkt.data.size - h.dataOffset();
                if (h.sequenceNumber() == self.rcv_nxt) {
                    if (data_len > 0) {
                        var mut_pkt = pkt; mut_pkt.data.trimFront(h.dataOffset());
                        const node = self.proto.packet_node_pool.acquire() catch { log.warn("TCP: packet_node_pool exhausted", .{}); return; };
                        node.data = .{ .data = mut_pkt.data.cloneInPool(&self.proto.view_pool) catch { self.proto.packet_node_pool.release(node); return; }, .seq = h.sequenceNumber() };
                        self.rcv_list.append(node); self.rcv_buf_used += data_len; self.rcv_view_count += node.data.data.views.len; self.rcv_nxt += @as(u32, @intCast(data_len)); self.rcv_packets_since_ack += 1;
                        self.processOOO();
                        if (self.rcv_packets_since_ack >= 2) self.sendControl(header.TCPFlagAck) catch {};
                        notify_mask |= waiter.EventIn;
                    }
                    if (fl & header.TCPFlagFin != 0) { self.rcv_nxt += 1; self.state = .close_wait; self.sendControl(header.TCPFlagAck) catch {}; self.rcv_packets_since_ack = 0; notify_mask |= waiter.EventIn | waiter.EventHUp; }
                } else if (fl & header.TCPFlagRst == 0) {
                    if (seqAfter(h.sequenceNumber(), self.rcv_nxt) and data_len > 0) {
                        var mut_pkt = pkt; mut_pkt.data.trimFront(h.dataOffset());
                        self.insertOOO(h.sequenceNumber(), mut_pkt.data) catch {};
                    }
                    self.sendControl(header.TCPFlagAck) catch {};
                }

                if (fl & header.TCPFlagAck != 0) {
                    const ack = h.ackNumber();
                    if (seqBeforeEq(ack, self.snd_nxt) and seqAfterEq(ack, self.last_ack)) {
                        self.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(self.snd_wnd_scale));
                        if (ack == self.last_ack) {
                            self.dup_ack_count += 1;
                            if (self.dup_ack_count == 3) {
                                self.cc.onRetransmit();
                                var node_it = self.snd_queue.first;
                                while (node_it) |node| {
                                    var sacked = false;
                                    for (self.peer_sack_blocks.items) |block| {
                                        const flag_len: u32 = if ((node.data.flags & (header.TCPFlagSyn | header.TCPFlagFin)) != 0) 1 else 0;
                                        const seg_end = node.data.seq + node.data.len + flag_len;
                                        if (seqAfterEq(node.data.seq, block.start) and seqBeforeEq(seg_end, block.end)) { sacked = true; break; }
                                    }
                                    if (sacked) { node_it = node.next; continue; }

                                    const la = self.local_addr orelse return;
                                    const ra = self.remote_addr orelse return;
                                    const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
                                    const route = self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto) catch return;
                                    const hdr_buf = self.proto.header_pool.acquire() catch return;
                                    defer self.proto.header_pool.release(hdr_buf);
                                    var pre = buffer.Prependable.init(hdr_buf);
                                    const options_len: u8 = if (node.data.flags & header.TCPFlagSyn != 0) 12 else 0;
                                    const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
                                    @memset(tcp_hdr, 0);
                                    var retransmit_h = header.TCP.init(tcp_hdr);
                                    retransmit_h.encode(la.port, ra.port, node.data.seq, self.rcv_nxt, node.data.flags, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
                                    if (options_len > 0) {
                                        retransmit_h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                                        var opt_ptr = retransmit_h.data[20..];
                                        opt_ptr[0] = 2; opt_ptr[1] = 4; std.mem.writeInt(u16, opt_ptr[2..4], self.max_segment_size, .big);
                                        opt_ptr = opt_ptr[4..];
                                        opt_ptr[0] = 1; opt_ptr[1] = 3; opt_ptr[2] = 3; opt_ptr[3] = self.rcv_wnd_scale;
                                        opt_ptr = opt_ptr[4..];
                                        opt_ptr[0] = 4; opt_ptr[1] = 2; opt_ptr[2] = 1; opt_ptr[3] = 1;
                                    }

                                    const view_mem = self.proto.view_pool.acquire() catch return;
                                    const views = @as([]buffer.ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem))));
                                    for (views[0..node.data.data.views.len], node.data.data.views) |*dst, src| {
                                        dst.* = src;
                                        if (src.cluster) |c| c.acquire();
                                    }
                                    const payload_view = node.data.data.toView(self.stack.allocator) catch return;
                                    defer self.stack.allocator.free(payload_view);
                                    retransmit_h.setChecksum(retransmit_h.calculateChecksum(la.addr.v4, ra.addr.v4, payload_view));
                                    const pb = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(node.data.data.size, views[0..node.data.data.views.len]), .header = pre };
                                    var mut_pb = pb; mut_pb.data.original_views = views; mut_pb.data.view_pool = &self.proto.view_pool;
                                    var mut_r = route; mut_r.writePacket(ProtocolNumber, mut_pb) catch {};
                                    mut_pb.data.deinit(); node.data.timestamp = now;
                                    self.stack.timer_queue.schedule(&self.retransmit_timer, 200);
                                    self.dup_ack_count = 0; break;
                                }
                            }
                        } else {
                            const diff = ack - self.last_ack; self.last_ack = ack; self.dup_ack_count = 0; self.retransmit_count = 0;
                            var it_node = self.snd_queue.first;
                            while (it_node) |node| {
                                const flag_len: u32 = if ((node.data.flags & (header.TCPFlagSyn | header.TCPFlagFin)) != 0) 1 else 0;
                                const seg_end = node.data.seq + node.data.len + flag_len;
                                if (seqBeforeEq(seg_end, ack)) {
                                    const next = node.next; self.snd_queue.remove(node); node.data.data.deinit(); self.proto.segment_node_pool.release(node); it_node = next;
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
                if (fl & header.TCPFlagFin != 0) { self.rcv_nxt += 1; self.state = .close_wait; self.sendControl(header.TCPFlagAck) catch {}; self.rcv_packets_since_ack = 0; notify_mask |= waiter.EventIn | waiter.EventHUp; }
            },
            .fin_wait2 => { if (fl & header.TCPFlagFin != 0) { self.rcv_nxt += 1; self.state = .closed; self.sendControl(header.TCPFlagAck) catch {}; notify_mask |= waiter.EventHUp; } },
            .closing => { if (fl & header.TCPFlagAck != 0 and h.ackNumber() == self.snd_nxt) { self.state = .closed; notify_mask |= waiter.EventHUp; } },
            .last_ack => { if (fl & header.TCPFlagAck != 0 and h.ackNumber() == self.snd_nxt) { self.state = .closed; notify_mask |= waiter.EventHUp; } },
            else => {},
        }
    }

    fn sendControl(self: *TCPEndpoint, fl: u8) tcpip.Error!void {
        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
        const r = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);

        // Update receive window before encoding
        const rcv_used = @as(u32, @intCast(self.rcv_buf_used));
        self.rcv_wnd = if (rcv_used < self.rcv_wnd_max) self.rcv_wnd_max - rcv_used else 0;

        const sack_len: u8 = if (self.sack_enabled and self.sack_blocks.items.len > 0) @as(u8, @intCast(2 + self.sack_blocks.items.len * 8)) else 0;
        const options_len = (sack_len + 3) & ~@as(u8, 3);
        const hdr_buf = self.proto.header_pool.acquire() catch return tcpip.Error.OutOfMemory;
        defer self.proto.header_pool.release(hdr_buf);
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
        @memset(tcp_hdr, 0);
        var h = header.TCP.init(tcp_hdr);
        h.encode(la.port, ra.port, self.snd_nxt, self.rcv_nxt, fl, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
        if (sack_len > 0) {
            h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
            var opt_ptr = h.data[20..];
            opt_ptr[0] = 5; opt_ptr[1] = sack_len;
            for (self.sack_blocks.items, 0..) |block, i| {
                std.mem.writeInt(u32, opt_ptr[2 + i * 8 .. 2 + i * 8 + 4][0..4], block.start, .big);
                std.mem.writeInt(u32, opt_ptr[6 + i * 8 .. 6 + i * 8 + 4][0..4], block.end, .big);
            }
            var k: usize = sack_len;
            while (k < options_len) : (k += 1) opt_ptr[k] = 1;
        }
        h.setChecksum(h.calculateChecksum(la.addr.v4, ra.addr.v4, &[_]u8{}));
        self.rcv_packets_since_ack = 0;
        if ((fl & header.TCPFlagSyn != 0) or (fl & header.TCPFlagFin != 0)) self.snd_nxt += 1;
        const pb = tcpip.PacketBuffer{ .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 }, .header = pre };
        var mut_r = r; try mut_r.writePacket(ProtocolNumber, pb);
    }

    fn insertOOO(self: *TCPEndpoint, seq: u32, pkt_data: buffer.VectorisedView) !void {
        var it = self.ooo_list.first;
        var prev: ?*std.TailQueue(Packet).Node = null;
        while (it) |node| {
            if (seqBefore(seq, node.data.seq)) break;
            if (seq == node.data.seq) return;
            prev = node;
            it = node.next;
        }
        const node = try self.proto.packet_node_pool.acquire();
        node.data = .{ .data = try pkt_data.cloneInPool(&self.proto.view_pool), .seq = seq };
        if (prev) |p| self.ooo_list.insertAfter(p, node) else self.ooo_list.prepend(node);
        try self.updateSackBlocks(seq, seq + @as(u32, @intCast(pkt_data.size)));
    }

    fn updateSackBlocks(self: *TCPEndpoint, start: u32, end: u32) !void {
        var i: usize = 0;
        while (i < self.sack_blocks.items.len) {
            if (self.sack_blocks.items[i].start == start and self.sack_blocks.items[i].end == end) {
                _ = self.sack_blocks.orderedRemove(i);
                break;
            }
            i += 1;
        }
        try self.sack_blocks.insert(0, .{ .start = start, .end = end });
        if (self.sack_blocks.items.len > 4) _ = self.sack_blocks.pop();
    }

    fn processOOO(self: *TCPEndpoint) void {
        while (self.ooo_list.first) |node| {
            if (node.data.seq == self.rcv_nxt) {
                const data_len = node.data.data.size;
                self.ooo_list.remove(node);
                self.rcv_list.append(node);
                self.rcv_buf_used += data_len;
                self.rcv_view_count += node.data.data.views.len;
                self.rcv_nxt += @as(u32, @intCast(data_len));
                self.rcv_packets_since_ack += 1;
            } else if (seqBefore(node.data.seq, self.rcv_nxt)) {
                const end = node.data.seq + @as(u32, @intCast(node.data.data.size));
                if (seqBeforeEq(end, self.rcv_nxt)) {
                    self.ooo_list.remove(node); node.data.data.deinit(); self.proto.packet_node_pool.release(node);
                } else break;
            } else break;
        }
        var i: usize = 0;
        while (i < self.sack_blocks.items.len) {
            if (seqBeforeEq(self.sack_blocks.items[i].end, self.rcv_nxt)) { _ = self.sack_blocks.swapRemove(i); }
            else { if (seqBefore(self.sack_blocks.items[i].start, self.rcv_nxt)) self.sack_blocks.items[i].start = self.rcv_nxt; i += 1; }
        }
    }
};

fn seqBefore(a: u32, b: u32) bool { return @as(i32, @bitCast(a -% b)) < 0; }
fn seqBeforeEq(a: u32, b: u32) bool { return @as(i32, @bitCast(a -% b)) <= 0; }
fn seqAfter(a: u32, b: u32) bool { return @as(i32, @bitCast(a -% b)) > 0; }
fn seqAfterEq(a: u32, b: u32) bool { return @as(i32, @bitCast(a -% b)) >= 0; }

pub const EndpointState = enum { initial, bound, connecting, established, syn_sent, syn_recv, fin_wait1, fin_wait2, time_wait, closed, error_state, listen, close_wait, last_ack, closing };
