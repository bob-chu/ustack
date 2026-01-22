const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");

pub const ProtocolNumber = 17;

pub const UDPProtocol = struct {
    pub fn init() UDPProtocol {
        return .{};
    }

    pub fn protocol(self: *UDPProtocol) stack.TransportProtocol {
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
        const ep = s.allocator.create(UDPEndpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = UDPEndpoint.init(s, wait_queue);
        return ep.endpoint();
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        const h = header.UDP.init(v);
        return .{ .src = h.sourcePort(), .dst = h.destinationPort() };
    }
};

pub const UDPEndpoint = struct {
    pub const Packet = struct {
        data: buffer.VectorisedView,
        sender_addr: tcpip.FullAddress,
    };

    stack: *stack.Stack,
    waiter_queue: *waiter.Queue,
    rcv_list: std.TailQueue(Packet),
    mutex: std.Thread.Mutex = .{},
    ref_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),
    
    local_addr: ?tcpip.FullAddress = null,
    remote_addr: ?tcpip.FullAddress = null,

    pub fn init(s: *stack.Stack, wq: *waiter.Queue) UDPEndpoint {
        return .{
            .stack = s,
            .waiter_queue = wq,
            .rcv_list = .{},
        };
    }

    pub fn transportEndpoint(self: *UDPEndpoint) stack.TransportEndpoint {
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

    pub fn incRef(self: *UDPEndpoint) void {
        _ = self.ref_count.fetchAdd(1, .monotonic);
    }

    pub fn decRef(self: *UDPEndpoint) void {
        if (self.ref_count.fetchSub(1, .release) == 1) {
            self.ref_count.fence(.acquire);
            self.destroy();
        }
    }

    fn destroy(self: *UDPEndpoint) void {
        self.mutex.lock();
        while (self.rcv_list.popFirst()) |node| {
            self.stack.allocator.destroy(node);
        }
        self.mutex.unlock();
        self.stack.allocator.destroy(self);
    }

    fn close_external(ptr: *anyopaque) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        
        if (self.local_addr) |la| {
            const id = stack.TransportEndpointID{
                .local_port = la.port,
                .local_address = la.addr,
                .remote_port = 0,
                .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } },
            };
            self.stack.unregisterTransportEndpoint(id);
        }

        self.decRef();
    }

    fn incRef_external(ptr: *anyopaque) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.incRef();
    }

    fn decRef_external(ptr: *anyopaque) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.decRef();
    }

    pub fn write(self: *UDPEndpoint, r: *stack.Route, remote_port: u16, data: buffer.VectorisedView) tcpip.Error!void {
        const local_address = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        
        const hdr_buf = self.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer self.stack.allocator.free(hdr_buf);
        
        var pre = buffer.Prependable.init(hdr_buf);
        const udp_hdr = pre.prepend(header.UDPMinimumSize).?;
        var h = header.UDP.init(udp_hdr);
        
        h.setSourcePort(local_address.port);
        h.setDestinationPort(remote_port);
        h.setLength(@as(u16, @intCast(header.UDPMinimumSize + data.size)));
        h.setChecksum(0);

        const pb = tcpip.PacketBuffer{
            .data = data,
            .header = pre,
        };
        
        return r.writePacket(ProtocolNumber, pb);
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;

        const h = header.UDP.init(mut_pkt.data.first() orelse return);
        mut_pkt.data.trimFront(header.UDPMinimumSize);

        const node = self.stack.allocator.create(std.TailQueue(Packet).Node) catch return;
        node.data = .{
            .data = mut_pkt.data, 
            .sender_addr = .{
                .nic = r.nic.id,
                .addr = id.remote_address,
                .port = h.sourcePort(),
            },
        };

        self.mutex.lock();
        const was_empty = self.rcv_list.first == null;
        self.rcv_list.append(node);
        self.mutex.unlock();

        if (was_empty) {
            self.waiter_queue.notify(waiter.EventIn);
        }
    }

    pub fn endpoint(self: *UDPEndpoint) tcpip.Endpoint {
        return .{
            .ptr = self,
            .vtable = &EndpointVTableImpl,
        };
    }

    const EndpointVTableImpl = tcpip.Endpoint.VTable{
        .close = close_external,
        .read = read,
        .write = write_external,
        .connect = connect,
        .shutdown = shutdown,
        .listen = listen,
        .accept = accept,
        .bind = bind,
        .getLocalAddress = getLocalAddress,
        .getRemoteAddress = getRemoteAddress,
    };

    fn read(ptr: *anyopaque, addr: ?*tcpip.FullAddress) tcpip.Error!buffer.View {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();

        const node = self.rcv_list.popFirst() orelse return tcpip.Error.WouldBlock;
        defer self.stack.allocator.destroy(node);

        if (addr) |a| {
            a.* = node.data.sender_addr;
        }

        return node.data.data.toView(self.stack.allocator) catch return tcpip.Error.NoBufferSpace;
    }

    fn write_external(ptr: *anyopaque, p: tcpip.Payloader, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        const data_buf = try p.fullPayload();
        
        var views = [_]buffer.View{@constCast(data_buf)};
        const data = buffer.VectorisedView.init(data_buf.len, &views);

        if (opts.to) |to| {
            const local_addr = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
            
            const net_proto: u16 = switch (to.addr) {
                .v4 => 0x0800,
                .v6 => 0x86dd,
            };
            var r = try self.stack.findRoute(to.nic, local_addr.addr, to.addr, net_proto);
            
            self.stack.mutex.lock();
            if (self.stack.link_addr_cache.get(to.addr)) |link_addr| {
                r.remote_link_address = link_addr;
            }
            self.stack.mutex.unlock();

            try self.write(&r, to.port, data);
        } else if (self.remote_addr) |to| {
            const local_addr = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
            
            const net_proto: u16 = switch (to.addr) {
                .v4 => 0x0800,
                .v6 => 0x86dd,
            };
            var r = try self.stack.findRoute(to.nic, local_addr.addr, to.addr, net_proto);
            
            self.stack.mutex.lock();
            if (self.stack.link_addr_cache.get(to.addr)) |link_addr| {
                r.remote_link_address = link_addr;
            }
            self.stack.mutex.unlock();

            try self.write(&r, to.port, data);
        } else {
            return tcpip.Error.DestinationRequired;
        }
        
        return data_buf.len;
    }

    fn connect(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.remote_addr = addr;
        return;
    }

    fn bind(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.local_addr = addr;
        
        const id = stack.TransportEndpointID{
            .local_port = addr.port,
            .local_address = addr.addr,
            .remote_port = 0,
            .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } },
        };
        try self.stack.registerTransportEndpoint(id, self.transportEndpoint());
        
        return;
    }

    fn shutdown(ptr: *anyopaque, flags: u8) tcpip.Error!void {
        _ = ptr; _ = flags;
        return;
    }

    fn listen(ptr: *anyopaque, backlog: i32) tcpip.Error!void {
        _ = ptr; _ = backlog;
        return tcpip.Error.UnknownProtocol;
    }

    fn accept(ptr: *anyopaque) tcpip.Error!tcpip.AcceptReturn {
        _ = ptr;
        return tcpip.Error.UnknownProtocol;
    }

    fn getLocalAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        _ = ptr;
        return tcpip.Error.UnknownProtocol;
    }

    fn getRemoteAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        _ = ptr;
        return tcpip.Error.UnknownProtocol;
    }
};
