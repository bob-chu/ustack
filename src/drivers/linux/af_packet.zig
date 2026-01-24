const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const header = @import("../../header.zig");
const buffer = @import("../../buffer.zig");

/// A LinkEndpoint implementation for Linux AF_PACKET (Raw Sockets).
/// This allows sending/receiving raw Ethernet frames on a physical interface.
pub const AfPacket = struct {
    fd: std.posix.fd_t,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    if_index: i32,
    
    dispatcher: ?*stack.NetworkDispatcher = null,

    /// Initialize an AF_PACKET socket bound to a specific interface.
    /// dev_name: e.g. "eth0", "lo".
    /// Requires CAP_NET_RAW.
    pub fn init(dev_name: []const u8) !AfPacket {
        // ETH_P_ALL = 0x0003 (big endian)
        const protocol = std.mem.nativeToBig(u16, 0x0003);
        const fd = try std.posix.socket(std.posix.AF.PACKET, std.posix.SOCK.RAW, protocol);
        errdefer std.posix.close(fd);

        // Get Interface Index
        const if_index = try getIfIndex(fd, dev_name);
        
        // Bind to interface
        var addr = std.posix.sockaddr.ll{
            .family = std.posix.AF.PACKET,
            .protocol = protocol,
            .ifindex = if_index,
            .hatype = 0,
            .pkttype = 0,
            .halen = 0,
            .addr = [_]u8{0} ** 8,
        };
        try std.posix.bind(fd, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(std.posix.sockaddr.ll));
        
        // Get Interface MAC Address
        const mac = try getIfMac(fd, dev_name);

        return AfPacket{
            .fd = fd,
            .if_index = if_index,
            .address = .{ .addr = mac },
        };
    }

    pub fn linkEndpoint(self: *AfPacket) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
            },
        };
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        _ = r; _ = protocol;
        
        const total_len = pkt.header.usedLength() + pkt.data.size;
        var buf = std.heap.page_allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(buf);
        
        const hdr_len = pkt.header.usedLength();
        @memcpy(buf[0..hdr_len], pkt.header.view());
        
        const view = pkt.data.toView(std.heap.page_allocator) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(view);
        @memcpy(buf[hdr_len..], view);
        
        _ = std.posix.write(self.fd, buf) catch return tcpip.Error.UnknownDevice;
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityNone;
    }

    pub fn readPacket(self: *AfPacket) !void {
        var buf: [9000]u8 = undefined;
        const len = std.posix.read(self.fd, &buf) catch |err| {
            if (err == error.WouldBlock) return;
            return err;
        };
        if (len == 0) return;

        if (len < header.EthernetMinimumSize) return;
        const eth = header.Ethernet.init(buf[0..len]);
        const eth_type = eth.etherType();
        
        // Skip own packets (loopback prevention if needed, though SOCK_RAW normally doesn't loop back unicast to self unless promiscuous)
        // But for AF_PACKET, we usually see everything.
        
        const payload_buf = try std.heap.page_allocator.alloc(u8, len - header.EthernetMinimumSize);
        @memcpy(payload_buf, buf[header.EthernetMinimumSize..len]);
        
        var views = [1]buffer.View{payload_buf};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload_buf.len, &views),
            .header = buffer.Prependable.init(&[_]u8{}),
        };
        
        if (self.dispatcher) |d| {
            const src = tcpip.LinkAddress{ .addr = eth.sourceAddress() };
            const dst = tcpip.LinkAddress{ .addr = eth.destinationAddress() };
            d.deliverNetworkPacket(&src, &dst, eth_type, pkt);
        }
        std.heap.page_allocator.free(payload_buf);
    }
    
    // Helpers for IOCTL
    fn getIfIndex(fd: std.posix.fd_t, name: []const u8) !i32 {
        var ifr: std.os.linux.ifreq = undefined;
        @memset(std.mem.asBytes(&ifr), 0);
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.ifr_ifrn.name[0..copy_len], name[0..copy_len]);
        
        try ioctl(fd, std.os.linux.SIOCGIFINDEX, @intFromPtr(&ifr));
        return ifr.ifru.ivalue;
    }
    
    fn getIfMac(fd: std.posix.fd_t, name: []const u8) ![6]u8 {
        var ifr: std.os.linux.ifreq = undefined;
        @memset(std.mem.asBytes(&ifr), 0);
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.ifr_ifrn.name[0..copy_len], name[0..copy_len]);
        
        try ioctl(fd, std.os.linux.SIOCGIFHWADDR, @intFromPtr(&ifr));
        var mac: [6]u8 = undefined;
        @memcpy(&mac, ifr.ifru.hwaddr.sa_data[0..6]);
        return mac;
    }
    
    fn ioctl(fd: std.posix.fd_t, req: u32, arg: usize) !void {
        const rc = std.os.linux.ioctl(fd, req, arg);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            else => return error.IoctlFailed,
        }
    }
};
