const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const header = @import("../../header.zig");
const buffer = @import("../../buffer.zig");
const log = @import("../../log.zig").scoped(.af_packet);
const stats = @import("../../stats.zig");

pub const AfPacket = struct {
    fd: std.posix.fd_t,
    allocator: std.mem.Allocator,
    cluster_pool: *buffer.ClusterPool,
    view_pool: buffer.BufferPool,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    if_index: i32 = 0,
    dispatcher: ?*stack.NetworkDispatcher = null,

    pub fn init(allocator: std.mem.Allocator, pool: *buffer.ClusterPool, dev_name: []const u8) !AfPacket {
        const protocol = @as(u16, @bitCast(std.mem.nativeToBig(u16, header.ETH_P_ALL)));
        const fd = try std.posix.socket(std.posix.AF.PACKET, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, protocol);
        errdefer std.posix.close(fd);

        const buf_size: i32 = 10 * 1024 * 1024; // 10MB
        try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&buf_size));
        try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&buf_size));

        const ignore_outgoing: i32 = 1;
        _ = std.posix.setsockopt(fd, 263, 23, std.mem.asBytes(&ignore_outgoing)) catch {};

        const if_index = try getIfIndex(fd, dev_name);

        var ll_addr = std.posix.sockaddr.ll{
            .family = std.posix.AF.PACKET,
            .protocol = protocol,
            .ifindex = if_index,
            .hatype = 0,
            .pkttype = 0,
            .halen = 0,
            .addr = [_]u8{0} ** 8,
        };
        try std.posix.bind(fd, @as(*const std.posix.sockaddr, @ptrCast(&ll_addr)), @sizeOf(std.posix.sockaddr.ll));

        const mac = try getIfMac(fd, dev_name);

        return AfPacket{
            .fd = fd,
            .allocator = allocator,
            .cluster_pool = pool,
            .view_pool = buffer.BufferPool.init(allocator, @sizeOf(buffer.ClusterView) * 1, 4096),
            .if_index = if_index,
            .address = .{ .addr = mac },
        };
    }

    pub fn linkEndpoint(self: *AfPacket) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .writePackets = writePackets_wrapper,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
            },
        };
    }

    fn writePackets_wrapper(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        for (packets) |p| {
            try writePacket(self, r, protocol, p);
        }
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

    fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
        return 0;
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        _ = r;
        _ = protocol;

        const hdr_len = pkt.header.usedLength();
        const total_len = hdr_len + pkt.data.size;

        var buf: [9014]u8 = undefined;
        if (total_len > buf.len) return tcpip.Error.MessageTooLong;

        @memcpy(buf[0..hdr_len], pkt.header.view());
        var off = hdr_len;
        for (pkt.data.views) |v| {
            @memcpy(buf[off .. off + v.view.len], v.view);
            off += v.view.len;
        }

        _ = std.posix.send(self.fd, buf[0..total_len], 0) catch |err| {
            if (err == error.WouldBlock) return tcpip.Error.WouldBlock;
            return tcpip.Error.BadLinkEndpoint;
        };

        stats.global_link_stats.tx_packets += 1;
        stats.global_link_stats.tx_bytes += total_len;
    }

    pub fn readPacket(self: *AfPacket) !bool {
        var num_read: usize = 0;
        const max_batch = 512;

        while (num_read < max_batch) {
            const c = self.cluster_pool.acquire() catch {
                stats.global_stats.tcp.pool_exhausted += 1;
                return num_read > 0;
            };

            const n = std.posix.recv(self.fd, &c.data, 0) catch |err| {
                c.release();
                if (err == error.WouldBlock) break;
                return err;
            };

            if (n == 0) {
                c.release();
                break;
            }

            if (n < header.EthernetMinimumSize) {
                c.release();
                continue;
            }

            // std.debug.print("RX: n={} src={any} type={x}\n", .{ n, c.data[6..12], std.mem.readInt(u16, c.data[12..14], .big) });

            if (std.mem.eql(u8, c.data[6..12], &self.address.addr)) {
                c.release();
                continue;
            }

            stats.global_link_stats.rx_packets += 1;
            stats.global_link_stats.rx_bytes += n;

            const view_mem = self.view_pool.acquire() catch {
                stats.global_stats.tcp.pool_exhausted += 1;
                c.release();
                return num_read > 0;
            };
            const original_views = @as([]buffer.ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem))));
            original_views[0] = .{ .cluster = c, .view = c.data[0..n] };

            const pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(n, original_views[0..1]),
                .header = buffer.Prependable.init(&[_]u8{}),
                .timestamp_ns = @intCast(std.time.nanoTimestamp()),
            };
            var mut_pkt = pkt;
            mut_pkt.data.original_views = original_views;
            mut_pkt.data.view_pool = &self.view_pool;

            if (self.dispatcher) |d| {
                const dummy_mac = tcpip.LinkAddress{ .addr = [_]u8{0} ** 6 };
                d.deliverNetworkPacket(&dummy_mac, &dummy_mac, 0, mut_pkt);
            }

            mut_pkt.data.deinit();
            num_read += 1;
        }

        return num_read > 0;
    }

    fn getIfIndex(fd: std.posix.fd_t, name: []const u8) !i32 {
        var ifr: std.os.linux.ifreq = undefined;
        @memset(std.mem.asBytes(&ifr), 0);
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.ifrn.name[0..copy_len], name[0..copy_len]);
        try ioctl(fd, header.SIOCGIFINDEX, @intFromPtr(&ifr));
        return ifr.ifru.ivalue;
    }

    fn getIfMac(fd: std.posix.fd_t, name: []const u8) ![6]u8 {
        var ifr: std.os.linux.ifreq = undefined;
        @memset(std.mem.asBytes(&ifr), 0);
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.ifrn.name[0..copy_len], name[0..copy_len]);
        try ioctl(fd, header.SIOCGIFHWADDR, @intFromPtr(&ifr));
        var mac: [6]u8 = undefined;
        const sockaddr_ptr = @as([*]const u8, @ptrCast(&ifr.ifru.hwaddr));
        @memcpy(&mac, sockaddr_ptr[2..8]);
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
