const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const header = @import("../../header.zig");
const buffer = @import("../../buffer.zig");
const log = @import("../../log.zig").scoped(.af_packet);

pub const AfPacket = struct {
    fd: std.posix.fd_t,
    allocator: std.mem.Allocator,
    cluster_pool: *buffer.ClusterPool,
    view_pool: buffer.BufferPool,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    if_index: i32 = 0,
    rx_clusters: [64]?*buffer.Cluster = [_]?*buffer.Cluster{null} ** 64,
    dispatcher: ?*stack.NetworkDispatcher = null,

    pub fn init(allocator: std.mem.Allocator, pool: *buffer.ClusterPool, dev_name: []const u8) !AfPacket {
        const protocol = std.mem.nativeToBig(u16, header.ETH_P_ALL);
        const fd = try std.posix.socket(std.posix.AF.PACKET, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, protocol);
        errdefer std.posix.close(fd);

        const if_index = try getIfIndex(fd, dev_name);

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

        const mac = try getIfMac(fd, dev_name);

        const buf_size: i32 = 64 * 1024 * 1024;
        try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&buf_size));
        try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&buf_size));

        return AfPacket{
            .fd = fd,
            .allocator = allocator,
            .cluster_pool = pool,
            .view_pool = buffer.BufferPool.init(allocator, @sizeOf(buffer.ClusterView) * 1, 1024),
            .if_index = if_index,
            .address = .{ .addr = mac },
            .rx_clusters = [_]?*buffer.Cluster{null} ** 64,
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
        _ = r;
        _ = protocol;
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        return self.writePackets(packets);
    }

    pub fn writePackets(self: *AfPacket, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        const batch_size = 64;
        var msgvec: [batch_size]std.os.linux.mmsghdr = undefined;
        var iovecs: [batch_size][header.MaxViewsPerPacket + 1]std.posix.iovec = undefined;

        var i: usize = 0;
        while (i < packets.len) {
            const current_batch = @min(packets.len - i, batch_size);
            for (0..current_batch) |j| {
                const pkt = packets[i + j];
                const hdr_view = pkt.header.view();
                iovecs[j][0] = .{ .base = @constCast(hdr_view.ptr), .len = hdr_view.len };

                var iov_cnt: usize = 1;
                for (pkt.data.views) |v| {
                    if (iov_cnt >= iovecs[j].len) break;
                    iovecs[j][iov_cnt] = .{ .base = @constCast(v.view.ptr), .len = v.view.len };
                    iov_cnt += 1;
                }

                msgvec[j] = .{
                    .msg_hdr = .{
                        .name = null,
                        .namelen = 0,
                        .iov = @as([*]std.posix.iovec, @ptrCast(&iovecs[j])),
                        .iovlen = @as(i32, @intCast(iov_cnt)),
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    },
                    .msg_len = 0,
                };
            }

            const res = std.os.linux.syscall4(.sendmmsg, @as(usize, @intCast(self.fd)), @intFromPtr(&msgvec), current_batch, 0);
            if (std.posix.errno(res) != .SUCCESS) {
                if (std.posix.errno(res) == .AGAIN) return tcpip.Error.WouldBlock;
                return tcpip.Error.UnknownDevice;
            }
            i += current_batch;
        }
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        _ = r; _ = protocol;
        const p = [_]tcpip.PacketBuffer{pkt};
        return self.writePackets(&p);
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

    pub fn readPacket(self: *AfPacket) !bool {
        const batch_size = 64;
        var msgvec: [batch_size]std.os.linux.mmsghdr = undefined;
        var iovecs: [batch_size]std.posix.iovec = undefined;

        var i: usize = 0;
        while (i < batch_size) : (i += 1) {
            if (self.rx_clusters[i]) |c| {
                if (c.ref_count.load(.monotonic) > 1) {
                    c.release();
                    self.rx_clusters[i] = null;
                }
            }
            if (self.rx_clusters[i] == null) {
                self.rx_clusters[i] = try self.cluster_pool.acquire();
            }
            const c = self.rx_clusters[i].?;
            iovecs[i] = .{ .base = &c.data, .len = c.data.len };
            msgvec[i] = .{
                .msg_hdr = .{
                    .name = null,
                    .namelen = 0,
                    .iov = @as([*]std.posix.iovec, @ptrCast(&iovecs[i])),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .msg_len = 0,
            };
        }

        const count_raw = std.os.linux.syscall5(.recvmmsg, @as(usize, @intCast(self.fd)), @intFromPtr(&msgvec), batch_size, std.posix.MSG.DONTWAIT, 0);
        const signed_count = @as(isize, @bitCast(count_raw));
        if (signed_count < 0) {
            const err_num = @as(std.os.linux.E, @enumFromInt(@as(i32, @intCast(-signed_count))));
            if (err_num == .AGAIN) return false;
            return error.Unexpected;
        }

        const num_received = @as(usize, @intCast(signed_count));
        if (num_received == 0) return false;

        for (0..num_received) |j| {
            const len = msgvec[j].msg_len;
            if (len == 0) continue;

            const c = self.rx_clusters[j].?;
            // We increment refcount because we are giving a reference to the stack.
            // Our reference in rx_clusters[j] remains.
            c.acquire();

            const view_mem = try self.view_pool.acquire();
            const original_views = @as([]buffer.ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem))));
            original_views[0] = .{ .cluster = c, .view = c.data[0..len] };

            const pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(len, original_views[0..1]),
                .header = buffer.Prependable.init(&[_]u8{}),
            };
            var mut_pkt = pkt;
            mut_pkt.data.original_views = original_views;
            mut_pkt.data.view_pool = &self.view_pool;

            if (self.dispatcher) |d| {
                const dummy_mac = tcpip.LinkAddress{ .addr = [_]u8{0} ** 6 };
                d.deliverNetworkPacket(&dummy_mac, &dummy_mac, 0, mut_pkt);
            }

            mut_pkt.data.deinit(); // This releases the reference we just gave to the stack (or the one stack kept).

            // Now check if stack kept it. If refcount > 1, it means stack kept it.
            if (c.ref_count.load(.monotonic) > 1) {
                c.release(); // Release our reference in rx_clusters
                self.rx_clusters[j] = null;
            }
        }

        return true;
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
