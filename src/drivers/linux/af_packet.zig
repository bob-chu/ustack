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
    header_pool: buffer.BufferPool,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    if_index: i32 = 0,
    dispatcher: ?*stack.NetworkDispatcher = null,

    // Ring configuration
    rx_ring: []u8,
    tx_ring: []u8,
    rx_idx: usize = 0,
    tx_idx: usize = 0,
    frame_size: u32,
    frame_nr: u32,

    pub fn init(allocator: std.mem.Allocator, pool: *buffer.ClusterPool, dev_name: []const u8) !AfPacket {
        const protocol = @as(u16, @bitCast(std.mem.nativeToBig(u16, header.ETH_P_ALL)));
        const fd = try std.posix.socket(std.posix.AF.PACKET, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, protocol);
        errdefer std.posix.close(fd);

        // Set TPACKET_V2
        const version = @as(i32, header.TPACKET_V2);
        try std.posix.setsockopt(fd, 263, header.PACKET_VERSION, std.mem.asBytes(&version));

        // Ring settings: 16KB frames to support Jumbo frames
        const frame_size: u32 = 16384;
        const frame_nr: u32 = 8192;
        const block_size: u32 = 16384 * 128; // 2MB block
        const block_nr: u32 = (frame_size * frame_nr) / block_size;

        const req = header.tpacket_req{
            .tp_block_size = block_size,
            .tp_block_nr = block_nr,
            .tp_frame_size = frame_size,
            .tp_frame_nr = frame_nr,
        };

        try std.posix.setsockopt(fd, 263, header.PACKET_RX_RING, std.mem.asBytes(&req));
        try std.posix.setsockopt(fd, 263, header.PACKET_TX_RING, std.mem.asBytes(&req));

        const rx_ring_size = frame_size * frame_nr;
        const tx_ring_size = frame_size * frame_nr;
        const total_ring_size = rx_ring_size + tx_ring_size;

        const ring_ptr = try std.posix.mmap(null, total_ring_size, std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED }, fd, 0);
        errdefer std.posix.munmap(ring_ptr);

        const rx_ring_ptr = ring_ptr[0..rx_ring_size];
        const tx_ring_ptr = ring_ptr[rx_ring_size..total_ring_size];

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
            .view_pool = buffer.BufferPool.init(allocator, @sizeOf(buffer.ClusterView) * header.MaxViewsPerPacket, 16384),
            .header_pool = buffer.BufferPool.init(allocator, header.ReservedHeaderSize, 16384),
            .if_index = if_index,
            .address = .{ .addr = mac },
            .rx_ring = rx_ring_ptr,
            .tx_ring = tx_ring_ptr,
            .frame_size = frame_size,
            .frame_nr = frame_nr,
        };
    }

    pub fn linkEndpoint(self: *AfPacket) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket_external,
                .writePackets = writePackets_external,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu_external,
                .setMTU = setMTU_external,
                .capabilities = capabilities,
                .close = close_external,
                .flush = flush_external,
            },
        };
    }

    fn flush_external(ptr: *anyopaque) void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        self.flush();
    }

    pub fn flush(self: *AfPacket) void {
        // Kick kernel to send pending frames
        const start = std.time.nanoTimestamp();
        _ = std.os.linux.syscall6(.sendto, @as(usize, @intCast(self.fd)), 0, 0, 0, 0, 0);
        const end = std.time.nanoTimestamp();
        stats.global_stats.latency.driver_tx.record(@as(i64, @intCast(end - start)));
        stats.global_link_stats.tx_syscalls += 1;
    }

    fn close_external(ptr: *anyopaque) void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        self.deinit();
    }

    pub fn deinit(self: *AfPacket) void {
        const total_ring_size = self.frame_size * self.frame_nr * 2;
        const mmap_ptr = @as([*]align(std.mem.page_size) u8, @ptrCast(@alignCast(self.rx_ring.ptr)));
        std.posix.munmap(mmap_ptr[0..total_ring_size]);
        std.posix.close(self.fd);
    }

    fn writePackets_external(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        _ = r;
        _ = protocol;
        return self.writePackets(packets);
    }

    pub fn writePackets(self: *AfPacket, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        var any_sent = false;
        for (packets) |pkt| {
            const slot = self.tx_ring[self.tx_idx * self.frame_size .. (self.tx_idx + 1) * self.frame_size];
            var h = @as(*volatile header.tpacket2_hdr, @ptrCast(@alignCast(slot.ptr)));

            if (h.tp_status != header.TP_STATUS_KERNEL) {
                self.flush();
                if (h.tp_status != header.TP_STATUS_KERNEL) return tcpip.Error.WouldBlock;
            }

            const hdr_view = pkt.header.view();
            const data_off = @as(usize, std.mem.alignForward(usize, @sizeOf(header.tpacket2_hdr), 16));
            var current_off = data_off;

            const total_len = hdr_view.len + pkt.data.size;
            if (total_len + data_off > self.frame_size) return tcpip.Error.MessageTooLong;

            @memcpy(slot[current_off .. current_off + hdr_view.len], hdr_view);
            current_off += hdr_view.len;

            for (pkt.data.views) |v| {
                @memcpy(slot[current_off .. current_off + v.view.len], v.view);
                current_off += v.view.len;
            }

            h.tp_len = @as(u32, @intCast(total_len));
            h.tp_mac = @as(u16, @intCast(data_off));
            h.tp_net = @as(u16, @intCast(data_off + 14));
            h.tp_status = header.TP_STATUS_SEND_REQUEST;

            stats.global_link_stats.tx_packets += 1;
            stats.global_link_stats.tx_bytes += total_len;

            self.tx_idx = (self.tx_idx + 1) % self.frame_nr;
            any_sent = true;
        }
        if (any_sent) self.flush();
    }

    fn writePacket_external(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        _ = r;
        _ = protocol;
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

    fn mtu_external(ptr: *anyopaque) u32 {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU_external(ptr: *anyopaque, m: u32) void {
        const self = @as(*AfPacket, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
        return 0;
    }

    pub fn readPacket(self: *AfPacket) !bool {
        var num_read: usize = 0;
        const max_batch = 4096;
        const driver_start = std.time.nanoTimestamp();
        defer {
            if (num_read > 0) {
                const driver_end = std.time.nanoTimestamp();
                stats.global_stats.latency.driver_rx.record(@as(i64, @intCast(driver_end - driver_start)));
            }
        }
        while (num_read < max_batch) {
            const rx_slot = self.rx_ring[self.rx_idx * self.frame_size .. (self.rx_idx + 1) * self.frame_size];
            var h = @as(*volatile header.tpacket2_hdr, @ptrCast(@alignCast(rx_slot.ptr)));

            const status = h.tp_status;
            if ((status & header.TP_STATUS_USER) == 0) break;

            const len = h.tp_len;
            const data_start = h.tp_mac;
            if (data_start + len > self.frame_size) {
                // Invalid frame, skip
                h.tp_status = header.TP_STATUS_KERNEL;
                self.rx_idx = (self.rx_idx + 1) % self.frame_nr;
                continue;
            }
            const data = rx_slot[data_start .. data_start + len];

            // Filter out loopback (if source MAC is ours)
            if (std.mem.eql(u8, data[6..12], &self.address.addr)) {
                h.tp_status = header.TP_STATUS_KERNEL;
                self.rx_idx = (self.rx_idx + 1) % self.frame_nr;
                continue;
            }

            const c = self.cluster_pool.acquire() catch {
                stats.global_stats.pool.cluster_exhausted += 1;
                return num_read > 0;
            };
            @memcpy(c.data[0..len], data);

            h.tp_status = header.TP_STATUS_KERNEL;
            self.rx_idx = (self.rx_idx + 1) % self.frame_nr;

            const h_buf = self.header_pool.acquire() catch {
                c.release();
                return num_read > 0;
            };

            stats.global_link_stats.rx_packets += 1;
            stats.global_link_stats.rx_bytes += len;

            const view_mem = self.view_pool.acquire() catch {
                stats.global_stats.pool.view_exhausted += 1;
                self.header_pool.release(h_buf);
                c.release();
                return num_read > 0;
            };
            const original_views = @as([]buffer.ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem))));
            original_views[0] = .{ .cluster = c, .view = c.data[0..len] };

            const pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(len, original_views[0..1]),
                .header = buffer.Prependable.init(h_buf),
                .timestamp_ns = @intCast(std.time.nanoTimestamp()),
            };
            var mut_pkt = pkt;
            mut_pkt.data.original_views = original_views;
            mut_pkt.data.view_pool = &self.view_pool;

            if (self.dispatcher) |d| {
                const dummy_mac = tcpip.LinkAddress{ .addr = [_]u8{0} ** 6 };
                const pkt_proto = std.mem.readInt(u16, data[12..14], .big);
                d.deliverNetworkPacket(&dummy_mac, &dummy_mac, pkt_proto, mut_pkt);
            }
            self.header_pool.release(h_buf);
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
