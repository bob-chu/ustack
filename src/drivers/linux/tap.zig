const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const header = @import("../../header.zig");
const buffer = @import("../../buffer.zig");
const log = @import("../../log.zig").scoped(.tap);
const stats = @import("../../stats.zig");

extern fn my_tuntap_init(fd: i32, name: [*:0]const u8) i32;

/// A LinkEndpoint implementation for Linux TUN/TAP devices.
pub const Tap = struct {
    fd: std.posix.fd_t,
    allocator: std.mem.Allocator,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } }, // Default fake MAC

    // To be set by stack.NIC.attach()
    dispatcher: ?*stack.NetworkDispatcher = null,
    cluster_pool: ?*buffer.ClusterPool = null,
    view_pool: buffer.BufferPool,
    header_pool: buffer.BufferPool,
    tx_buf: [16384]u8 = undefined, // Max jumbo frame + headers

    /// Initialize a TAP device by name (e.g., "tap0").
    /// Note: This requires CAP_NET_ADMIN privileges.
    pub fn init(allocator: std.mem.Allocator, dev_name: []const u8) !Tap {
        const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0);

        // Use C wrapper to avoid struct layout issues
        const name_c = try allocator.dupeZ(u8, dev_name);
        defer allocator.free(name_c);

        const rc = my_tuntap_init(fd, name_c);
        if (rc < 0) {
            log.err("my_tuntap_init failed: rc={}", .{rc});
            return error.TunsetiffFailed;
        }

        // Set interface up and assign IP via our new C helpers
        // Use 10.0.0.1 for the host side of the tap
        _ = my_set_if_up(name_c);
        _ = my_set_if_addr(name_c, "10.0.0.1");

        return Tap{
            .fd = fd,
            .allocator = allocator,
            .view_pool = buffer.BufferPool.init(allocator, @sizeOf(buffer.ClusterView) * header.MaxViewsPerPacket, 4096),
            .header_pool = buffer.BufferPool.init(allocator, header.ReservedHeaderSize, 4096),
        };
    }

    extern fn my_set_if_up(name: [*:0]const u8) i32;
    extern fn my_set_if_addr(name: [*:0]const u8, addr: [*:0]const u8) i32;

    /// Initialize from an existing file descriptor.
    /// Useful if the FD is passed from a privileged parent process.
    pub fn initFromFd(allocator: std.mem.Allocator, fd: std.posix.fd_t) Tap {
        return Tap{
            .fd = fd,
            .allocator = allocator,
            .view_pool = buffer.BufferPool.init(allocator, @sizeOf(buffer.ClusterView) * header.MaxViewsPerPacket, 4096),
            .header_pool = buffer.BufferPool.init(allocator, header.ReservedHeaderSize, 4096),
        };
    }

    /// Returns the link endpoint interface to register with the Stack.
    pub fn linkEndpoint(self: *Tap) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
                .close = close,
            },
        };
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        self.view_pool.deinit();
        self.header_pool.deinit();
        std.posix.close(self.fd);
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        _ = r;
        _ = protocol;

        const total_len = pkt.header.usedLength() + pkt.data.size;
        if (total_len > self.tx_buf.len) return tcpip.Error.MessageTooLong;

        // Copy header into tx_buf
        const hdr_len = pkt.header.usedLength();
        @memcpy(self.tx_buf[0..hdr_len], pkt.header.view());

        // Copy data views directly (avoid toView allocation)
        var offset: usize = hdr_len;
        for (pkt.data.views) |v| {
            @memcpy(self.tx_buf[offset..][0..v.view.len], v.view);
            offset += v.view.len;
        }

        const rc = std.os.linux.write(self.fd, &self.tx_buf, total_len);
        if (std.posix.errno(rc) != .SUCCESS) {
            log.err("writePacket failed: fd={}, rc={}, err={}", .{ self.fd, rc, std.posix.errno(rc) });
            return tcpip.Error.UnknownDevice;
        }
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
        const nic = @as(*stack.NIC, @ptrCast(@alignCast(dispatcher.ptr)));
        self.cluster_pool = &nic.stack.cluster_pool;
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityNone;
    }

    pub fn readPacket(self: *Tap) !bool {
        const cp = self.cluster_pool orelse return false;
        const c = cp.acquire() catch {
            stats.global_stats.pool.cluster_exhausted += 1;
            return false;
        };

        const len = std.posix.read(self.fd, &c.data) catch |err| {
            c.release();
            if (err == error.WouldBlock) return false;
            return err;
        };
        if (len == 0) {
            c.release();
            return false;
        }

        const h_buf = self.header_pool.acquire() catch {
            c.release();
            return false;
        };

        const view_mem = self.view_pool.acquire() catch {
            self.header_pool.release(h_buf);
            c.release();
            return false;
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
            const dst_mac = tcpip.LinkAddress{ .addr = c.data[0..6].* };
            const src_mac = tcpip.LinkAddress{ .addr = c.data[6..12].* };
            d.deliverNetworkPacket(&src_mac, &dst_mac, 0, mut_pkt);
        }

        self.header_pool.release(h_buf);
        mut_pkt.data.deinit();

        return true;
    }
};
