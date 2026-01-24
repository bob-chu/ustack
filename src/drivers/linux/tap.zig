const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const header = @import("../../header.zig");
const buffer = @import("../../buffer.zig");

extern fn my_tuntap_init(fd: i32, name: [*:0]const u8) i32;

/// A LinkEndpoint implementation for Linux TUN/TAP devices.
pub const Tap = struct {
    fd: std.posix.fd_t,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } }, // Default fake MAC

    // To be set by stack.NIC.attach()
    dispatcher: ?*stack.NetworkDispatcher = null,

    /// Initialize a TAP device by name (e.g., "tap0").
    /// Note: This requires CAP_NET_ADMIN privileges.
    pub fn init(dev_name: []const u8) !Tap {
        const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0);

        // Use C wrapper to avoid struct layout issues
        const name_c = try std.heap.page_allocator.dupeZ(u8, dev_name);
        defer std.heap.page_allocator.free(name_c);

        const rc = my_tuntap_init(fd, name_c);
        if (rc < 0) {
            std.debug.print("my_tuntap_init failed: rc={}\n", .{rc});
            return error.TunsetiffFailed;
        }

        // Set interface up and assign IP via our new C helpers
        // Use 10.0.0.1 for the host side of the tap
        _ = my_set_if_up(name_c);
        _ = my_set_if_addr(name_c, "10.0.0.1");

        return Tap{
            .fd = fd,
        };
    }

    extern fn my_set_if_up(name: [*:0]const u8) i32;
    extern fn my_set_if_addr(name: [*:0]const u8, addr: [*:0]const u8) i32;

    /// Initialize from an existing file descriptor.
    /// Useful if the FD is passed from a privileged parent process.
    pub fn initFromFd(fd: std.posix.fd_t) Tap {
        return Tap{
            .fd = fd,
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
            },
        };
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        _ = r;
        _ = protocol;

        // We need to linearize the packet for write().
        const total_len = pkt.header.usedLength() + pkt.data.size;

        var buf = std.heap.page_allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(buf);

        const hdr_len = pkt.header.usedLength();
        @memcpy(buf[0..hdr_len], pkt.header.view());

        // Copy data
        const view = pkt.data.toView(std.heap.page_allocator) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(view);
        @memcpy(buf[hdr_len..], view);

        const rc = std.os.linux.write(self.fd, buf.ptr, buf.len);
        if (std.posix.errno(rc) != .SUCCESS) {
            std.debug.print("writePacket failed: fd={}, rc={}, err={}\n", .{ self.fd, rc, std.posix.errno(rc) });
            return tcpip.Error.UnknownDevice;
        }
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
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
        var buf: [9000]u8 = undefined; // Support up to Jumbo
        const len = std.posix.read(self.fd, &buf) catch |err| {
            if (err == error.WouldBlock) return false;
            return err;
        };
        if (len == 0) return false; // EOF

        var views = [1]buffer.View{buf[0..len]};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(len, &views),
            .header = buffer.Prependable.init(&[_]u8{}),
        };

        if (self.dispatcher) |d| {
            const dst_mac = tcpip.LinkAddress{ .addr = buf[0..6].* };
            const src_mac = tcpip.LinkAddress{ .addr = buf[6..12].* };
            d.deliverNetworkPacket(&src_mac, &dst_mac, 0, pkt);
        }

        return true;
    }
};
