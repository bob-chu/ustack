const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const header = @import("../../header.zig");
const buffer = @import("../../buffer.zig");

/// A LinkEndpoint implementation for Linux AF_PACKET (Raw Sockets).
/// This allows sending/receiving raw Ethernet frames on a physical interface.
pub const AfPacket = struct {
    fd: std.posix.fd_t,
    allocator: std.mem.Allocator,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    if_index: i32,

    dispatcher: ?*stack.NetworkDispatcher = null,

    /// Initialize an AF_PACKET socket bound to a specific interface.
    /// dev_name: e.g. "eth0", "lo".
    /// Requires CAP_NET_RAW.
    pub fn init(allocator: std.mem.Allocator, dev_name: []const u8) !AfPacket {
        // ETH_P_ALL (big endian)
        const protocol = std.mem.nativeToBig(u16, header.ETH_P_ALL);
        const fd = try std.posix.socket(std.posix.AF.PACKET, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, protocol);
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
            .allocator = allocator,
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
        _ = r;
        _ = protocol;

        const total_len = pkt.header.usedLength() + pkt.data.size;
        // std.debug.print("Tx Packet on {}, len={}\n", .{ self.fd, total_len });
        var buf = self.allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
        defer self.allocator.free(buf);

        const hdr_len = pkt.header.usedLength();
        @memcpy(buf[0..hdr_len], pkt.header.view());

        const view = pkt.data.toView(self.allocator) catch return tcpip.Error.NoBufferSpace;
        defer self.allocator.free(view);
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

    pub fn readPacket(self: *AfPacket) !bool {
        var buf: [9000]u8 = undefined;
        const len = std.posix.read(self.fd, &buf) catch |err| {
            if (err == error.WouldBlock) return false;
            return err;
        };
        if (len == 0) return false;

        // Debug Log
        // std.debug.print("Rx Packet on {}, len={}\n", .{ self.fd, len });

        // Pass the FULL frame to the dispatcher (EthernetEndpoint expects it)
        const frame_buf = try self.allocator.alloc(u8, len);
        @memcpy(frame_buf, buf[0..len]);

        var views = [1]buffer.View{frame_buf};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(frame_buf.len, &views),
            .header = buffer.Prependable.init(&[_]u8{}),
        };

        if (self.dispatcher) |d| {
            // We pass dummy MACs/type because EthernetEndpoint will parse the real ones from the frame
            const dummy_mac = tcpip.LinkAddress{ .addr = [_]u8{0} ** 6 };
            d.deliverNetworkPacket(&dummy_mac, &dummy_mac, 0, pkt);
        }

        self.allocator.free(frame_buf);
        return true;
    }

    // Helpers for IOCTL
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
        // In libc's ifreq, hwaddr is a sockaddr, and MAC is in sa_data[0..6]
        // We use a raw pointer to get the data from the sockaddr part.
        const sockaddr_ptr = @as([*]const u8, @ptrCast(&ifr.ifru.hwaddr));
        @memcpy(&mac, sockaddr_ptr[2..8]); // sockaddr.family is 2 bytes, then data
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
