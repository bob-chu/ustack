const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const header = @import("../../header.zig");
const buffer = @import("../../buffer.zig");

/// A LinkEndpoint implementation for Linux TUN/TAP devices.
pub const Tap = struct {
    fd: std.posix.fd_t,
    mtu_val: u32 = 1500,
    address: [6]u8 = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }, // Default fake MAC
    
    // To be set by stack.NIC.attach()
    dispatcher: ?*stack.NetworkDispatcher = null,

    /// Initialize a TAP device by name (e.g., "tap0").
    /// Note: This requires CAP_NET_ADMIN privileges.
    pub fn init(dev_name: []const u8) !Tap {
        // Open the clone device
        const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        
        // IFF_TAP | IFF_NO_PI
        const IFF_TAP: c_short = 0x0002;
        const IFF_NO_PI: c_short = 0x1000;
        const TUNSETIFF: c_ulong = 0x400454ca; // _IOW('T', 202, int) on x86_64. 
        // Note: Magic number depends on architecture. Zig's std.os.linux.ioctl might work better if we had ifreq definitions.
        
        // Construct ifreq struct manually
        var ifr: extern struct {
            name: [16]u8,
            flags: c_short,
            padding: [22]u8 = [_]u8{0} ** 22, // Pad to 40 bytes (sizeof ifreq is usually 40)
        } = undefined;
        
        @memset(&ifr.name, 0);
        const copy_len = @min(dev_name.len, 15);
        @memcpy(ifr.name[0..copy_len], dev_name[0..copy_len]);
        ifr.flags = IFF_TAP | IFF_NO_PI;
        
        const rc = std.os.linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            else => return error.TunsetiffFailed,
        }
        
        return Tap{
            .fd = fd,
        };
    }
    
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
        _ = r; _ = protocol;
        
        // We need to linearize the packet for write().
        // In a high-performance implementation, use writev() with the scatter-gather view directly.
        const total_len = pkt.header.usedLength() + pkt.data.size;
        
        // For simplicity, we allocate a buffer. 
        // Optimization TODO: Use a pre-allocated write buffer or writev.
        var buf = std.heap.page_allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(buf);
        
        const hdr_len = pkt.header.usedLength();
        @memcpy(buf[0..hdr_len], pkt.header.view());
        
        // Copy data
        const view = pkt.data.toView(std.heap.page_allocator) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(view);
        @memcpy(buf[hdr_len..], view);
        
        _ = std.posix.write(self.fd, buf) catch return tcpip.Error.UnknownDevice;
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
    
    /// Read a packet from the device and inject it into the stack.
    /// This should be called by the event loop when the FD is readable.
    pub fn readPacket(self: *Tap) !void {
        var buf: [9000]u8 = undefined; // Support up to Jumbo
        const len = std.posix.read(self.fd, &buf) catch |err| {
            if (err == error.WouldBlock) return;
            return err;
        };
        if (len == 0) return; // EOF
        
        // Parse Ethernet Header
        if (len < header.EthernetMinimumSize) return;
        const eth = header.Ethernet.init(buf[0..len]);
        const eth_type = eth.etherType();
        
        // Create PacketBuffer
        // The stack expects to own the memory or have a valid view.
        // We allocate a copy here because 'buf' is on the stack.
        const payload_buf = try std.heap.page_allocator.alloc(u8, len - header.EthernetMinimumSize);
        // Note: Caller (UDP/TCP endpoint) handles freeing logic or cloning if needed.
        // But for safety, our UDP stack now clones.
        // However, if the stack dispatch is synchronous, we must free it after dispatch.
        // If async/queued, we must NOT free it. 
        // ustack is currently synchronous dispatch.
        
        @memcpy(payload_buf, buf[header.EthernetMinimumSize..len]);
        
        var views = [1]buffer.View{payload_buf};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload_buf.len, &views),
            .header = buffer.Prependable.init(&[_]u8{}),
        };
        
        if (self.dispatcher) |d| {
            d.deliverNetworkPacket(eth.sourceAddress(), eth.destinationAddress(), eth_type, pkt);
        }
        
        // Since ustack handles cloning in endpoints if needed, we should be able to free here IF synchronous.
        // But wait, what if it's queued in an IP fragment reassembly list?
        // IPv4 reassembly clones.
        // So we can free here.
        std.heap.page_allocator.free(payload_buf);
    }
};
