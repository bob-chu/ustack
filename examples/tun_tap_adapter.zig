const std = @import("std");
const os = std.os;
const stack = @import("../src/stack.zig");
const tcpip = @import("../src/tcpip.zig");
const header = @import("../src/header.zig");
const buffer = @import("../src/buffer.zig");

// Simple Linux Tun/Tap wrapper
pub const TunTapEndpoint = struct {
    fd: std.os.fd_t,
    mtu_val: u32 = 1500,
    address: [6]u8 = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }, // Fake MAC
    
    // To be set by stack.NIC
    dispatcher: ?*stack.NetworkDispatcher = null,
    wrapped_dispatcher: stack.NetworkDispatcher = undefined,

    pub fn init(dev_name: []const u8) !TunTapEndpoint {
        const fd = try std.os.open("/dev/net/tun", std.os.O.RDWR, 0);
        
        // Setup TUN/TAP interface (simplified, usually requires ioctl)
        // struct ifreq ifr;
        // memset(&ifr, 0, sizeof(ifr));
        // ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        // strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
        // ioctl(fd, TUNSETIFF, (void *) &ifr);
        
        // Since we can't easily do ioctl in pure Zig without defining structs manually or using cImport,
        // we'll mock the FD part or assume the user passes an open FD in a real scenario.
        // For this example, we'll focus on the interface adaptation.
        
        return TunTapEndpoint{
            .fd = fd,
        };
    }
    
    pub fn initFromFd(fd: std.os.fd_t) TunTapEndpoint {
        return TunTapEndpoint{
            .fd = fd,
        };
    }

    pub fn linkEndpoint(self: *TunTapEndpoint) stack.LinkEndpoint {
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

    // Stack calls this to send a packet OUT
    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*TunTapEndpoint, @ptrCast(@alignCast(ptr)));
        _ = r; _ = protocol;
        
        // Flatten packet for writing to FD
        const total_len = pkt.header.usedLength() + pkt.data.size;
        // In a real app, use writev to avoid allocation
        var buf = std.heap.page_allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(buf);
        
        const hdr_len = pkt.header.usedLength();
        @memcpy(buf[0..hdr_len], pkt.header.view());
        
        // Copy data
        const view = pkt.data.toView(std.heap.page_allocator) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(view);
        @memcpy(buf[hdr_len..], view);
        
        _ = std.os.write(self.fd, buf) catch return tcpip.Error.UnknownDevice;
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*TunTapEndpoint, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*TunTapEndpoint, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*TunTapEndpoint, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*TunTapEndpoint, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityNone;
    }
    
    // Call this when FD is readable
    pub fn onReadable(self: *TunTapEndpoint) !void {
        var buf: [9000]u8 = undefined; // Support up to Jumbo
        const len = try std.os.read(self.fd, &buf);
        if (len == 0) return;
        
        // Parse Ethernet Header
        if (len < header.EthernetMinimumSize) return;
        const eth = header.Ethernet.init(buf[0..len]);
        const eth_type = eth.etherType();
        
        // Create PacketBuffer
        // Note: In a real system, you'd use a buffer pool
        var payload_buf = std.heap.page_allocator.alloc(u8, len - header.EthernetMinimumSize) catch return;
        @memcpy(payload_buf, buf[header.EthernetMinimumSize..len]);
        
        var views = [_]buffer.View{payload_buf};
        var pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload_buf.len, &views),
            .header = undefined, // No header prepended yet
        };
        
        if (self.dispatcher) |d| {
            // Pass up to Network Layer (Stack)
            d.deliverNetworkPacket(eth.sourceAddress(), eth.destinationAddress(), eth_type, pkt);
        }
        
        // Cleanup? deliverNetworkPacket is synchronous in this stack, 
        // but normally data is copied or consumed.
        // Our VectorisedView doesn't own data by default unless we structured it that way.
        // Here we allocated payload_buf. Who frees it?
        // Current stack implementation copies data out usually.
        // So we should free it here if synchronous.
        std.heap.page_allocator.free(payload_buf);
    }
};
