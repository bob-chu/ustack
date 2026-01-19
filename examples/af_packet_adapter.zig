const std = @import("std");
const os = std.os;
const stack = @import("../src/stack.zig");
const tcpip = @import("../src/tcpip.zig");
const header = @import("../src/header.zig");
const buffer = @import("../src/buffer.zig");

// Linux AF_PACKET wrapper
pub const AfPacketEndpoint = struct {
    fd: std.os.fd_t,
    mtu_val: u32 = 1500,
    address: [6]u8 = [_]u8{ 0, 0, 0, 0, 0, 0 },
    
    dispatcher: ?*stack.NetworkDispatcher = null,
    wrapped_dispatcher: stack.NetworkDispatcher = undefined,

    pub fn init(if_index: i32) !AfPacketEndpoint {
        // socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
        // Simplified for example: using mock FD or standard socket creation if available
        // Zig's std.os.socket supports AF_PACKET on Linux
        
        // const fd = try std.os.socket(std.os.AF.PACKET, std.os.SOCK.RAW, std.mem.nativeToBig(u16, 0x0003)); // ETH_P_ALL
        
        // Bind to interface
        // var addr = std.os.sockaddr.ll{
        //     .family = std.os.AF.PACKET,
        //     .protocol = std.mem.nativeToBig(u16, 0x0003),
        //     .ifindex = if_index,
        //     ...
        // };
        // try std.os.bind(fd, &addr.any, @sizeOf(std.os.sockaddr.ll));
        
        const fd: std.os.fd_t = 0; // Mocked
        
        return AfPacketEndpoint{
            .fd = fd,
        };
    }

    pub fn linkEndpoint(self: *AfPacketEndpoint) stack.LinkEndpoint {
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
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        _ = r; _ = protocol;
        
        // Prepare buffer
        const total_len = pkt.header.usedLength() + pkt.data.size;
        var buf = std.heap.page_allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(buf);
        
        const hdr_len = pkt.header.usedLength();
        @memcpy(buf[0..hdr_len], pkt.header.view());
        const view = pkt.data.toView(std.heap.page_allocator) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(view);
        @memcpy(buf[hdr_len..], view);
        
        // sendto/write to raw socket
        _ = std.os.write(self.fd, buf) catch return tcpip.Error.UnknownDevice;
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityNone;
    }
    
    pub fn onReadable(self: *AfPacketEndpoint) !void {
        var buf: [9000]u8 = undefined;
        // recvfrom(fd, ...)
        const len = try std.os.read(self.fd, &buf);
        if (len < header.EthernetMinimumSize) return;
        
        const eth = header.Ethernet.init(buf[0..len]);
        const eth_type = eth.etherType();
        
        var payload_buf = std.heap.page_allocator.alloc(u8, len - header.EthernetMinimumSize) catch return;
        @memcpy(payload_buf, buf[header.EthernetMinimumSize..len]);
        
        var views = [_]buffer.View{payload_buf};
        var pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload_buf.len, &views),
            .header = undefined,
        };
        
        if (self.dispatcher) |d| {
            d.deliverNetworkPacket(eth.sourceAddress(), eth.destinationAddress(), eth_type, pkt);
        }
        std.heap.page_allocator.free(payload_buf);
    }
};
