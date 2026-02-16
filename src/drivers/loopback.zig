const std = @import("std");
const stack = @import("../stack.zig");
const tcpip = @import("../tcpip.zig");
const buffer = @import("../buffer.zig");
const log = @import("../log.zig").scoped(.loopback);

/// A simple LinkEndpoint for loopback.
/// It queues packets and delivers them on tick() to avoid recursive deadlocks.
pub const Loopback = struct {
    dispatcher: ?*stack.NetworkDispatcher = null,
    mtu_val: u32 = 65536,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } },
    queue: std.TailQueue(Packet),
    allocator: std.mem.Allocator,

    const Packet = struct {
        protocol: tcpip.NetworkProtocolNumber,
        pkt: tcpip.PacketBuffer,
    };

    pub fn init(allocator: std.mem.Allocator) Loopback {
        return .{
            .queue = .{},
            .allocator = allocator,
        };
    }

    pub fn linkEndpoint(self: *Loopback) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .writePackets = writePackets,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
            },
        };
    }

    fn writePackets(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        for (packets) |p| {
            try writePacket(ptr, r, protocol, p);
        }
    }

    pub fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*Loopback, @ptrCast(@alignCast(ptr)));
        _ = r;

        const node = self.allocator.create(std.TailQueue(Packet).Node) catch return tcpip.Error.OutOfMemory;
        node.data = .{
            .protocol = protocol,
            .pkt = pkt.clone(self.allocator) catch {
                self.allocator.destroy(node);
                return tcpip.Error.NoBufferSpace;
            },
        };
        self.queue.append(node);
    }

    pub fn tick(self: *Loopback) void {
        while (self.queue.popFirst()) |node| {
            log.debug("Loopback: Delivering packet proto=0x{x}", .{node.data.protocol});
            if (self.dispatcher) |d| {
                d.deliverNetworkPacket(&self.address, &self.address, node.data.protocol, node.data.pkt);
            }
            node.data.pkt.data.deinit();
            self.allocator.destroy(node);
        }
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*Loopback, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*Loopback, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*Loopback, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*Loopback, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityLoopback;
    }
};
