const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const AfPacketEndpoint = @import("af_packet_adapter.zig").AfPacketEndpoint;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var s = try stack.Stack.init(allocator);
    
    var af_packet = try AfPacketEndpoint.init(1);
    try s.createNIC(1, af_packet.linkEndpoint());

    std.debug.print("Example: AF_PACKET + Libev starting...\n", .{});
    
    // ev_io_init(&io, cb, af_packet.fd, EV_READ);
}
