const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const AfXdpEndpoint = @import("af_xdp_adapter.zig").AfXdpEndpoint;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var s = try stack.Stack.init(allocator);
    
    var xdp = try AfXdpEndpoint.init("eth0");
    try s.createNIC(1, xdp.linkEndpoint());

    std.debug.print("Example: AF_XDP + Libev starting...\n", .{});
    
    // ev_io_init(&io, cb, xdp.xsk_fd, EV_READ);
}
