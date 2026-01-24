const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const AfXdp = ustack.drivers.af_xdp.AfXdp;

// Conceptual AF_XDP (Express Data Path) adapter for Zig
// This provides a LinkEndpoint compatible with the stack using the real AfXdp driver.
pub const AfXdpEndpoint = struct {
    driver: AfXdp,

    pub fn init(allocator: std.mem.Allocator, if_name: []const u8) !AfXdpEndpoint {
        const driver = try AfXdp.init(allocator, if_name, 0);
        return AfXdpEndpoint{ .driver = driver };
    }

    pub fn linkEndpoint(self: *AfXdpEndpoint) stack.LinkEndpoint {
        return self.driver.linkEndpoint();
    }

    pub fn deinit(self: *AfXdpEndpoint) void {
        self.driver.deinit();
    }

    // Call this when RX ring has data
    pub fn onReadable(self: *AfXdpEndpoint) !void {
        try self.driver.poll();
    }
};
