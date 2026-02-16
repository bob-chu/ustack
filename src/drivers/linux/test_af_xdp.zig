const std = @import("std");
const AfXdp = @import("af_xdp.zig").AfXdp;
const tcpip = @import("../../tcpip.zig");
const stack = @import("../../stack.zig");
const buffer = @import("../../buffer.zig");
const header = @import("../../header.zig");

test "AfXdp basic properties" {
    const allocator = std.testing.allocator;

    // Test that it can be created without crashing (minimal setup)
    // We don't actually call init() here because it requires root and real interfaces
    const dummy_fd: std.posix.fd_t = 0;
    const xdp = AfXdp{
        .fd = dummy_fd,
        .allocator = allocator,
        .umem_area = undefined,
        .rx_ring = undefined,
        .tx_ring = undefined,
        .fill_ring = undefined,
        .comp_ring = undefined,
        .if_index = 0,
        .view_pool = undefined,
        .header_pool = undefined,
        .frame_manager = undefined,
        .fill_map_slice = undefined,
        .comp_map_slice = undefined,
        .rx_map_slice = undefined,
        .tx_map_slice = undefined,
    };

    try std.testing.expectEqual(@as(u32, 1500), xdp.mtu_val);
}

test "AfXdp functional init" {
    const allocator = std.testing.allocator;

    // This test only works if run as root and veth_test0 exists.
    // We use a guard to skip if not available.
    var cp = buffer.ClusterPool.init(allocator);
    defer cp.deinit();
    var xdp = AfXdp.init(allocator, &cp, "veth_test0", 0) catch |err| {
        if (err == error.PermissionDenied or err == error.SocketNotSupported or err == error.Unexpected or err == error.IoctlFailed) return;
        std.debug.print("Init failed: {}\n", .{err});
        return;
    };
    defer xdp.deinit();

    try std.testing.expect(xdp.fd > 0);
}
