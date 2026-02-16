const std = @import("std");
const stack = @import("stack.zig");
const tcpip = @import("tcpip.zig");
const utils = @import("utils.zig");

// Drivers
const AfPacket = @import("drivers/linux/af_packet.zig").AfPacket;
const AfXdp = @import("drivers/linux/af_xdp.zig").AfXdp;
const Tap = @import("drivers/linux/tap.zig").Tap;
const EthernetEndpoint = @import("link/eth.zig").EthernetEndpoint;
const Loopback = @import("drivers/loopback.zig").Loopback;

pub const DriverType = enum {
    af_packet,
    af_xdp,
    tap,
    loopback,
};

pub const InterfaceConfig = struct {
    name: []const u8,
    driver: DriverType,
    address: ?[]const u8 = null, // Supports IPv4 or IPv6
    prefix: u8 = 24,
    gateway: ?[]const u8 = null,
    queue_id: u32 = 0,
    mtu: u32 = 1500,
};

pub const NetworkInterface = struct {
    allocator: std.mem.Allocator,
    stack: *stack.Stack,
    nic_id: tcpip.NICID,

    driver: union(DriverType) {
        af_packet: AfPacket,
        af_xdp: AfXdp,
        tap: Tap,
        loopback: Loopback,
    },
    eth_endpoint: *EthernetEndpoint,

    pub fn init(allocator: std.mem.Allocator, s: *stack.Stack, cfg: InterfaceConfig) !*NetworkInterface {
        const self = try allocator.create(NetworkInterface);
        self.allocator = allocator;
        self.stack = s;
        self.nic_id = s.allocNicId();

        // 1. Init Driver
        switch (cfg.driver) {
            .af_packet => {
                self.driver = .{ .af_packet = try AfPacket.init(allocator, &s.cluster_pool, cfg.name) };
            },
            .af_xdp => {
                self.driver = .{ .af_xdp = try AfXdp.init(allocator, &s.cluster_pool, cfg.name, cfg.queue_id) };
            },
            .tap => {
                self.driver = .{ .tap = try Tap.init(allocator, cfg.name) };
            },
            .loopback => {
                self.driver = .{ .loopback = Loopback.init(allocator) };
            },
        }

        // 2. Wrap in Ethernet Endpoint
        const link_ep = switch (self.driver) {
            .af_packet => |*d| d.linkEndpoint(),
            .af_xdp => |*d| d.linkEndpoint(),
            .tap => |*d| d.linkEndpoint(),
            .loopback => |*d| d.linkEndpoint(),
        };
        const mac = switch (self.driver) {
            .af_packet => |*d| d.address,
            .af_xdp => |*d| d.address,
            .tap => |*d| d.address,
            .loopback => |*d| d.address,
        };

        self.eth_endpoint = try allocator.create(EthernetEndpoint);
        self.eth_endpoint.* = EthernetEndpoint.init(link_ep, mac);

        // 3. Create NIC in Stack
        try s.createNIC(self.nic_id, self.eth_endpoint.linkEndpoint());
        const nic = s.nics.get(self.nic_id).?;

        // 4. Add Addresses
        // ARP is always needed for Ethernet
        try nic.addAddress(.{
            .protocol = 0x0806,
            .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
        });

        if (cfg.address) |ip_str| {
            const addr = try utils.parseIp(ip_str);
            const protocol: tcpip.NetworkProtocolNumber = switch (addr) {
                .v4 => 0x0800,
                .v6 => 0x86dd,
            };

            try nic.addAddress(.{
                .protocol = protocol,
                .address_with_prefix = .{ .address = addr, .prefix_len = cfg.prefix },
            });

            // Route to subnet
            try s.addRoute(.{
                .destination = .{ .address = addr, .prefix = cfg.prefix },
                .gateway = switch (addr) {
                    .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                    .v6 => .{ .v6 = [_]u8{0} ** 16 },
                },
                .nic = self.nic_id,
                .mtu = cfg.mtu,
            });
        }

        // 5. Add Default Gateway
        if (cfg.gateway) |gw_str| {
            const gw_addr = try utils.parseIp(gw_str);
            try s.addRoute(.{
                .destination = switch (gw_addr) {
                    .v4 => .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
                    .v6 => .{ .address = .{ .v6 = [_]u8{0} ** 16 }, .prefix = 0 },
                },
                .gateway = gw_addr,
                .nic = self.nic_id,
                .mtu = cfg.mtu,
            });
        }

        return self;
    }

    pub fn deinit(self: *NetworkInterface) void {
        switch (self.driver) {
            .af_packet => |*d| _ = d, // AfPacket struct has no deinit, just closes fd on destroy if owned? No, wait.
            .af_xdp => |*d| d.deinit(),
            .tap => |*d| _ = d,
            .loopback => |*d| _ = d,
        }
        // Ideally we should close FDs here for packet/tap too if not handled.
        // Currently existing drivers don't have consistent deinit patterns.
        // Let's rely on OS cleanup for now or add deinit to them later.

        self.allocator.destroy(self.eth_endpoint);
        self.allocator.destroy(self);
    }

    pub fn getFd(self: *NetworkInterface) std.posix.fd_t {
        return switch (self.driver) {
            .af_packet => |d| d.fd,
            .af_xdp => |d| d.fd,
            .tap => |d| d.fd,
            .loopback => -1,
        };
    }

    pub fn process(self: *NetworkInterface) !void {
        switch (self.driver) {
            .af_packet => |*d| {
                while (true) {
                    const more = d.readPacket() catch |err| {
                        if (err == error.WouldBlock) return;
                        return err;
                    };
                    if (!more) break;
                }
            },
            .af_xdp => |*d| try d.poll(),
            .tap => |*d| {
                while (true) {
                    const more = d.readPacket() catch |err| {
                        if (err == error.WouldBlock) return;
                        return err;
                    };
                    if (!more) break;
                }
            },
            .loopback => |*d| d.tick(),
        }
    }
};

test "InterfaceConfig MTU propagates to routes" {
    const main = @import("main.zig");
    const allocator = std.testing.allocator;

    var s = try main.init(allocator);
    defer s.deinit();

    const iface = try NetworkInterface.init(allocator, &s, .{
        .name = "lo",
        .driver = .loopback,
        .address = "10.0.0.1",
        .prefix = 24,
        .mtu = 9000,
    });
    defer iface.deinit();

    var found_9000 = false;
    var found_1500 = false;

    for (s.route_table.routes.items) |entry| {
        if (entry.mtu == 9000) found_9000 = true;
        if (entry.mtu == 1500) found_1500 = true;
    }

    try std.testing.expect(found_9000);
    try std.testing.expect(!found_1500);
}
