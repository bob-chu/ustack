const std = @import("std");
const tcpip = @import("tcpip.zig");

pub fn parseIp(str: []const u8) !tcpip.Address {
    if (std.mem.indexOf(u8, str, ":") != null) {
        // Parse IPv6
        var out: [16]u8 = undefined;
        // Basic parsing for full IPv6 or shortened with ::
        // Zig's std.net.IpAddress.parse might be useful if available, but we need [16]u8
        // Let's implement a basic one or use std.net
        const addr = try std.net.Ip6Address.parse(str, 0);
        @memcpy(&out, &addr.sa.addr);
        return tcpip.Address{ .v6 = out };
    } else {
        // Parse IPv4
        var it = std.mem.split(u8, str, ".");
        var out: [4]u8 = undefined;
        for (0..4) |i| {
            const part = it.next() orelse return error.InvalidIP;
            out[i] = try std.fmt.parseInt(u8, part, 10);
        }
        return tcpip.Address{ .v4 = out };
    }
}

pub const Cidr = struct {
    address: tcpip.Address,
    prefix_len: u8,
};

pub fn parseCidr(str: []const u8) !Cidr {
    var it = std.mem.split(u8, str, "/");
    const ip_part = it.first();
    const prefix_part = it.next();

    const address = try parseIp(ip_part);
    const prefix_len = if (prefix_part) |p| try std.fmt.parseInt(u8, p, 10) else switch (address) {
        .v4 => 32,
        .v6 => 128,
    };

    return Cidr{
        .address = address,
        .prefix_len = prefix_len,
    };
}
