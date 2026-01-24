const std = @import("std");

pub fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |i| {
        const part = it.next() orelse return error.InvalidIP;
        out[i] = try std.fmt.parseInt(u8, part, 10);
    }
    return out;
}

pub const Cidr = struct {
    address: [4]u8,
    prefix_len: u8,
};

pub fn parseCidr(str: []const u8) !Cidr {
    var it = std.mem.split(u8, str, "/");
    const ip_part = it.first();
    const prefix_part = it.next();

    const address = try parseIp(ip_part);
    const prefix_len = if (prefix_part) |p| try std.fmt.parseInt(u8, p, 10) else 32;

    return Cidr{
        .address = address,
        .prefix_len = prefix_len,
    };
}
