const std = @import("std");
const ustack = @import("ustack");
const posix = ustack.posix;
const waiter = ustack.waiter;

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    const args = try std.process.argsAlloc(allocator);
    if (args.len < 4) return;
    const mode = args[2];

    var s = try ustack.init(allocator);
    var af = try ustack.drivers.af_packet.AfPacket.init(allocator, &s.cluster_pool, args[1]);
    var eth = ustack.link.eth.EthernetEndpoint.init(af.linkEndpoint(), af.address);
    eth.linkEndpoint().setMTU(9000);
    try s.createNIC(1, eth.linkEndpoint());
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0806, .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 } });
    var parts = std.mem.split(u8, args[3], "/");
    const local_ip = try parseIp(parts.first());
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = local_ip }, .prefix_len = 24 } });
    try s.addRoute(.{ .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 }, .gateway = .{ .v4 = .{ 0, 0, 0, 0 } }, .nic = 1, .mtu = 9000 });

    posix.init(allocator);
    const fd = try posix.usocket(&s, std.posix.AF.INET, std.posix.SOCK.STREAM, 0);

    if (std.mem.eql(u8, mode, "server")) {
        const addr = std.posix.sockaddr.in{ .family = std.posix.AF.INET, .port = std.mem.nativeToBig(u16, 5201), .addr = 0, .zero = [_]u8{0} ** 8 };
        try posix.ubind(fd, @as(std.posix.sockaddr, @bitCast(addr)), @sizeOf(std.posix.sockaddr.in));
        try posix.ulisten(fd, 10);
        std.debug.print("Server listening...\n", .{});
        while (true) {
            _ = af.readPacket() catch {};
            s.flush();
            const afd = posix.uaccept(fd, null, null) catch { std.time.sleep(100 * std.time.ns_per_us); continue; };
            std.debug.print("Accepted fd={}\n", .{afd});
            var buf: [16384]u8 = undefined;
            while (true) {
                _ = af.readPacket() catch {};
                s.flush();
                const n = posix.urecv(afd, &buf, 0) catch |err| { if (err == error.WouldBlock) { std.time.sleep(10 * std.time.ns_per_us); continue; } break; };
                if (n == 0) break;
            }
            posix.uclose(afd);
        }
    } else {
        const target_ip = try parseIp(args[4]);
        const l_addr = std.posix.sockaddr.in{ .family = std.posix.AF.INET, .port = 0, .addr = @bitCast(local_ip), .zero = [_]u8{0} ** 8 };
        try posix.ubind(fd, @as(std.posix.sockaddr, @bitCast(l_addr)), @sizeOf(std.posix.sockaddr.in));
        const r_addr = std.posix.sockaddr.in{ .family = std.posix.AF.INET, .port = std.mem.nativeToBig(u16, 5201), .addr = @bitCast(target_ip), .zero = [_]u8{0} ** 8 };
        _ = posix.uconnect(fd, @as(std.posix.sockaddr, @bitCast(r_addr)), @sizeOf(std.posix.sockaddr.in)) catch |err| { if (err != error.WouldBlock) return err; };
        const sock = try posix.getSocket(fd);
        while (!sock.endpoint.ready(waiter.EventOut)) { _ = af.readPacket() catch {}; s.flush(); std.time.sleep(100 * std.time.ns_per_us); }
        std.debug.print("Connected!\n", .{});
        const payload = [_]u8{'A'} ** 8000;
        var total: u64 = 0;
        const start = std.time.milliTimestamp();
        while (std.time.milliTimestamp() - start < 2000) {
            _ = af.readPacket() catch {};
            s.flush();
            const n = posix.usend(fd, &payload, 0) catch |err| { 
                if (err == error.WouldBlock) { std.time.sleep(10 * std.time.ns_per_us); continue; }
                std.debug.print("Send error: {}\n", .{err});
                break;
            };
            total += n;
        }
        std.debug.print("Throughput: {d:.2} Mbps\n", .{ (@as(f64, @floatFromInt(total)) * 8.0) / 2.0 / 1000000.0 });
    }
}
fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |j| out[j] = try std.fmt.parseInt(u8, it.next() orelse "0", 10);
    return out;
}
