const std = @import("std");
const tcpip = @import("tcpip.zig");
const stack = @import("stack.zig");
const header = @import("header.zig");
const waiter = @import("waiter.zig");
const buffer = @import("buffer.zig");
const log = @import("log.zig").scoped(.dns);

pub const Resolver = struct {
    stack: *stack.Stack,
    allocator: std.mem.Allocator,
    dns_server: tcpip.Address,

    pub fn init(s: *stack.Stack, dns_server: tcpip.Address) Resolver {
        return .{
            .stack = s,
            .allocator = s.allocator,
            .dns_server = dns_server,
        };
    }

    pub fn resolve(self: *Resolver, hostname: []const u8) !tcpip.Address {
        var wq = waiter.Queue{};
        const udp_proto = self.stack.transport_protocols.get(header.UDP.ProtocolNumber).?;

        // Determine protocol based on DNS server address family
        const net_proto: u16 = switch (self.dns_server) {
            .v4 => @import("network/ipv4.zig").ProtocolNumber,
            .v6 => @import("network/ipv6.zig").ProtocolNumber,
        };

        var ep = try udp_proto.newEndpoint(self.stack, net_proto, &wq);
        defer ep.close();

        // Try to find specific source address to bind to (avoids INADDR_ANY routing issues)
        var bind_addr = switch (self.dns_server) {
            .v4 => tcpip.Address{ .v4 = .{ 0, 0, 0, 0 } },
            .v6 => tcpip.Address{ .v6 = [_]u8{0} ** 16 },
        };

        // Find address on NIC 1 (default)
        if (self.stack.nics.get(1)) |nic| {
            for (nic.addresses.items) |pa| {
                if (std.meta.activeTag(pa.address_with_prefix.address) == std.meta.activeTag(self.dns_server)) {
                    bind_addr = pa.address_with_prefix.address;
                    break;
                }
            }
        }

        // Bind to ephemeral port
        try ep.bind(.{ .nic = 1, .addr = bind_addr, .port = 0 });

        // Debug: check assigned port
        if (ep.getLocalAddress()) |la| {
            log.debug("DNS: Bound to port {}", .{la.port});
        } else |_| {}

        // Build DNS query
        var dns_buf = try self.allocator.alloc(u8, 512);
        defer self.allocator.free(dns_buf);

        var idx: usize = 0;

        // Header
        @memset(dns_buf[0..header.DNSHeaderSize], 0);
        var h = header.DNS.init(dns_buf[0..header.DNSHeaderSize]);
        const query_id = @as(u16, @intCast(std.time.milliTimestamp() & 0xFFFF));
        h.setId(query_id);
        h.setFlags(0x0100); // Standard Query, Recursion Desired
        h.setQuestionCount(1);
        idx += header.DNSHeaderSize;

        // Question: Name
        var it = std.mem.split(u8, hostname, ".");
        while (it.next()) |label| {
            if (label.len > 63) return error.LabelTooLong;
            dns_buf[idx] = @intCast(label.len);
            idx += 1;
            @memcpy(dns_buf[idx..][0..label.len], label);
            idx += label.len;
        }
        dns_buf[idx] = 0;
        idx += 1; // Root label

        // Question: Type (A=1) and Class (IN=1)
        std.mem.writeInt(u16, dns_buf[idx..][0..2], 1, .big);
        idx += 2;
        std.mem.writeInt(u16, dns_buf[idx..][0..2], 1, .big);
        idx += 2;

        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader {
                return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
            }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
            }
        };
        var fp = Payloader{ .data = dns_buf[0..idx] };

        const dest = tcpip.FullAddress{
            .nic = 0, // Route lookup
            .addr = self.dns_server,
            .port = 53,
        };

        // Send Query
        while (true) {
            _ = ep.write(fp.payloader(), .{ .to = &dest }) catch |err| {
                if (err == tcpip.Error.WouldBlock) {
                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                }
                return err;
            };
            break;
        }

        // Wait for response with timeout
        var timeout: usize = 0;
        while (timeout < 500) : (timeout += 1) { // 5 seconds
            var packet = ep.read(null) catch |err| {
                if (err == tcpip.Error.WouldBlock) {
                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                }
                return err;
            };
            defer packet.deinit();

            if (packet.size < header.DNSHeaderSize) continue;

            const packet_flat = try packet.toView(self.allocator);
            defer self.allocator.free(packet_flat);

            const resp_h = header.DNS.init(@constCast(packet_flat[0..header.DNSHeaderSize]));

            if (resp_h.id() != query_id) continue;

            // Basic parsing
            // Skip header
            var pos: usize = header.DNSHeaderSize;

            // Skip questions
            var q_count = resp_h.questionCount();
            while (q_count > 0) : (q_count -= 1) {
                while (pos < packet_flat.len and packet_flat[pos] != 0) {
                    pos += packet_flat[pos] + 1;
                }
                pos += 1; // Skip null
                pos += 4; // Skip Type + Class
            }

            // Parse Answers
            var ans_count = resp_h.answerCount();

            while (ans_count > 0 and pos < packet_flat.len) : (ans_count -= 1) {
                // Name
                if (packet_flat[pos] & 0xC0 == 0xC0) {
                    pos += 2; // Pointer
                } else {
                    while (pos < packet_flat.len and packet_flat[pos] != 0) {
                        pos += packet_flat[pos] + 1;
                    }
                    pos += 1;
                }

                if (pos + 10 > packet_flat.len) break;
                const rtype = std.mem.readInt(u16, packet_flat[pos..][0..2], .big);
                const rclass = std.mem.readInt(u16, packet_flat[pos + 2 ..][0..2], .big);
                _ = rclass;
                // TTL (4)
                const rdlen = std.mem.readInt(u16, packet_flat[pos + 8 ..][0..2], .big);
                pos += 10;

                if (pos + rdlen > packet_flat.len) break;

                if (rtype == 1 and rdlen == 4) { // A Record
                    var ip: [4]u8 = undefined;
                    @memcpy(&ip, packet_flat[pos..][0..4]);
                    return tcpip.Address{ .v4 = ip };
                }
                pos += rdlen;
            }
        }

        return error.DnsTimeout;
    }
};

test "DNS Query and Response Parsing" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var udp_proto = @import("transport/udp.zig").UDPProtocol.init(allocator);
    try s.registerTransportProtocol(udp_proto.protocol());

    var ipv4_proto = @import("network/ipv4.zig").IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    var fake_link = struct {
        last_pkt: ?[]u8 = null,
        allocator: std.mem.Allocator,

        fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = r;
            _ = protocol;
            const hdr_view = pkt.header.view();
            const data_len = pkt.data.size;
            if (self.last_pkt) |p| self.allocator.free(p);
            self.last_pkt = self.allocator.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
            var offset = hdr_view.len;
            for (pkt.data.views) |v| {
                @memcpy(self.last_pkt.?[offset .. offset + v.view.len], v.view);
                offset += v.view.len;
            }
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            _ = ptr;
            return .{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } };
        }
        fn mtu(ptr: *anyopaque) u32 {
            _ = ptr;
            return 1500;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            _ = ptr;
            _ = m;
        }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
            _ = ptr;
            return stack.CapabilityNone;
        }
    }{ .allocator = allocator };
    defer if (fake_link.last_pkt) |p| allocator.free(p);

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).mtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{
        .protocol = 0x0800,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 0, 0, 1 } }, .prefix_len = 24 },
    });
    // Add default route
    try s.addRoute(.{
        .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
        .gateway = .{ .v4 = .{ 10, 0, 0, 254 } },
        .nic = 1,
        .mtu = 1500,
    });
    // Add ARP entry for gateway
    try s.addLinkAddress(.{ .v4 = .{ 10, 0, 0, 254 } }, .{ .addr = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } });

    const dns_server = tcpip.Address{ .v4 = .{ 8, 8, 8, 8 } };
    var resolver = Resolver.init(&s, dns_server);

    // Run resolver in a separate thread because it blocks
    const ThreadContext = struct {
        resolver: *Resolver,
        result: ?tcpip.Address = null,
        done: bool = false,
    };
    var ctx = ThreadContext{ .resolver = &resolver };

    const t = try std.Thread.spawn(.{}, struct {
        fn run(c: *ThreadContext) void {
            c.result = c.resolver.resolve("example.com") catch null;
            c.done = true;
        }
    }.run, .{&ctx});

    // Wait for query to be sent
    while (fake_link.last_pkt == null) {
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    // Verify Query Packet
    // IP(20) + UDP(8) + DNS(12) + QName(13: 7example3com0) + QType(2) + QClass(2) = 57 bytes
    const pkt = fake_link.last_pkt.?;
    try std.testing.expect(pkt.len >= 28 + 12);

    // Extract Query ID
    const query_id = std.mem.readInt(u16, pkt[28..30], .big); // UDP payload starts at 28 (20+8)
    _ = query_id; // Unused but kept for documentation

    // Construct Response
    // 1 Answer: example.com A 93.184.216.34
    var resp_buf = try allocator.alloc(u8, 512);
    defer allocator.free(resp_buf);

    // Copy query as base
    const query_len = pkt.len - 28;
    @memcpy(resp_buf[0..query_len], pkt[28..]);

    // Update Header
    // ID matches
    // Flags: QR=1, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0 -> 0x8180
    std.mem.writeInt(u16, resp_buf[2..4], 0x8180, .big);
    // ANCOUNT = 1
    std.mem.writeInt(u16, resp_buf[6..8], 1, .big);

    var idx = query_len;
    // Answer Section
    // Name: Pointer to 0xC00C (offset 12)
    resp_buf[idx] = 0xC0;
    idx += 1;
    resp_buf[idx] = 0x0C;
    idx += 1;
    // Type: A (1)
    std.mem.writeInt(u16, resp_buf[idx..][0..2], 1, .big);
    idx += 2;
    // Class: IN (1)
    std.mem.writeInt(u16, resp_buf[idx..][0..2], 1, .big);
    idx += 2;
    // TTL: 60
    std.mem.writeInt(u32, resp_buf[idx..][0..4], 60, .big);
    idx += 4;
    // RDLength: 4
    std.mem.writeInt(u16, resp_buf[idx..][0..2], 4, .big);
    idx += 2;
    // RData: 93.184.216.34
    resp_buf[idx] = 93;
    idx += 1;
    resp_buf[idx] = 184;
    idx += 1;
    resp_buf[idx] = 216;
    idx += 1;
    resp_buf[idx] = 34;
    idx += 1;

    // Inject Response
    // We need to find the UDP endpoint bound to the source port
    const src_port = std.mem.readInt(u16, pkt[20..22], .big);

    // We need to inject at UDP layer or Network layer?
    // Let's inject at UDP layer via handlePacket
    const udp_ep_id = stack.TransportEndpointID{
        .local_port = src_port,
        .local_address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .remote_port = 0,
        .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } },
    };
    _ = udp_ep_id;

    // We need to reconstruct UDP header for handlePacket
    var full_resp = try allocator.alloc(u8, 8 + idx);
    defer allocator.free(full_resp);

    var udp_h = header.UDP.init(full_resp[0..8]);
    udp_h.setSourcePort(53);
    udp_h.setDestinationPort(src_port);
    udp_h.setLength(@as(u16, @intCast(8 + idx)));
    udp_h.setChecksum(0);
    @memcpy(full_resp[8..], resp_buf[0..idx]);

    var full_views = [_]buffer.ClusterView{.{ .cluster = null, .view = full_resp }};
    const full_pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(full_resp.len, &full_views),
        .header = buffer.Prependable.init(&[_]u8{}),
    };

    // Use _ to suppress unused variable error for resp_pkt as we use full_pkt

    // Deliver to stack
    const r = stack.Route{
        .local_address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 8, 8, 8, 8 } },
        .local_link_address = .{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } },
        .remote_link_address = .{ .addr = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } },
        .net_proto = 0x0800,
        .nic = nic,
    };

    s.transportDispatcher().deliverTransportPacket(&r, 17, full_pkt);

    // Give the thread a moment to process the packet
    // Since we are running in a test environment, the 'resolver' running in the thread
    // might block on `read` if the notification doesn't wake it up or if it misses the event.
    // However, `deliverTransportPacket` calls `ep.handlePacket` which calls `notify`.
    // The resolver thread is in a loop checking for `WouldBlock`.
    // We just need to wait long enough.

    // Wait for done with timeout
    var wait_count: usize = 0;
    while (!ctx.done and wait_count < 100) : (wait_count += 1) {
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    // Detach or join? We can't join if it's blocked forever.
    // But it has a 5s timeout internally.
    if (!ctx.done) {
        // If test fails here, the thread is still running.
        // We can't cancel it easily.
        // Just fail.
    } else {
        t.join();
    }

    try std.testing.expect(ctx.done);
    try std.testing.expect(ctx.result != null);
    const ip = ctx.result.?.v4;
    try std.testing.expectEqual(@as(u8, 93), ip[0]);
    try std.testing.expectEqual(@as(u8, 184), ip[1]);
    try std.testing.expectEqual(@as(u8, 216), ip[2]);
    try std.testing.expectEqual(@as(u8, 34), ip[3]);
}
