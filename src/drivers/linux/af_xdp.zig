const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const buffer = @import("../../buffer.zig");
const xdp = @import("xdp_defs.zig");

/// A LinkEndpoint implementation for Linux AF_XDP (Express Data Path).
pub const AfXdp = struct {
    fd: std.posix.fd_t,
    allocator: std.mem.Allocator,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    
    // UMEM
    umem_area: []align(std.mem.page_size) u8,
    
    // Rings
    rx_ring: Ring,
    tx_ring: Ring,
    fill_ring: Ring,
    comp_ring: Ring,

    dispatcher: ?*stack.NetworkDispatcher = null,

    const Ring = struct {
        producer: *volatile u32,
        consumer: *volatile u32,
        desc: [*]xdp.xdp_desc, // For RX/TX
        addr: [*]u64,          // For Fill/Comp
        size: u32,
        mask: u32,
    };

    const NUM_FRAMES = 2048;
    const FRAME_SIZE = 2048; // Must be power of 2 usually? Or just aligned. 2048 is standard.
    const RING_SIZE = 1024;

    pub fn init(allocator: std.mem.Allocator, if_name: []const u8, queue_id: u32) !AfXdp {
        const fd = try std.posix.socket(std.posix.AF.XDP, std.posix.SOCK.RAW, 0);
        errdefer std.posix.close(fd);

        // 1. Allocate UMEM (aligned to page size)
        const umem_size = NUM_FRAMES * FRAME_SIZE;
        const umem_area = try allocator.alignedAlloc(u8, std.mem.page_size, umem_size);
        errdefer allocator.free(umem_area);

        // 2. Register UMEM
        const reg = xdp.xdp_umem_reg{
            .addr = @intFromPtr(umem_area.ptr),
            .len = umem_size,
            .chunk_size = FRAME_SIZE,
            .headroom = 0,
        };
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_UMEM_REG, std.mem.asBytes(&reg));

        // 3. Configure Fill/Comp Rings
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_UMEM_FILL_RING, std.mem.asBytes(&@as(u32, RING_SIZE)));
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_UMEM_COMPLETION_RING, std.mem.asBytes(&@as(u32, RING_SIZE)));

        // 4. Configure RX/TX Rings
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_RX_RING, std.mem.asBytes(&@as(u32, RING_SIZE)));
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_TX_RING, std.mem.asBytes(&@as(u32, RING_SIZE)));

        // 5. Get Offsets
        var off: xdp.xdp_mmap_offsets = undefined;
        var off_len: u32 = @sizeOf(xdp.xdp_mmap_offsets);
        try getsockopt(fd, xdp.SOL_XDP, xdp.XDP_MMAP_OFFSETS, std.mem.asBytes(&off), &off_len);

        // 6. Mmap Rings
        const fill_map = try std.posix.mmap(null, off.fr.desc + RING_SIZE * @sizeOf(u64), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, fd, xdp.XDP_UMEM_PGOFF_FILL_RING);
        const comp_map = try std.posix.mmap(null, off.cr.desc + RING_SIZE * @sizeOf(u64), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, fd, xdp.XDP_UMEM_PGOFF_COMPLETION_RING);
        const rx_map = try std.posix.mmap(null, off.rx.desc + RING_SIZE * @sizeOf(xdp.xdp_desc), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, fd, xdp.XDP_PGOFF_RX_RING);
        const tx_map = try std.posix.mmap(null, off.tx.desc + RING_SIZE * @sizeOf(xdp.xdp_desc), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, fd, xdp.XDP_PGOFF_TX_RING);

        var self = AfXdp{
            .fd = fd,
            .allocator = allocator,
            .umem_area = umem_area,
            .fill_ring = initRing(fill_map, off.fr, RING_SIZE, true),
            .comp_ring = initRing(comp_map, off.cr, RING_SIZE, true),
            .rx_ring = initRing(rx_map, off.rx, RING_SIZE, false),
            .tx_ring = initRing(tx_map, off.tx, RING_SIZE, false),
        };

        // 7. Bind
        // Need to get ifindex first. Using helper from af_packet driver logic or reimplementing.
        const ifindex = try getIfIndex(if_name);
        std.debug.print("AF_XDP: Binding to {s} (index={}) queue={}\n", .{if_name, ifindex, queue_id});
        
        var sa = xdp.sockaddr_xdp{
            .family = std.posix.AF.XDP,
            .flags = 0, // Let kernel choose (prefer zero-copy, fallback to copy)
            .ifindex = ifindex,
            .queue_id = queue_id,
            .shared_umem_fd = 0,
        };
        try std.posix.bind(fd, @as(*const std.posix.sockaddr, @ptrCast(&sa)), @sizeOf(xdp.sockaddr_xdp));

        // 8. Populate Fill Ring
        // Give all frames to kernel for RX initially
        var prod = self.fill_ring.producer.*;
        for (0..RING_SIZE) |i| {
            self.fill_ring.addr[prod & self.fill_ring.mask] = i * FRAME_SIZE;
            prod += 1;
        }
        self.fill_ring.producer.* = prod; // Publish

        return self;
    }

    fn initRing(map: []u8, off: xdp.xdp_ring_offset, size: u32, is_addr: bool) Ring {
        _ = is_addr;
        const map_ptr = @as([*]u8, @ptrCast(map.ptr));
        return .{
            .producer = @as(*volatile u32, @ptrCast(@alignCast(map_ptr + off.producer))),
            .consumer = @as(*volatile u32, @ptrCast(@alignCast(map_ptr + off.consumer))),
            .desc = @as([*]xdp.xdp_desc, @ptrCast(@alignCast(map_ptr + off.desc))),
            .addr = @as([*]u64, @ptrCast(@alignCast(map_ptr + off.desc))), // Reused for addr rings
            .size = size,
            .mask = size - 1,
        };
    }

    pub fn linkEndpoint(self: *AfXdp) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
            },
        };
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        _ = r; _ = protocol;

        // Check TX ring space
        const prod = self.tx_ring.producer.*;
        const cons = self.tx_ring.consumer.*;
        if (prod - cons >= self.tx_ring.size) return tcpip.Error.NoBufferSpace;

        // Check completion ring to reclaim frames (simplified: just assume we have enough UMEM frames if we manage them)
        // In this simple implementation, we might run out of UMEM frames if we don't recycle from completion ring.
        // Let's reclaim first.
        const comp_cons = self.comp_ring.consumer.*;
        const comp_prod = self.comp_ring.producer.*;
        _ = comp_cons;
        _ = comp_prod;
        // We don't actually need to do anything with completed frames in this simple model, just advance consumer
        // effectively "freeing" them for the allocator (if we had one).
        // Since we are just using frames linearly/randomly, we need a simple allocator.
        // Hack: Use frames [RING_SIZE..NUM_FRAMES] for TX?
        // Let's implement a simple stack of free frame indices?
        
        // For simplicity: We will just use the last 1024 frames for TX, and first 1024 for RX.
        // We assume single-threaded access.
        
        const frame_idx = (prod & (self.tx_ring.mask)) + RING_SIZE; // Offset to upper half
        const frame_offset = frame_idx * FRAME_SIZE;
        const data_ptr = self.umem_area[frame_offset..];
        
        // Copy packet data to UMEM
        const total_len = pkt.header.usedLength() + pkt.data.size;
        if (total_len > FRAME_SIZE) return tcpip.Error.MessageTooLong;
        
        const hdr_len = pkt.header.usedLength();
        @memcpy(data_ptr[0..hdr_len], pkt.header.view());
        
        const view = pkt.data.toView(self.allocator) catch return tcpip.Error.NoBufferSpace;
        defer self.allocator.free(view);
        @memcpy(data_ptr[hdr_len..][0..view.len], view);
        
        // Write descriptor
        self.tx_ring.desc[prod & self.tx_ring.mask] = .{
            .addr = frame_offset,
            .len = @as(u32, @intCast(total_len)),
            .options = 0,
        };
        
        // Kick
        self.tx_ring.producer.* = prod + 1;
        // Need to notify kernel? sendto()
        _ = std.posix.sendto(self.fd, &[_]u8{}, 0, null, 0) catch {};
    }

    pub fn poll(self: *AfXdp) !void {
        // Check RX Ring
        var cons = self.rx_ring.consumer.*;
        const prod = self.rx_ring.producer.*;
        
        while (cons != prod) {
            const desc = self.rx_ring.desc[cons & self.rx_ring.mask];
            const data = self.umem_area[desc.addr .. desc.addr + desc.len];
            
            // Dispatch
            // Create a packet buffer that copies data (for safety, as we reuse the UMEM frame immediately)
            const frame_buf = try self.allocator.alloc(u8, desc.len);
            @memcpy(frame_buf, data);
            
            var views = [1]buffer.View{frame_buf};
            const pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(frame_buf.len, &views),
                .header = buffer.Prependable.init(&[_]u8{}),
            };
            
            if (self.dispatcher) |d| {
                // Pass to Ethernet handler (dummy addresses, it parses header)
                const dummy = tcpip.LinkAddress{ .addr = [_]u8{0} ** 6 };
                d.deliverNetworkPacket(&dummy, &dummy, 0, pkt);
            }
            
            self.allocator.free(frame_buf);
            
            // Recycle frame to Fill Ring
            const fill_prod = self.fill_ring.producer.*;
            self.fill_ring.addr[fill_prod & self.fill_ring.mask] = desc.addr;
            self.fill_ring.producer.* = fill_prod + 1;
            
            cons += 1;
        }
        self.rx_ring.consumer.* = cons;
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityNone;
    }

    // Helpers
    fn setsockopt(fd: std.posix.fd_t, level: u32, optname: u32, optval: []const u8) !void {
        const rc = std.os.linux.setsockopt(fd, @as(i32, @intCast(level)), optname, optval.ptr, @as(std.posix.socklen_t, @intCast(optval.len)));
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            else => return error.SetsockoptFailed,
        }
    }
    
    fn getsockopt(fd: std.posix.fd_t, level: u32, optname: u32, optval: []u8, optlen: *u32) !void {
        const rc = std.os.linux.getsockopt(fd, @as(i32, @intCast(level)), optname, optval.ptr, optlen);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            else => return error.GetsockoptFailed,
        }
    }

    fn getIfIndex(name: []const u8) !u32 {
        const fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(fd);

        var ifr: std.os.linux.ifreq = undefined;
        @memset(std.mem.asBytes(&ifr), 0);
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.ifrn.name[0..copy_len], name[0..copy_len]);
        const header = @import("../../header.zig"); // Use header constants
        
        const rc = std.os.linux.ioctl(fd, header.SIOCGIFINDEX, @intFromPtr(&ifr));
        if (std.posix.errno(rc) != .SUCCESS) return error.IoctlFailed;
        return @as(u32, @intCast(ifr.ifru.ivalue));
    }
};
