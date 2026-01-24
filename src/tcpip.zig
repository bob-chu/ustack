const std = @import("std");

pub const NICID = i32;
pub const NetworkProtocolNumber = u16;
pub const TransportProtocolNumber = u16;

pub const Address = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn eq(self: Address, other: Address) bool {
        if (std.meta.activeTag(self) != std.meta.activeTag(other)) return false;
        return switch (self) {
            .v4 => |v| std.mem.eql(u8, &v, &other.v4),
            .v6 => |v| std.mem.eql(u8, &v, &other.v6),
        };
    }

    pub fn isAny(self: Address) bool {
        return switch (self) {
            .v4 => |v| std.mem.eql(u8, &v, &[_]u8{ 0, 0, 0, 0 }),
            .v6 => |v| std.mem.eql(u8, &v, &[_]u8{0} ** 16),
        };
    }

    pub fn toSolicitedNodeMulticast(self: Address) Address {
        const v6 = switch (self) {
            .v4 => unreachable,
            .v6 => |v| v,
        };
        var res = [_]u8{0} ** 16;
        res[0] = 0xff;
        res[1] = 0x02;
        res[11] = 0x01;
        res[12] = 0xff;
        res[13] = v6[13];
        res[14] = v6[14];
        res[15] = v6[15];
        return .{ .v6 = res };
    }
};

pub const LinkAddress = struct {
    addr: [6]u8,
    pub fn eq(self: LinkAddress, other: LinkAddress) bool {
        return std.mem.eql(u8, &self.addr, &other.addr);
    }
};

pub const FullAddress = struct {
    nic: NICID,
    addr: Address,
    port: u16,
};

pub const Error = error{
    UnknownProtocol,
    UnknownNICID,
    UnknownDevice,
    DuplicateNICID,
    DuplicateAddress,
    NoRoute,
    BadLinkEndpoint,
    InvalidEndpointState,
    WouldBlock,
    NetworkUnreachable,
    MessageTooLong,
    NoBufferSpace,
    NotPermitted,
    OutOfMemory,
    DestinationRequired,
};

const buffer = @import("buffer.zig");
const waiter = @import("waiter.zig");

pub const Payloader = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        fullPayload: *const fn (ptr: *anyopaque) Error![]const u8,
    };

    pub fn fullPayload(self: Payloader) Error![]const u8 {
        return self.vtable.fullPayload(self.ptr);
    }
};

pub const WriteOptions = struct {
    to: ?*const FullAddress = null,
};

pub const AcceptReturn = struct { ep: Endpoint, wq: *waiter.Queue };

pub const Endpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        close: *const fn (ptr: *anyopaque) void,
        read: *const fn (ptr: *anyopaque, addr: ?*FullAddress) Error!buffer.View,
        write: *const fn (ptr: *anyopaque, p: Payloader, opts: WriteOptions) Error!usize,
        connect: *const fn (ptr: *anyopaque, addr: FullAddress) Error!void,
        shutdown: *const fn (ptr: *anyopaque, flags: u8) Error!void,
        listen: *const fn (ptr: *anyopaque, backlog: i32) Error!void,
        accept: *const fn (ptr: *anyopaque) Error!AcceptReturn,
        bind: *const fn (ptr: *anyopaque, addr: FullAddress) Error!void,
        getLocalAddress: *const fn (ptr: *anyopaque) Error!FullAddress,
        getRemoteAddress: *const fn (ptr: *anyopaque) Error!FullAddress,
        setReceiveWindow: ?*const fn (ptr: *anyopaque, size: u32) void = null,
        setOption: *const fn (ptr: *anyopaque, opt: EndpointOption) Error!void,
        getOption: *const fn (ptr: *anyopaque, opt: EndpointOptionType) EndpointOption,
    };

    pub fn close(self: Endpoint) void {
        self.vtable.close(self.ptr);
    }
    pub fn read(self: Endpoint, addr: ?*FullAddress) Error!buffer.View {
        return self.vtable.read(self.ptr, addr);
    }
    pub fn write(self: Endpoint, p: Payloader, opts: WriteOptions) Error!usize {
        return self.vtable.write(self.ptr, p, opts);
    }
    pub fn connect(self: Endpoint, addr: FullAddress) Error!void {
        return self.vtable.connect(self.ptr, addr);
    }
    pub fn bind(self: Endpoint, addr: FullAddress) Error!void {
        return self.vtable.bind(self.ptr, addr);
    }
    pub fn listen(self: Endpoint, backlog: i32) Error!void {
        return self.vtable.listen(self.ptr, backlog);
    }
    pub fn accept(self: Endpoint) Error!AcceptReturn {
        return self.vtable.accept(self.ptr);
    }
    pub fn getLocalAddress(self: Endpoint) Error!FullAddress {
        return self.vtable.getLocalAddress(self.ptr);
    }
    pub fn getRemoteAddress(self: Endpoint) Error!FullAddress {
        return self.vtable.getRemoteAddress(self.ptr);
    }
    pub fn shutdown(self: Endpoint, flags: u8) Error!void {
        return self.vtable.shutdown(self.ptr, flags);
    }
    pub fn setOption(self: Endpoint, opt: EndpointOption) Error!void {
        return self.vtable.setOption(self.ptr, opt);
    }
    pub fn getOption(self: Endpoint, opt_type: EndpointOptionType) EndpointOption {
        return self.vtable.getOption(self.ptr, opt_type);
    }
};

pub const EndpointOptionType = enum {
    ts_enabled,
};

pub const EndpointOption = union(EndpointOptionType) {
    ts_enabled: bool,
};

pub const AddressWithPrefix = struct {
    address: Address,
    prefix_len: u8,

    // Convenience method to get subnet
    pub fn toSubnet(self: AddressWithPrefix) Subnet {
        return .{
            .address = self.address,
            .prefix = self.prefix_len,
        };
    }
};

// Subnet with mask for routing (CIDR notation)
pub const Subnet = struct {
    address: Address,
    prefix: u8,

    // Check if address belongs to this subnet (longest-prefix matching)
    pub fn contains(self: Subnet, addr: Address) bool {
        // Addresses must be same length
        if (std.meta.activeTag(self.address) != std.meta.activeTag(addr)) {
            return false;
        }

        // Compare prefix bits
        const prefix_bits = self.prefix;
        const bytes_to_check = prefix_bits / 8;
        const remaining_bits = prefix_bits % 8;
        var i: usize = 0;

        const self_buf = switch (self.address) {
            .v4 => |v| v[0..],
            .v6 => |v| v[0..],
        };
        const addr_buf = switch (addr) {
            .v4 => |v| v[0..],
            .v6 => |v| v[0..],
        };

        // Check full bytes
        while (i < bytes_to_check) : (i += 1) {
            if (self_buf[i] != addr_buf[i]) {
                return false;
            }
        }

        // Check partial byte
        if (remaining_bits > 0) {
            const mask = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
            if ((self_buf[i] & mask) != (addr_buf[i] & mask)) {
                return false;
            }
        }

        return true;
    }

    // Prefix comparison operator for sorting routes (longest first)
    pub fn gt(self: Subnet, other: u8) bool {
        return self.prefix > other;
    }

    // Convenience method to get prefix value
    pub fn prefix(self: Subnet) u8 {
        return self.prefix;
    }
};

pub const ProtocolAddress = struct {
    protocol: NetworkProtocolNumber,
    address_with_prefix: AddressWithPrefix,
};

pub const PacketBuffer = struct {
    data: buffer.VectorisedView,
    header: buffer.Prependable,
    
    link_header: ?buffer.View = null,
    network_header: ?buffer.View = null,
    transport_header: ?buffer.View = null,

    pub fn clone(self: PacketBuffer, allocator: std.mem.Allocator) !PacketBuffer {
        var new_pb = self;
        // Simplified clone for now, just copy views slice
        const new_views = allocator.alloc(buffer.View, self.data.views.len) catch return Error.OutOfMemory;
        @memcpy(new_views, self.data.views);
        new_pb.data.views = new_views;
        return new_pb;
    }
};
