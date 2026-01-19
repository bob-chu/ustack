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
};

pub const LinkAddress = [6]u8;

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
};

pub const AddressWithPrefix = struct {
    address: Address,
    prefix_len: u8,
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
