const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");

pub const EthernetEndpoint = struct {
    lower: stack.LinkEndpoint,
    addr: tcpip.LinkAddress,
    dispatcher: ?*stack.NetworkDispatcher = null,
    wrapped_dispatcher: stack.NetworkDispatcher = undefined,

    pub fn init(lower: stack.LinkEndpoint, addr: tcpip.LinkAddress) EthernetEndpoint {
        return .{
            .lower = lower,
            .addr = addr,
        };
    }

    pub fn linkEndpoint(self: *EthernetEndpoint) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.LinkEndpoint.VTable{
        .writePacket = writePacket,
        .attach = attach,
        .linkAddress = linkAddress,
        .mtu = mtu,
        .setMTU = setMTU,
        .capabilities = capabilities,
    };

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;
        
        const eth_header = mut_pkt.header.prepend(header.EthernetMinimumSize) orelse return tcpip.Error.NoBufferSpace;
        var eth = header.Ethernet.init(eth_header);
        
        const dst = if (r) |route| route.remote_link_address orelse [_]u8{0xff} ** 6 else [_]u8{0xff} ** 6;
        const src = if (r) |route| route.local_link_address else self.addr;
        
        eth.encode(src, dst, protocol);
        
        return self.lower.writePacket(r, protocol, mut_pkt);
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
        self.wrapped_dispatcher = .{
            .ptr = self,
            .vtable = &.{
                .deliverNetworkPacket = deliverNetworkPacket,
            },
        };
        self.lower.attach(&self.wrapped_dispatcher);
    }

    fn deliverNetworkPacket(ptr: *anyopaque, remote: tcpip.LinkAddress, local: tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        _ = remote; _ = local; _ = protocol;
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        if (v.len < header.EthernetMinimumSize) return;
        
        const eth = header.Ethernet.init(v);
        const p = eth.etherType();
        mut_pkt.link_header = v[0..header.EthernetMinimumSize];
        mut_pkt.data.trimFront(header.EthernetMinimumSize);
        
        if (self.dispatcher) |d| {
            d.deliverNetworkPacket(eth.sourceAddress(), eth.destinationAddress(), p, mut_pkt);
        }
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        return self.addr;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        return self.lower.mtu() - header.EthernetMinimumSize;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        self.lower.setMTU(m + header.EthernetMinimumSize);
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        return self.lower.capabilities();
    }
};
