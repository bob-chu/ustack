const std = @import("std");

pub const SOL_XDP = 283;

pub const XDP_MMAP_OFFSETS = 1;
pub const XDP_RX_RING = 2;
pub const XDP_TX_RING = 3;
pub const XDP_UMEM_REG = 4;
pub const XDP_UMEM_FILL_RING = 5;
pub const XDP_UMEM_COMPLETION_RING = 6;
pub const XDP_STATISTICS = 7;
pub const XDP_OPTIONS = 8;

pub const XDP_SHARED_UMEM = 1;
pub const XDP_COPY = 2;
pub const XDP_ZEROCOPY = 4;
pub const XDP_USE_NEED_WAKEUP = 8;

pub const XDP_PGOFF_RX_RING: i64 = 0;
pub const XDP_PGOFF_TX_RING: i64 = 0x80000000;
pub const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x100000000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x180000000;

pub const xdp_umem_reg = extern struct {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
};

pub const xdp_ring_offset = extern struct {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
};

pub const xdp_mmap_offsets = extern struct {
    rx: xdp_ring_offset,
    tx: xdp_ring_offset,
    fr: xdp_ring_offset,
    cr: xdp_ring_offset,
};

pub const xdp_desc = extern struct {
    addr: u64,
    len: u32,
    options: u32,
};

pub const sockaddr_xdp = extern struct {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
};
