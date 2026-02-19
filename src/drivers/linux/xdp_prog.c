#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} xsk_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int index = ctx->rx_queue_index;
    const char fmt[] = "XDP: queue=%d\n";
    bpf_trace_printk(fmt, sizeof(fmt), index);
    return bpf_redirect_map(&xsk_map, index, XDP_PASS);
}


char _license[] SEC("license") = "GPL";
