#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int load_xdp_and_get_xsk_map(const char *ifname, const char *filename) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) return -1;

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) return -2;

    if (bpf_object__load(obj)) return -3;

    prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    if (!prog) return -4;

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) return -5;

    // Attach to interface (Generic XDP for maximum compatibility in Docker/WSL2)
    bpf_xdp_detach(ifindex, 0, NULL);
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        return -6;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "xsk_map");
    if (map_fd < 0) return -7;

    return map_fd;
}
