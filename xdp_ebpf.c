#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
    __u32 packet_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
    __type(key, int);
    __type(value, int);
} events SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    struct event evt = {
        .packet_count = 1,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";