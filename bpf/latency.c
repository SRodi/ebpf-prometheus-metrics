#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define ETH_P_IP 0x800

struct ipv4_key {
    __be32 src_ip;
    __be32 dst_ip;
    // Use skb->hash as identifier
    __u32 id;
    __u8 h_proto;
};

struct l3 {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 h_proto;
};

struct latency_t {
    __u64 timestamp_in;
    __u64 timestamp_out;
    __u64 delta;
    struct l3 layer_3;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ipv4_key *);
    __type(value, struct latency_t);
} latency_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096); // Size of the ring buffer
} events SEC(".maps");

static inline struct ipv4_key build_key( struct iphdr *iphr, struct sk_buff *skb) {
    // Get source and destination ip addresses
    __be32 src, dst;
    __u32 id;
    __u8 proto;

    bpf_probe_read_kernel(&src, sizeof(src), &iphr->saddr);
    bpf_probe_read_kernel(&dst, sizeof(dst), &iphr->daddr);
    bpf_probe_read_kernel(&id, sizeof(id), &skb->hash);
    bpf_probe_read_kernel(&proto, sizeof(proto), &iphr->protocol);

    // Initialize IPv4 key
    struct ipv4_key key = {
        .src_ip = src,
        .dst_ip = dst,
        .id = id,
        .h_proto = proto
    };

    return key;
}

static inline struct l3 build_l3( struct iphdr *iphr, struct sk_buff *skb) {
    // Get source and destination ip addresses
    __be32 src, dst;
    __u32 id;
    __u8 proto;

    bpf_probe_read_kernel(&src, sizeof(src), &iphr->saddr);
    bpf_probe_read_kernel(&dst, sizeof(dst), &iphr->daddr);
    bpf_probe_read_kernel(&proto, sizeof(proto), &iphr->protocol);

    // Initialize IPv4 key
    struct l3 layer_3 = {
        .src_ip = src,
        .dst_ip = dst,
        .h_proto = proto
    };

    return layer_3;
}

static inline __u32 get_key(struct sk_buff *skb) {
    __u32 id;
    bpf_probe_read_kernel(&id, sizeof(id), &skb->hash);
    return id;
}


// get the ip header from the skb
static inline struct iphdr *get_iphdr(struct sk_buff *skb) {
    void* head;
    u16 offset;
    u32 hash;
    struct iphdr *iphr;

    // Get the network header
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&offset, sizeof(offset), &skb->network_header);

    // Get the ip header
    iphr = (struct iphdr *)(head + offset);
    if (!iphr) {
        bpf_printk("Failed to get IP header\n");
        return 0;
    }
    return iphr;
}

SEC("kprobe/ip_rcv")
int ip_rcv(struct pt_regs *ctx) {
    // Get the socket buffer
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    // Get the ip header
    struct iphdr *iphr = get_iphdr(skb);
    // Build the key
    struct ipv4_key key = build_key(iphr, skb);
    // Build layer 3 struct
    struct l3 layer_3 = build_l3(iphr, skb);

    // Initialize latency structure and set timestamp
    struct latency_t latency = {
        .timestamp_in = bpf_ktime_get_ns(),
        .layer_3 = layer_3
    };

    // Update latency map with the new data
    bpf_map_update_elem(&latency_map, &key, &latency, BPF_ANY);

    return 0;
}

SEC("kprobe/ip_rcv_finish")
int ip_rcv_finish(struct pt_regs *ctx) {
    // Get the socket buffer
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    // Get the ip header
    struct iphdr *iphr = get_iphdr(skb);
    // Build the key
    struct ipv4_key key = build_key(iphr, skb);

    struct latency_t *latency = bpf_map_lookup_elem(&latency_map, &key);
    if (latency) {
        // Update latency struct
        latency->timestamp_out = bpf_ktime_get_ns();
        latency->delta = ( latency->timestamp_out - latency->timestamp_in ) / 1000;
        // Print latency
        bpf_printk("latency: %llu ms\n", latency->delta);
        // Send event to user space via ring buffer
        void *data = bpf_ringbuf_reserve(&events, sizeof(*latency), 0);
        if (data) {
            __builtin_memcpy(data, latency, sizeof(*latency));
            bpf_ringbuf_submit(data, 0);
        }
        // Delete latency from map
        bpf_map_delete_elem(&latency_map, &key);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";