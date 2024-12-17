#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define ETH_P_IP 0x800

struct ipv4_key {
    __be32 src_ip;
    __be32 dst_ip;
    __sum16 check;
    __u8 h_proto;
};

struct latency_t {
    __u64 timestamp_in;
    __u64 latency;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ipv4_key);
    __type(value, struct latency_t);
} latency_map SEC(".maps");

static inline struct iphdr *get_iphdr(struct pt_regs *ctx) {
    void* head;
    u16 offset;
    struct iphdr *iphr;
    struct sk_buff *skb;
    
    // Get socket buffer
    bpf_probe_read_kernel(&skb, sizeof(skb), &PT_REGS_PARM1(ctx));
    
    // Get head and offset
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&offset, sizeof(offset), &skb->network_header);

    // Get IP header
    iphr = (struct iphdr *)(head + offset);
    if (!iphr) {
        bpf_printk("Failed to get IP header\n");
        return 0;
    }
    return iphr;
}

static inline struct ipv4_key build_key( struct iphdr *iphr) {
    // Get source and destination ip addresses
    __be32 src, dst;
    __sum16 check;
    __u8 proto;

    bpf_probe_read_kernel(&src, sizeof(src), &iphr->saddr);
    bpf_probe_read_kernel(&dst, sizeof(dst), &iphr->daddr);
    bpf_probe_read_kernel(&proto, sizeof(proto), &iphr->protocol);
    bpf_probe_read_kernel(&proto, sizeof(proto), &iphr);

    bpf_printk("IP src: %x, dst: %x, proto: %x\n", src, dst, proto);

    // Initialize IPv4 key
    struct ipv4_key key = {};
    key.src_ip = src;
    key.dst_ip = dst;
    key.check = check;
    key.h_proto = proto;

    return key;
}

static inline struct ipv4_key reverse_ipv4_key(struct ipv4_key key) {
    struct ipv4_key reversed_key;
    reversed_key.src_ip = key.dst_ip;
    reversed_key.dst_ip = key.src_ip;
    reversed_key.check = key.check;
    reversed_key.h_proto = key.h_proto; // Assuming protocol remains the same
    return reversed_key;
}

SEC("kprobe/ip_rcv")
int trace_ip_rcv(struct pt_regs *ctx) {
    // Get ip header
    struct iphdr *iphr = get_iphdr(ctx);

    // Get key
    struct ipv4_key key = build_key(iphr);

    // Initialize latency structure and set timestamp
    struct latency_t latency = {};
    latency.timestamp_in = bpf_ktime_get_ns();

    // Update latency map with the new data
    bpf_map_update_elem(&latency_map, &key, &latency, BPF_ANY);

    return 0;
}

SEC("kprobe/ip_output")
int trace_ip_output(struct pt_regs *ctx) {
    // Get ip header
    struct iphdr *iphr = get_iphdr(ctx);

    // Get key
    struct ipv4_key key = build_key(iphr);

    // Reverse key
    struct ipv4_key reversed_key = reverse_ipv4_key(key);

    struct latency_t *latency = bpf_map_lookup_elem(&latency_map, &reversed_key);
    if (latency) {
        // Evaluate latency
        __u64 delta = bpf_ktime_get_ns() - latency->timestamp_in;
        // Update latency struct
        latency->latency = delta;
        // Update latency_map
        bpf_map_update_elem(&latency_map, &reversed_key, latency, BPF_ANY);
        // Print latency
        bpf_printk("src_ip: %x, dst_ip: %x, latency: %llu ns\n", reversed_key.src_ip, reversed_key.dst_ip, latency->latency);
        // // Delete latency from map
        // bpf_map_delete_elem(&latency_map, &key);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";