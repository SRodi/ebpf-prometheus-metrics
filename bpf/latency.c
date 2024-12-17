#include "vmlinux.h"
// #include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800

struct latency_t {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct latency_t);
} latency_map SEC(".maps");

static __inline __u16 bpf_htons(__u16 x) {
    return __builtin_bswap16(x);
}

// create function to return the ip header
static __always_inline struct iphdr *ip_hdr(struct __sk_buff *skb) {
    // Get data and data_end
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    // Get ethernet header
    struct ethhdr eth;
    // Check if data is valid
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;
    // Read ethernet header
    bpf_probe_read_kernel(&eth, sizeof(eth), data);
    // Check if it is IP packet
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return 0;
    // Get IP header
    struct iphdr ip;
    // Check if IP header is valid
    if ((void *)data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return 0;
    // Read IP header
    bpf_probe_read_kernel(&ip, sizeof(ip), data + sizeof(struct ethhdr));

    return &ip;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_ip(struct __sk_buff *skb) {
    // Get IP header
    struct iphdr ip = *ip_hdr(skb);

    // Set key as IP id    
    __u32 key = ip.id;
    // Initialize latency struct
    struct latency_t latency = {};
    // Fill latency struct
    latency.timestamp = bpf_ktime_get_ns();
    latency.src_ip = ip.saddr;
    latency.dst_ip = ip.daddr;
    // Update latency map
    bpf_map_update_elem(&latency_map, &key, &latency, BPF_ANY);
    return 0;
}

SEC("tp/net/net_dev_queue")
int trace_ip_return(struct __sk_buff *skb) {
    // Get IP header
    struct iphdr ip = *ip_hdr(skb);

    // Set key as IP id
    __u32 key = ip.id;
    // Declare latency struct
    struct latency_t *latency;
    // Get latency struct from map
    latency = bpf_map_lookup_elem(&latency_map, &key);
    if (latency) {
        // Evaluate latency
        __u64 delta = bpf_ktime_get_ns() - latency->timestamp;
        // Print latency
        bpf_printk("src_ip: %x, dst_ip: %x, latency: %llu ns\n", latency->src_ip, latency->dst_ip, delta);
        // Delete latency from map
        bpf_map_delete_elem(&latency_map, &key);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";