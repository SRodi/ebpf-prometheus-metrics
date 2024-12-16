#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

// Define a hash map to store start timestamps and IP addresses
struct packet_info {
    u64 timestamp;
    __be32 src_ip;
    __be32 dst_ip;
};
BPF_HASH(start_time_map, u32, struct packet_info);

// Define a histogram map for latency
BPF_HISTOGRAM(latency_histogram, __be32, __be32);

SEC("kprobe/ip_rcv")
int trace_ip_rcv(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u32 packet_id = skb->hash; // Use packet hash as a unique identifier
    struct iphdr *iph = bpf_hdr_pointer(skb, sizeof(struct iphdr));
    if (!iph) return 0;

    struct packet_info info = {
        .timestamp = bpf_ktime_get_ns(),
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
    };
    start_time_map.update(&packet_id, &info);
    return 0;
}

SEC("kprobe/dev_queue_xmit")
int trace_dev_queue_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u32 packet_id = skb->hash;
    struct packet_info *info = start_time_map.lookup(&packet_id);
    if (info) {
        u64 delta_ns = bpf_ktime_get_ns() - info->timestamp;
        // Update histogram with latency and IPs
        latency_histogram.increment(delta_ns / 1000, info->src_ip, info->dst_ip); // µs
        start_time_map.delete(&packet_id);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
