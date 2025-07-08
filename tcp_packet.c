#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_PORT 8080  // ✅ no '='

SEC("xdp")
int tcp_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Filter only IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Only TCP packets
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Calculate IP header length
    int ip_hdr_len = iph->ihl * 4;

    // TCP header
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Drop if destination port is DEFAULT_PORT
    if (tcph->dest == __constant_htons(DEFAULT_PORT))
        return XDP_DROP;

    return XDP_PASS;
}

// License is required for eBPF programs
char _license[] SEC("license") = "GPL";
