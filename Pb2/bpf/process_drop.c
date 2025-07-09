#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define bpf_ntohs(x) __builtin_bswap16(x) 


// Map to hold the allowed process name (task->comm)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[16]);  // task->comm is max 16 bytes
} allowed_comm SEC(".maps");

SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_printk("COMM: %s\n", comm);

    __u32 key = 0;
    char *allowed = bpf_map_lookup_elem(&allowed_comm, &key);
    if (!allowed || __builtin_memcmp(comm, allowed, sizeof(comm)) != 0) {
        bpf_printk("❌ Dropped process (comm mismatch): %s\n", comm);
        return TC_ACT_SHOT;
    }

    // Proceed to check TCP port
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    int ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    __u16 port = bpf_ntohs(tcph->dest);
    if (port != 4040) {
        bpf_printk("❌ Dropped port: %d from %s\n", port, comm);
        return TC_ACT_SHOT;
    }

    bpf_printk("✅ Allowed: %s to port %d\n", comm, port);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
