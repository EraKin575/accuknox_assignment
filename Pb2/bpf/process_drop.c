#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define ALLOWED_PORT 4040
#define bpf_ntohs(x) __builtin_bswap16(x)


// Map for the allowed process name
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[16]);  // task->comm is max 16 bytes
} allowed_comm SEC(".maps");

SEC("cgroup/connect4")
int filter_tcp_connect(struct bpf_sock_addr *ctx) {
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    __u32 key = 0;
    char *allowed = bpf_map_lookup_elem(&allowed_comm, &key);
    if (!allowed)
        return 0;  // Drop if map not populated

    if (__builtin_memcmp(comm, allowed, sizeof(comm)) != 0) {
        bpf_printk("Dropping unknown process: %s\n", comm);
        return 0;  // Drop if comm doesn't match
    }

    __u16 dport = bpf_ntohs(ctx->user_port);
    if (dport != ALLOWED_PORT) {
        bpf_printk("Dropping port %d for %s\n", dport, comm);
        return 0;
    }

    bpf_printk("✅ Allowing %s to port %d\n", comm, dport);
    return 1;  // Allow connection
}
