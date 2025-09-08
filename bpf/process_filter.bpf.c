// File: bpf/process_filter.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define TARGET_PORT 4040
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, char[TASK_COMM_LEN]);
} pid_map SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_map_update_elem(&pid_map, &pid, &comm, BPF_ANY);
    return 0;
}

static __always_inline u16 parse_ipv4_tcp_dest_port(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return 0;

    if (iph->version != 4)
        return 0;

    u32 ihl_bytes = iph->ihl * 4;
    void *tcp_off = data + ihl_bytes;
    if (tcp_off + sizeof(struct tcphdr) > data_end)
        return 0;

    struct tcphdr *tcph = tcp_off;
    if (iph->protocol != IPPROTO_TCP)
        return 0;

    return bpf_ntohs(tcph->dest);
}

SEC("cgroup_skb/egress")
int filter_egress(struct __sk_buff *skb)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char *comm = bpf_map_lookup_elem(&pid_map, &pid);
    if (!comm)
        return 1;

    char target_comm[TASK_COMM_LEN] = "myprocess";
    int i;
    for (i = 0; i < TASK_COMM_LEN; i++) {
        if (comm[i] != target_comm[i])
            return 1;
        if (comm[i] == '\0')
            break;
    }

    u16 dest_port = parse_ipv4_tcp_dest_port(skb);
    if (dest_port == 0)
        return 1;

    if (dest_port != TARGET_PORT) {
        bpf_printk("Dropping packet from PID %d to port %d\n", pid, dest_port);
        return 0;
    }

    bpf_printk("Allowing packet from PID %d to port %d\n", pid, dest_port);
    return 1;
}
