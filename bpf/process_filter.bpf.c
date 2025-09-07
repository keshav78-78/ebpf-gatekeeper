#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define TARGET_PORT 4040
#define TASK_COMM_LEN 16

char LICENSE[] SEC("licence") = "GPL";

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, char[TASK_COMM_LEN]);
} pid_map SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_map_update_elem(&pid_map, &pid, &comm, BPF_ANY);
    return 0;
}

SEC("cgroup_skb/egress")
int filter_egress(struct __sk_buff *skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char *comm = bpf_map_lookup_elem(&pid_map, &pid);
    if (!comm) {
        return 1;
    }

    char target_comm[TASK_COMM_LEN] = "myprocess";
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (comm[i] != target_comm[i]) {
            return 1;
        }
        if (comm[i] == '\0') {
            break;
        }
    }

    struct bpf_sock *sk = skb->sk;
    if (!sk) {
        return 1;
    }

    if (sk->type != SOCK_STREAM) {
        return 1;
    }

    u16 dest_port = bpf_ntohs(sk->dst_port);

    if (dest_port != TARGET_PORT) {
        bpf_printk("Dropping packet from PID %d to port %d\n", pid, dest_port);
        return 0;
    }

    bpf_printk("Allowing packet from PID %d to port %d\n", pid, dest_port);
    return 1;
}
