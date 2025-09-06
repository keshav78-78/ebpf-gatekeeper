#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TARGET_PORT 4040
#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int drop_tcp_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Only process IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Only process TCP
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    // Drop if dest port matches
    if (bpf_ntohs(tcp->dest) == TARGET_PORT) {
        bpf_printk("XDP: Dropping TCP packet to port %d\n", TARGET_PORT);
        return XDP_DROP;
    }

    return XDP_PASS;
}
