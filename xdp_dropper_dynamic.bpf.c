#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries,1);
} config_map SEC(".maps");

char __licence[] SEC("licence") = "GPL";

SEC("xdp")
int drop_tcp_port_dynamic(struct xdp_md *ctx){
    __u32 key = 0;
    __u16 *target_port;

    target_port = bpf_map_lookup_elem(&config_map, &key);
    if (!target_port || *target_port == 0){
        return XDP_PASS;
    }
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long) ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;

    if (bpf_ntohs(tcp->dest) == *target_port) {
        return XDP_DROP;
    }

    return XDP_PASS;
}