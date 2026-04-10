#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

// inline checksum update helper
static inline void update_csum(__u16 *csum, __be32 old, __be32 new)
{
    __u32 c = ~(*csum);
    c += (~old & 0xffff) + (old >> 16);
    c += (new & 0xffff) + (new >> 16);
    c = (c >> 16) + (c & 0xffff);
    c += (c >> 16);
    *csum = ~c;
}

static inline void update_csum_16(__u16 *csum, __be16 old, __be16 new)
{
    __u32 c = ~(*csum);
    c += (~old & 0xffff);
    c += (new & 0xffff);
    c = (c >> 16) + (c & 0xffff);
    c += (c >> 16);
    *csum = ~c;
}

struct service_key {
    __u32   vip;
    __be16  port;
    __u8    proto;
    __u8    pad;
};

struct backend {
    __be32  ip;
    __be16  port;
    __u8    pad[2];
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         struct service_key);
    __type(value,       struct backend);
} service_map SEC(".maps");

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data      = (void *)(long)(ctx->data);
    void *data_end  = (void *)(long)(ctx->data_end);

    struct ethhdr *eth = data;
    if ((void *)(eth+1) > data_end){
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth+1);
    if ((void *)(iph+1) > data_end){
        return XDP_PASS;
    }

    __u8 ihl    = iph->ihl;

    struct tcphdr *tcp = (void *)iph+(ihl*4);
    if ((void *)(tcp+1) > data_end){
        return XDP_PASS;
    }
    
    struct service_key key = {};
    key.vip     = iph->daddr;
    key.proto   = iph->protocol;

    key.port    = tcp->dest;

    __be32 old_ip   = iph->daddr;
    __be16 old_port = tcp->dest;

    bpf_printk("Old IP:Port is 0x%08x:%d\n", bpf_ntohl(iph->daddr), tcp->dest);
    struct backend *value = bpf_map_lookup_elem(&service_map, &key);
    if ( value != NULL ){
        tcp->dest   = value->port;
        iph->daddr  = value->ip;

        update_csum(&iph->check, old_ip, value->ip);
        update_csum_16(&tcp->check, old_port, value->port);
        update_csum(&tcp->check, old_ip, value->ip);

        bpf_printk("New IP:Port is 0x%08x:%d\n", bpf_ntohl(value->ip), tcp->dest);
    }

    return XDP_PASS;
}



char LICENSE[] SEC("license") = "GPL";