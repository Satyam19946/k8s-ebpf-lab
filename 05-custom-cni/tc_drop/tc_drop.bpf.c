#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define BLOCKED_IP bpf_htonl(0x0a000002) //192.168.1.100

SEC("tc")
int tc_drop(struct __sk_buff *skb)
{
    void *data      = (void *)(long)(skb->data);
    void *data_end  = (void *)(long)(skb->data_end);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
        return TC_ACT_OK;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end){
        return TC_ACT_OK;
    }

    if (ip->saddr == BLOCKED_IP){
        bpf_printk("tc_drop: dropping packet from 0x%08x", bpf_ntohl(ip->saddr));
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";