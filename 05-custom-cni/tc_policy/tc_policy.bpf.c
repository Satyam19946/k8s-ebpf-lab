#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "tc_monitor.h"

struct policy_key {
    __be32  src_ip;
    __be32  dst_ip;
    __be16  dst_port;
    __u8    proto;
    __u8    pad;
};

struct policy_val {
    __u8    action;
    __u8    pad[3];
};

struct ct_key {
    __be32  src_ip;
    __be32  dst_ip;
    __be16  src_port;
    __be16  dst_port;
    __u8    proto;
    __u8    pad[3];
};

struct ct_val {
    __u8    state;   /* 0 = new, 1 = established */
    __u8    pad[3];
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         struct policy_key);
    __type(value,       struct policy_val);
} policy_map SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,         struct ct_key);
    __type(value,       struct ct_val);
} ct_map SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} monitor_rb SEC(".maps");

SEC("tc")
int tc_policy(struct __sk_buff *skb)
{
    bpf_printk("BPF Program tc_policy triggered\n");
    void *data      = (void *)(long)(skb->data);
    void *data_end  = (void *)(long)(skb->data_end);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
        bpf_printk("bail: eth bounds\n");
        return TC_ACT_OK;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        bpf_printk("bail: not IPv4, proto=%x\n", eth->h_proto);
        return TC_ACT_OK;
    }

    struct iphdr *iph = (void *)(eth+1);
    if ((void *)(iph+1) > data_end){
        bpf_printk("bail: iph bounds\n");
        return TC_ACT_OK;
    }

    if (iph->protocol != IPPROTO_TCP){
        bpf_printk("bail: not TCP, proto=%d\n", iph->protocol);
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)iph+(iph->ihl * 4);
    if ((void *)(tcp + 1) > data_end){
        bpf_printk("bail: tcp bounds\n");
        return TC_ACT_OK;
    }

    struct ct_key ctkey = {};

    ctkey.src_ip    = iph->saddr;
    ctkey.dst_ip    = iph->daddr;
    ctkey.src_port  = tcp->source;
    ctkey.dst_port  = tcp->dest;
    ctkey.proto     = iph->protocol;

    struct ct_val *ctval = bpf_map_lookup_elem(&ct_map, &ctkey);
    
    struct monitor_event *e = bpf_ringbuf_reserve(&monitor_rb, sizeof(*e), 0);
    if (e){
        e->src_ip       = iph->saddr;
        e->dst_ip       = iph->daddr;
        e->proto        = iph->protocol;
        e->src_port     = tcp->source;
        e->dst_port     = tcp->dest;
    }

    if (ctval && ctval->state){
        bpf_printk("Found connection in ct_map From:0x%08x:%d\n", 
                    bpf_ntohl(ctkey.src_ip), bpf_ntohs(ctkey.src_port));
        if (e){
            e->action = ACTION_CT_HIT;
            bpf_ringbuf_submit(e, 0);
        }
        return TC_ACT_OK;
    }

    struct policy_key key = {};
    key.src_ip      = iph->saddr;
    key.dst_ip      = iph->daddr;
    key.proto       = iph->protocol;
    key.dst_port    = tcp->dest;

    struct policy_val *value = bpf_map_lookup_elem(&policy_map, &key);
    
    if (value && value->action == 1){
        bpf_printk("Allowing connection from 0x%08x to 0x%08x:%d\n",
                        bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr), bpf_ntohs(tcp->dest));
        
        struct ct_key reply_key = {};
        reply_key.src_ip   = iph->daddr;
        reply_key.dst_ip   = iph->saddr;
        reply_key.src_port = tcp->dest;
        reply_key.dst_port = tcp->source;
        reply_key.proto    = iph->protocol;

        struct ct_val ctv = {};
        ctv.state = 1;
        bpf_map_update_elem(&ct_map, &ctkey, &ctv, BPF_ANY);
        bpf_map_update_elem(&ct_map, &reply_key, &ctv, BPF_ANY);
        if(e){
            e->action = ACTION_ALLOWED;
            bpf_ringbuf_submit(e, 0);
        }
        return TC_ACT_OK;
    }
    bpf_printk("Blocking connection from 0x%08x to 0x%08x:%d\n",
                    bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr), bpf_ntohs(tcp->dest));
    
    if (e) {
        e->action = ACTION_DROPPED;
        bpf_ringbuf_submit(e, 0);
    }
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";