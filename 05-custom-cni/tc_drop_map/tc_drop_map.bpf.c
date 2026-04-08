#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct conn_key {
    __be32  src_addr;
    __u8    proto;
    __u8    pad[3];
};

struct value {
    __u32   hit_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct conn_key);
    __type(value, struct value);
} conn_map SEC(".maps");

SEC("tc")
int tc_drop_map(struct __sk_buff *skb){

    void *data      = (void *)(long)(skb->data);
    void *data_end  = (void *)(long)(skb->data_end);

    struct ethhdr *eth = data;
    if ((void *)(eth+1) > data_end){
        return TC_ACT_OK;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return TC_ACT_OK;
    }

    struct iphdr *iph = (void *)(eth+1);

    if ((void *)(iph+1) > data_end){
        return TC_ACT_OK;
    }

    /* 
        This is needed cause the args to bpf_map_lookup_elem 
        has to be a PTR_TO_STACK or PTR_TO_MAP_VALUE
    */
    struct conn_key key = {};
    key.src_addr    = iph->saddr;
    key.proto       = iph->protocol;

    struct value *val = bpf_map_lookup_elem(&conn_map, &key);

    if (val != NULL){
        __sync_fetch_and_add(&val->hit_count, 1);
        bpf_printk("Traffic from ip 0x%08x dropped %d times", 
                        bpf_ntohl(key.src_addr), val->hit_count);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;

}

char LICENSE[] SEC("license") = "GPL";