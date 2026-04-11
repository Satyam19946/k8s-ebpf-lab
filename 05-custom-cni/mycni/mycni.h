#ifndef MYCNI_H
#define MYCNI_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ── network config ── */
#define POD_CIDR        "10.244.0.0/16"
#define NODE_SUBNET     "10.244.1"
#define GATEWAY_IP      "10.244.1.1"
#define ALLOC_FILE      "/var/lib/mycni/allocations"
#define VETH_PREFIX     "veth"
#define MAX_PODS        254

/* ── BPF pin paths — written by tc_policy_loader, read by mycni ── */
#define PIN_POLICY      "/sys/fs/bpf/policy_map"
#define PIN_CT          "/sys/fs/bpf/ct_map"
#define PIN_RB          "/sys/fs/bpf/monitor_rb"
#define PIN_PROG        "/sys/fs/bpf/tc_policy_prog"

/* ── policy map structs — must match tc_policy.bpf.c ── */
struct policy_key {
    __u32  src_ip;
    __u32  dst_ip;
    __u16  dst_port;
    __u8   proto;
    __u8   pad;
};

struct policy_val {
    __u8  action;   /* 1 = allow */
    __u8  pad[3];
};

/* ── CNI config populated from env vars ── */
struct cni_config {
    char cni_command[16];
    char cni_netns[256];
    char cni_ifname[16];
    char cni_containerid[128];
};

#endif