#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "tc_monitor.h"

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

struct policy_key {
    __u32  src_ip;
    __u32  dst_ip;
    __u16  dst_port;
    __u8   proto;
    __u8   pad;
};

struct policy_val {
    __u8  action;
    __u8  pad[3];
};

static int handle_event(void *ctx, void *data, size_t size)
{
    if (size < sizeof(struct monitor_event))
        return 0;

    struct monitor_event *e = data;

    /* convert IPs to dotted decimal */
    struct in_addr src = { .s_addr = e->src_ip };
    struct in_addr dst = { .s_addr = e->dst_ip };

    const char *action_str;
    switch (e->action) {
        case ACTION_CT_HIT:  action_str = "CT_HIT  "; break;
        case ACTION_ALLOWED: action_str = "ALLOWED "; break;
        case ACTION_DROPPED: action_str = "DROPPED "; break;
        default:             action_str = "UNKNOWN "; break;
    }

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->src_ip, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &e->dst_ip, dst_str, sizeof(dst_str));

    printf("[%s] %s:%d -> %s:%d proto=%d\n",
        action_str,
        src_str, ntohs(e->src_port),
        dst_str, ntohs(e->dst_port),
        e->proto);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    /* --- load BPF object --- */
    struct bpf_object *obj = bpf_object__open("tc_policy/tc_policy.bpf.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load failed\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_policy");
    if (!prog) {
        fprintf(stderr, "program 'tc_policy' not found\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);

    /* --- attach clsact qdisc --- */
    LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex      = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );

    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "bpf_tc_hook_create failed: %d\n", err);
        return 1;
    }

    /* --- attach BPF program as filter --- */
    LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = prog_fd,
    );

    if (bpf_tc_attach(&hook, &opts)) {
        fprintf(stderr, "bpf_tc_attach failed\n");
        return 1;
    }

    // Create and attach the egress hook 
    LIBBPF_OPTS(bpf_tc_hook, hook_egress,
        .ifindex      = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );

    err = bpf_tc_hook_create(&hook_egress);
    if (err && err != -EEXIST) {
        fprintf(stderr, "bpf_tc_hook_create egress failed: %d\n", err);
        return 1;
    }

    LIBBPF_OPTS(bpf_tc_opts, opts_egress,
        .prog_fd = prog_fd,
    );

    if (bpf_tc_attach(&hook_egress, &opts_egress)) {
        fprintf(stderr, "bpf_tc_attach egress failed\n");
        return 1;
    }

    /* --- get policy map fd and populate --- */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "policy_map");
    if (!map) {
        fprintf(stderr, "map 'policy_map' not found\n");
        return 1;
    }

    int map_fd = bpf_map__fd(map);

    struct policy_key key = {};
    key.src_ip   = htonl(0x0af40102);   /* 10.244.1.2 */
    key.dst_ip   = htonl(0x0af40101);   /* 10.244.1.1 */
    key.dst_port = htons(8080);
    key.proto    = 6;

    struct policy_val val = { .action = 1 };
    if (bpf_map_update_elem(map_fd, &key, &val, BPF_NOEXIST)) {
        fprintf(stderr, "bpf_map_update_elem failed: %s\n", strerror(errno));
        return 1;
    }

    /* --- set up ringbuf --- */
    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "monitor_rb");
    if (!rb_map) {
        fprintf(stderr, "map 'monitor_rb' not found\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        return 1;
    }

    printf("tc_policy attached to %s ingress\n", iface);
    printf("default deny — allowing: 10.244.1.2 -> 10.244.1.1:8080 TCP\n");
    printf("monitoring events...\n\n");
    printf("%-10s %-22s %-22s %s\n", "action", "src", "dst", "proto");
    printf("%-10s %-22s %-22s %s\n", "------", "---", "---", "-----");

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (keep_running) {
        ring_buffer__poll(rb, 100);  /* 100ms timeout */
    }

    /* --- clean up --- */
    ring_buffer__free(rb);
    opts.flags = opts.prog_id = opts.prog_fd = 0;
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    
    // egress detach
    opts_egress.flags = opts_egress.prog_id = opts_egress.prog_fd = 0;
    bpf_tc_detach(&hook_egress, &opts_egress);
    bpf_tc_hook_destroy(&hook_egress);
    
    bpf_object__close(obj);
    printf("\ndetached.\n");
    return 0;
}