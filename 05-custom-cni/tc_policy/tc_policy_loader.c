#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "tc_monitor.h"

#define PIN_POLICY  "/sys/fs/bpf/policy_map"
#define PIN_CT      "/sys/fs/bpf/ct_map"
#define PIN_RB      "/sys/fs/bpf/monitor_rb"
#define PIN_PROG    "/sys/fs/bpf/tc_policy_prog"

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

static int handle_event(void *ctx, void *data, size_t size)
{
    if (size < sizeof(struct monitor_event))
        return 0;

    struct monitor_event *e = data;

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &e->dst_ip, dst_str, sizeof(dst_str));

    const char *action_str;
    switch (e->action) {
        case ACTION_CT_HIT:  action_str = "CT_HIT  "; break;
        case ACTION_ALLOWED: action_str = "ALLOWED "; break;
        case ACTION_DROPPED: action_str = "DROPPED "; break;
        default:             action_str = "UNKNOWN "; break;
    }

    printf("[%s] %s:%d -> %s:%d proto=%d\n",
        action_str,
        src_str, ntohs(e->src_port),
        dst_str, ntohs(e->dst_port),
        e->proto);

    return 0;
}

int main(void)
{
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

    /* --- pin program so mycni can attach it to new veths --- */
    if (bpf_program__pin(prog, PIN_PROG)) {
        fprintf(stderr, "bpf_program__pin failed: %s\n", strerror(errno));
        return 1;
    }

    /* --- pin maps so mycni can write policy entries --- */
    struct bpf_map *policy_map = bpf_object__find_map_by_name(obj, "policy_map");
    struct bpf_map *ct_map     = bpf_object__find_map_by_name(obj, "ct_map");
    struct bpf_map *rb_map     = bpf_object__find_map_by_name(obj, "monitor_rb");

    if (!policy_map || !ct_map || !rb_map) {
        fprintf(stderr, "failed to find maps\n");
        return 1;
    }

    if (bpf_map__pin(policy_map, PIN_POLICY)) {
        fprintf(stderr, "pin policy_map failed: %s\n", strerror(errno));
        return 1;
    }
    if (bpf_map__pin(ct_map, PIN_CT)) {
        fprintf(stderr, "pin ct_map failed: %s\n", strerror(errno));
        return 1;
    }
    if (bpf_map__pin(rb_map, PIN_RB)) {
        fprintf(stderr, "pin monitor_rb failed: %s\n", strerror(errno));
        return 1;
    }

    /* --- set up ringbuf poller --- */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(rb_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        return 1;
    }

    printf("tc_policy daemon running.\n");
    printf("pinned: %s  %s  %s  %s\n", PIN_PROG, PIN_POLICY, PIN_CT, PIN_RB);
    printf("waiting for mycni to attach programs to veths...\n\n");
    printf("%-10s %-22s %-22s %s\n", "action", "src", "dst", "proto");
    printf("%-10s %-22s %-22s %s\n", "------", "---", "---", "-----");

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (keep_running)
        ring_buffer__poll(rb, 100);

    /* --- cleanup pins on exit --- */
    ring_buffer__free(rb);
    bpf_program__unpin(prog, PIN_PROG);
    bpf_map__unpin(policy_map, PIN_POLICY);
    bpf_map__unpin(ct_map, PIN_CT);
    bpf_map__unpin(rb_map, PIN_RB);
    bpf_object__close(obj);

    printf("\nshutdown.\n");
    return 0;
}