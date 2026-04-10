#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

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

    /* --- get map fd --- */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "policy_map");
    if (!map) {
        fprintf(stderr, "map 'policy_map' not found\n");
        return 1;
    }

    int map_fd = bpf_map__fd(map);

    /*
     * populate a test policy entry:
     * allow 10.244.1.2 -> 10.244.1.1 port 8080 TCP
     * everything else is default deny (not in map = TC_ACT_SHOT)
     */
    struct policy_key key = {};
    key.src_ip   = htonl(0x0af40102);   /* 10.244.1.2 */
    key.dst_ip   = htonl(0x0af40101);   /* 10.244.1.1 */
    key.dst_port = htons(8080);
    key.proto    = 6;                    /* TCP */

    struct policy_val val = { .action = 1 };
    if (bpf_map_update_elem(map_fd, &key, &val, BPF_NOEXIST)) {
        fprintf(stderr, "bpf_map_update_elem failed: %s\n", strerror(errno));
        return 1;
    }

    printf("tc_policy attached to %s ingress\n", iface);
    printf("default deny — allow: 10.244.1.2 -> 10.244.1.1:8080 TCP\n");
    printf("Ctrl+C to detach.\n");

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (keep_running)
        sleep(1);

    /* --- detach and clean up --- */
    opts.flags = opts.prog_id = opts.prog_fd = 0;
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);

    printf("\ndetached.\n");
    return 0;
}