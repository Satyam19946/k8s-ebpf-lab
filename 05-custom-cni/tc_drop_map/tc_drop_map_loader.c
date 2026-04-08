#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

#define PIN_PATH "/sys/fs/bpf/conn_map"

struct conn_key {
    __u32 src_addr;
    __u8  proto;
    __u8  pad[3];
};

struct value {
    __u32 hit_count;
};

/* returns 1 if the pin path already exists, 0 otherwise */
int pin_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
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
    struct bpf_object *obj = bpf_object__open("tc_drop_map/tc_drop_map.bpf.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load failed\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_drop_map");
    if (!prog) {
        fprintf(stderr, "program 'tc_drop_map' not found\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);

    /* --- map: reuse pin if it exists, otherwise pin fresh --- */
    int map_fd;

    if (pin_exists(PIN_PATH)) {
        /*
         * A previous run pinned the map. Open it directly by path.
         * The map and all its entries are intact — no repopulation needed.
         */
        map_fd = bpf_obj_get(PIN_PATH);
        if (map_fd < 0) {
            fprintf(stderr, "bpf_obj_get failed: %s\n", strerror(errno));
            return 1;
        }
        printf("reusing pinned map at %s\n", PIN_PATH);
    } else {
        /*
         * First run. Pin the map and populate initial blocked entries.
         */
        struct bpf_map *map = bpf_object__find_map_by_name(obj, "conn_map");
        if (!map) {
            fprintf(stderr, "map 'conn_map' not found\n");
            return 1;
        }

        if (bpf_map__pin(map, PIN_PATH)) {
            fprintf(stderr, "bpf_map__pin failed: %s\n", strerror(errno));
            return 1;
        }
        printf("pinned map at %s\n", PIN_PATH);

        map_fd = bpf_map__fd(map);

        /* populate initial blocked entry */
        struct conn_key key = {};
        key.src_addr = htonl(0x0a000002);   /* 10.0.0.2 */
        key.proto    = 1;                    /* ICMP */

        struct value val = { .hit_count = 0 };
        if (bpf_map_update_elem(map_fd, &key, &val, BPF_NOEXIST)) {
            fprintf(stderr, "bpf_map_update_elem failed\n");
            return 1;
        }

        printf("blocking: 10.0.0.2 proto=ICMP\n");
    }

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

    printf("tc_drop_map attached to %s ingress. Ctrl+C to detach.\n", iface);

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