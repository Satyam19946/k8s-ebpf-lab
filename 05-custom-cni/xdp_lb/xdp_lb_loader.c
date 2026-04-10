#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

struct service_key {
    __u32  vip;
    __u16  port;
    __u8   proto;
    __u8   pad;
};

struct backend {
    __u32  ip;
    __u16  port;
    __u8   pad[2];
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

    struct bpf_object *obj = bpf_object__open("xdp_lb/xdp_lb.bpf.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load failed\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_lb");
    if (!prog) {
        fprintf(stderr, "program 'xdp_lb' not found\n");
        return 1;
    }

    /* attach XDP program to interface */
    int prog_fd = bpf_program__fd(prog);
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "bpf_xdp_attach failed: %s\n", strerror(errno));
        return 1;
    }

    /* get map fd */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "service_map");
    if (!map) {
        fprintf(stderr, "map 'service_map' not found\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    /* populate a test service entry
     * VIP: 10.96.0.10:80 TCP → backend: 10.244.1.2:8080
     */
    struct service_key key = {};
    key.vip   = htonl(0x0a60000a);   /* 10.96.0.10  */
    key.port  = htons(80);
    key.proto = 6;                    /* TCP */

    struct backend val = {};
    val.ip   = htonl(0x0af40102);   /* 10.244.1.2  */
    val.port = htons(8080);

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_NOEXIST)) {
        fprintf(stderr, "bpf_map_update_elem failed: %s\n", strerror(errno));
        return 1;
    }

    printf("xdp_lb attached to %s\n", iface);
    printf("service: 10.96.0.10:80 -> 10.244.1.2:8080\n");
    printf("Ctrl+C to detach.\n");

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (keep_running)
        sleep(1);

    /* detach XDP */
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);

    printf("\ndetached.\n");
    return 0;
}