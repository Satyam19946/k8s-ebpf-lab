#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

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

    /* --- load the BPF object --- */
    struct bpf_object *obj = bpf_object__open("tc_drop/tc_drop.bpf.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load failed\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_drop");
    if (!prog) {
        fprintf(stderr, "program 'tc_drop' not found\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);

    /* --- create the clsact qdisc on the interface --- */
    LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex   = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );

    /*
     * bpf_tc_hook_create attaches a clsact qdisc to the interface.
     * If one already exists, it returns -EEXIST — that's fine, we
     * can still add filters to it. We ignore that specific error.
     */
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "bpf_tc_hook_create failed: %d\n", err);
        return 1;
    }

    /* --- attach the BPF program as a filter --- */
    LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = prog_fd,
    );

    if (bpf_tc_attach(&hook, &opts)) {
        fprintf(stderr, "bpf_tc_attach failed\n");
        return 1;
    }

    printf("tc_drop attached to %s ingress. Ctrl+C to detach.\n", iface);
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