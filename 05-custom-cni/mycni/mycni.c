#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "mycni.h"

/* ------------------------------------------------------------------ */
/* IP allocation                                                        */
/* ------------------------------------------------------------------ */

int alloc_ip(const char *containerid, char *ip_out)
{
    mkdir("/var/lib/mycni", 0755);

    int used[256] = {};
    used[0] = used[1] = used[255] = 1;

    FILE *f = fopen(ALLOC_FILE, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char *colon = strchr(line, ':');
            if (!colon) continue;
            int last_octet = atoi(colon + strlen(NODE_SUBNET) + 2);
            used[last_octet] = 1;
        }
        fclose(f);
    }

    int octet = -1;
    for (int i = 2; i < 255; i++) {
        if (!used[i]) { octet = i; break; }
    }

    if (octet == -1) {
        fprintf(stderr, "mycni: IP pool exhausted\n");
        return -1;
    }

    snprintf(ip_out, 32, "%s.%d", NODE_SUBNET, octet);

    f = fopen(ALLOC_FILE, "a");
    if (!f) {
        fprintf(stderr, "mycni: cannot open alloc file: %s\n", strerror(errno));
        return -1;
    }
    fprintf(f, "%s:%s\n", containerid, ip_out);
    fclose(f);

    return 0;
}

int release_ip(const char *containerid)
{
    FILE *f = fopen(ALLOC_FILE, "r");
    if (!f) return 0;

    char lines[256][256];
    int count = 0;
    char line[256];

    while (fgets(line, sizeof(line), f) && count < 256) {
        if (strncmp(line, containerid, strlen(containerid)) != 0)
            strncpy(lines[count++], line, sizeof(lines[0]));
    }
    fclose(f);

    f = fopen(ALLOC_FILE, "w");
    if (!f) return -1;
    for (int i = 0; i < count; i++)
        fputs(lines[i], f);
    fclose(f);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Shell command helper                                                 */
/* ------------------------------------------------------------------ */

int run(const char *fmt, ...)
{
    char cmd[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);

    fprintf(stderr, "mycni: run: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0)
        fprintf(stderr, "mycni: command failed (exit %d): %s\n", ret, cmd);
    return ret;
}

/* ------------------------------------------------------------------ */
/* BPF — attach tc_policy to a veth                                    */
/* ------------------------------------------------------------------ */

int attach_tc_policy(const char *iface)
{
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "mycni: if_nametoindex %s failed\n", iface);
        return -1;
    }

    int prog_fd = bpf_obj_get(PIN_PROG);
    if (prog_fd < 0) {
        fprintf(stderr, "mycni: bpf_obj_get prog failed: %s\n", strerror(errno));
        return -1;
    }

    /* ingress */
    LIBBPF_OPTS(bpf_tc_hook, hook_in,
        .ifindex      = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );
    int err = bpf_tc_hook_create(&hook_in);
    if (err && err != -EEXIST) {
        fprintf(stderr, "mycni: bpf_tc_hook_create ingress failed: %d\n", err);
        close(prog_fd);
        return -1;
    }
    LIBBPF_OPTS(bpf_tc_opts, opts_in, .prog_fd = prog_fd);
    if (bpf_tc_attach(&hook_in, &opts_in)) {
        fprintf(stderr, "mycni: bpf_tc_attach ingress failed\n");
        close(prog_fd);
        return -1;
    }

    /* egress */
    LIBBPF_OPTS(bpf_tc_hook, hook_out,
        .ifindex      = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );
    err = bpf_tc_hook_create(&hook_out);
    if (err && err != -EEXIST) {
        fprintf(stderr, "mycni: bpf_tc_hook_create egress failed: %d\n", err);
        close(prog_fd);
        return -1;
    }
    LIBBPF_OPTS(bpf_tc_opts, opts_out, .prog_fd = prog_fd);
    if (bpf_tc_attach(&hook_out, &opts_out)) {
        fprintf(stderr, "mycni: bpf_tc_attach egress failed\n");
        close(prog_fd);
        return -1;
    }

    close(prog_fd);
    fprintf(stderr, "mycni: tc_policy attached to %s (ingress + egress)\n", iface);
    return 0;
}

int detach_tc_policy(const char *iface)
{
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) return 0;  /* already gone */

    LIBBPF_OPTS(bpf_tc_hook, hook_in,
        .ifindex      = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );
    bpf_tc_hook_destroy(&hook_in);

    LIBBPF_OPTS(bpf_tc_hook, hook_out,
        .ifindex      = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );
    bpf_tc_hook_destroy(&hook_out);

    fprintf(stderr, "mycni: tc_policy detached from %s\n", iface);
    return 0;
}

/* ------------------------------------------------------------------ */
/* BPF — write pod policy entry into pinned policy_map                 */
/* ------------------------------------------------------------------ */

int add_pod_policy(const char *pod_ip)
{
    int map_fd = bpf_obj_get(PIN_POLICY);
    if (map_fd < 0) {
        fprintf(stderr, "mycni: bpf_obj_get policy_map failed: %s\n", strerror(errno));
        return -1;
    }

    struct in_addr addr;
    inet_pton(AF_INET, pod_ip, &addr);

    /*
     * Default: allow this pod to reach the gateway on any TCP port.
     * In production this would be driven by NetworkPolicy objects
     * from the Kubernetes API.
     */
    struct policy_key key = {};
    key.src_ip   = addr.s_addr;
    key.dst_ip   = htonl(0x0af40101);  /* 10.244.1.1 gateway */
    key.dst_port = htons(8080);
    key.proto    = 6;                   /* TCP */

    struct policy_val val = { .action = 1 };
    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)) {
        fprintf(stderr, "mycni: bpf_map_update_elem failed: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    fprintf(stderr, "mycni: policy entry added for pod %s\n", pod_ip);
    close(map_fd);
    return 0;
}

int remove_pod_policy(const char *pod_ip)
{
    int map_fd = bpf_obj_get(PIN_POLICY);
    if (map_fd < 0) return 0;  /* map gone, nothing to do */

    struct in_addr addr;
    inet_pton(AF_INET, pod_ip, &addr);

    struct policy_key key = {};
    key.src_ip   = addr.s_addr;
    key.dst_ip   = htonl(0x0af40101);
    key.dst_port = htons(8080);
    key.proto    = 6;

    bpf_map_delete_elem(map_fd, &key);
    close(map_fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* ADD                                                                  */
/* ------------------------------------------------------------------ */

int cmd_add(struct cni_config *cfg)
{
    char pod_ip[32];
    if (alloc_ip(cfg->cni_containerid, pod_ip) < 0)
        return -1;

    char host_veth[16];
    snprintf(host_veth, sizeof(host_veth), "%s%.8s",
             VETH_PREFIX, cfg->cni_containerid);

    /* 1. create veth pair */
    if (run("ip link add %s type veth peer name %s",
            host_veth, cfg->cni_ifname) != 0)
        return -1;

    /* 2. move pod-side into pod netns */
    if (run("ip link set %s netns %s",
            cfg->cni_ifname, cfg->cni_netns) != 0)
        return -1;

    /* 3. assign IP inside pod netns */
    if (run("nsenter --net=%s -- ip addr add %s/24 dev %s",
            cfg->cni_netns, pod_ip, cfg->cni_ifname) != 0)
        return -1;

    /* 4. bring pod-side up */
    if (run("nsenter --net=%s -- ip link set %s up",
            cfg->cni_netns, cfg->cni_ifname) != 0)
        return -1;

    /* 5. bring loopback up */
    if (run("nsenter --net=%s -- ip link set lo up",
            cfg->cni_netns) != 0)
        return -1;

    /* 6. default route via gateway */
    if (run("nsenter --net=%s -- ip route add default via %s",
            cfg->cni_netns, GATEWAY_IP) != 0)
        return -1;

    /* 7. bring host-side veth up */
    if (run("ip link set %s up", host_veth) != 0)
        return -1;

    /* 8. host route to pod */
    if (run("ip route add %s/32 dev %s", pod_ip, host_veth) != 0)
        return -1;

    /* 9. attach tc_policy BPF program to the new veth */
    if (attach_tc_policy(host_veth) != 0)
        return -1;

    /* 10. write policy entry for this pod into the pinned map */
    if (add_pod_policy(pod_ip) != 0)
        return -1;

    /* 11. return CNI result JSON to kubelet */
    printf("{\n");
    printf("  \"cniVersion\": \"0.4.0\",\n");
    printf("  \"interfaces\": [{\n");
    printf("    \"name\": \"%s\",\n", cfg->cni_ifname);
    printf("    \"sandbox\": \"%s\"\n", cfg->cni_netns);
    printf("  }],\n");
    printf("  \"ips\": [{\n");
    printf("    \"version\": \"4\",\n");
    printf("    \"address\": \"%s/24\",\n", pod_ip);
    printf("    \"gateway\": \"%s\",\n", GATEWAY_IP);
    printf("    \"interface\": 0\n");
    printf("  }]\n");
    printf("}\n");

    return 0;
}

/* ------------------------------------------------------------------ */
/* DEL                                                                  */
/* ------------------------------------------------------------------ */

int cmd_del(struct cni_config *cfg)
{
    char host_veth[16];
    snprintf(host_veth, sizeof(host_veth), "%s%.8s",
             VETH_PREFIX, cfg->cni_containerid);

    /* detach BPF before deleting the interface */
    detach_tc_policy(host_veth);

    /* delete veth — peer inside pod netns is deleted automatically */
    run("ip link del %s", host_veth);

    /* release IP allocation */
    release_ip(cfg->cni_containerid);

    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    struct cni_config cfg = {};

    const char *cmd         = getenv("CNI_COMMAND");
    const char *netns       = getenv("CNI_NETNS");
    const char *ifname      = getenv("CNI_IFNAME");
    const char *containerid = getenv("CNI_CONTAINERID");

    if (!cmd || !containerid) {
        fprintf(stderr, "mycni: missing CNI environment variables\n");
        return 1;
    }

    strncpy(cfg.cni_command,     cmd,         sizeof(cfg.cni_command) - 1);
    strncpy(cfg.cni_containerid, containerid, sizeof(cfg.cni_containerid) - 1);
    if (netns)   strncpy(cfg.cni_netns,  netns,   sizeof(cfg.cni_netns) - 1);
    if (ifname)  strncpy(cfg.cni_ifname, ifname,  sizeof(cfg.cni_ifname) - 1);

    if (strcmp(cfg.cni_command, "ADD") == 0)
        return cmd_add(&cfg) == 0 ? 0 : 1;

    if (strcmp(cfg.cni_command, "DEL") == 0)
        return cmd_del(&cfg) == 0 ? 0 : 1;

    if (strcmp(cfg.cni_command, "CHECK") == 0) {
        printf("{\"cniVersion\": \"0.4.0\"}\n");
        return 0;
    }

    fprintf(stderr, "mycni: unknown command: %s\n", cfg.cni_command);
    return 1;
}