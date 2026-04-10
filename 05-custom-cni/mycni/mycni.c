#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "mycni.h"

/* ------------------------------------------------------------------ */
/* IP allocation — dead simple file-based pool                         */
/* ------------------------------------------------------------------ */

/*
 * Allocate the next free IP in NODE_SUBNET.
 * Format of ALLOC_FILE: one containerid:ip pair per line.
 *   abc123:10.244.1.5
 *   def456:10.244.1.6
 */
int alloc_ip(const char *containerid, char *ip_out)
{
    mkdir("/var/lib/mycni", 0755);

    /* read existing allocations, find used IPs */
    int used[256] = {};
    used[0] = used[1] = used[255] = 1;   /* .0 network, .1 gateway, .255 broadcast */

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

    /* find first free octet */
    int octet = -1;
    for (int i = 2; i < 255; i++) {
        if (!used[i]) { octet = i; break; }
    }

    if (octet == -1) {
        fprintf(stderr, "mycni: IP pool exhausted\n");
        return -1;
    }

    snprintf(ip_out, 32, "%s.%d", NODE_SUBNET, octet);

    /* append to alloc file */
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
        /* keep lines that don't match this containerid */
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
/* ADD                                                                  */
/* ------------------------------------------------------------------ */

int cmd_add(struct cni_config *cfg)
{
    char pod_ip[32];
    if (alloc_ip(cfg->cni_containerid, pod_ip) < 0)
        return -1;

    /* generate a veth name from the container ID (first 8 chars) */
    char host_veth[16];
    snprintf(host_veth, sizeof(host_veth), "%s%.8s",
             VETH_PREFIX, cfg->cni_containerid);

    /* 1. create veth pair in host netns */
    if (run("ip link add %s type veth peer name %s",
            host_veth, cfg->cni_ifname) != 0)
        return -1;

    /* 2. move pod-side into the pod netns */
    if (run("ip link set %s netns %s",
            cfg->cni_ifname, cfg->cni_netns) != 0)
        return -1;

    /* 3. assign IP to pod-side interface inside pod netns */
    if (run("nsenter --net=%s -- ip addr add %s/24 dev %s",
            cfg->cni_netns, pod_ip, cfg->cni_ifname) != 0)
        return -1;

    /* 4. bring pod-side up */
    if (run("nsenter --net=%s -- ip link set %s up",
            cfg->cni_netns, cfg->cni_ifname) != 0)
        return -1;

    /* 5. bring loopback up inside pod netns */
    if (run("nsenter --net=%s -- ip link set lo up",
            cfg->cni_netns) != 0)
        return -1;

    /* 6. add default route in pod netns via gateway */
    if (run("nsenter --net=%s -- ip route add default via %s",
            cfg->cni_netns, GATEWAY_IP) != 0)
        return -1;

    /* 7. bring host-side veth up */
    if (run("ip link set %s up", host_veth) != 0)
        return -1;

    /* 8. add host route to pod IP via host-side veth */
    if (run("ip route add %s/32 dev %s", pod_ip, host_veth) != 0)
        return -1;

    /* 9. write CNI result JSON to stdout — kubelet reads this */
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
    /* generate the same veth name we used on ADD */
    char host_veth[16];
    snprintf(host_veth, sizeof(host_veth), "%s%.8s",
             VETH_PREFIX, cfg->cni_containerid);

    /* deleting the host-side veth automatically deletes the peer */
    run("ip link del %s", host_veth);

    release_ip(cfg->cni_containerid);

    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    struct cni_config cfg = {};

    /* read environment variables kubelet set */
    const char *cmd = getenv("CNI_COMMAND");
    const char *netns = getenv("CNI_NETNS");
    const char *ifname = getenv("CNI_IFNAME");
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
        /* CHECK: verify network is still set up correctly */
        /* minimal implementation — just return success */
        printf("{\"cniVersion\": \"0.4.0\"}\n");
        return 0;
    }

    fprintf(stderr, "mycni: unknown command: %s\n", cfg.cni_command);
    return 1;
}