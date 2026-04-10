#ifndef MYCNI_H
#define MYCNI_H

#include <stdint.h>

#define POD_CIDR        "10.244.0.0/16"
#define NODE_SUBNET     "10.244.1"      /* this node's /24 */
#define GATEWAY_IP      "10.244.1.1"   /* host-side veth IP, pod's default gw */
#define ALLOC_FILE      "/var/lib/mycni/allocations"
#define VETH_PREFIX     "veth"
#define MAX_PODS        254             /* .1 reserved for gateway, .255 broadcast */

struct cni_config {
    char cni_command[16];   /* ADD, DEL, CHECK */
    char cni_netns[256];    /* /var/run/netns/cni-xxxx */
    char cni_ifname[16];    /* eth0 */
    char cni_containerid[128];
};

#endif