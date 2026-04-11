#include <linux/bpf.h>

#ifndef TC_MONITOR_H
#define TC_MONITOR_H

#define ACTION_CT_HIT    0
#define ACTION_ALLOWED   1
#define ACTION_DROPPED   2

struct monitor_event {
    __u32   src_ip;
    __u32   dst_ip;
    __u16   src_port;
    __u16   dst_port;
    __u8    proto;
    __u8    action;     /* ACTION_* above */
    __u8    pad[2];
};                      /* 16 bytes, multiple of 8 */

#endif