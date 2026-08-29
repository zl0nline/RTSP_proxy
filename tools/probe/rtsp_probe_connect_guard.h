#ifndef RTSP_PROBE_CONNECT_GUARD_H
#define RTSP_PROBE_CONNECT_GUARD_H

#include <linux/types.h>

#define RTSP_PROBE_CONNECT_GUARD_ABI_VERSION 1
#define RTSP_PROBE_AF_INET 2
#define RTSP_PROBE_AF_INET6 10

struct rtsp_probe_connect_target {
    __u32 abi_version;
    __u32 address_family;
    __u32 port_network_order;
    __u32 address[4];
    __u32 reserved;
};

_Static_assert(sizeof(struct rtsp_probe_connect_target) == 32,
               "probe connect guard ABI must remain 32 bytes");

#endif
