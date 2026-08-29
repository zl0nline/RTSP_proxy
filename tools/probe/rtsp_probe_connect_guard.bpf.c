#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "rtsp_probe_connect_guard.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rtsp_probe_connect_target);
} allowed_target SEC(".maps");

static __always_inline struct rtsp_probe_connect_target *target(void)
{
    __u32 key = 0;
    struct rtsp_probe_connect_target *configured;

    configured = bpf_map_lookup_elem(&allowed_target, &key);
    if (configured == 0 ||
        configured->abi_version != RTSP_PROBE_CONNECT_GUARD_ABI_VERSION ||
        configured->reserved != 0)
        return 0;
    return configured;
}

SEC("cgroup/connect4")
int rtsp_probe_guard_ipv4(struct bpf_sock_addr *context)
{
    struct rtsp_probe_connect_target *configured = target();

    if (configured == 0 || configured->address_family != RTSP_PROBE_AF_INET ||
        configured->address[1] != 0 || configured->address[2] != 0 ||
        configured->address[3] != 0)
        return 0;
    return context->user_port == configured->port_network_order &&
           context->user_ip4 == configured->address[0];
}

SEC("cgroup/connect6")
int rtsp_probe_guard_ipv6(struct bpf_sock_addr *context)
{
    struct rtsp_probe_connect_target *configured = target();

    if (configured == 0 || configured->address_family != RTSP_PROBE_AF_INET6)
        return 0;
    return context->user_port == configured->port_network_order &&
           context->user_ip6[0] == configured->address[0] &&
           context->user_ip6[1] == configured->address[1] &&
           context->user_ip6[2] == configured->address[2] &&
           context->user_ip6[3] == configured->address[3];
}

char LICENSE[] SEC("license") = "GPL";
