// PROTOTYPE ONLY: hard-coded loopback tuple guard for the Phase G Linux spike.
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef ALLOWED_PORT
#error "ALLOWED_PORT must be provided by the prototype runner"
#endif

SEC("cgroup/connect4")
int guard_ipv4(struct bpf_sock_addr *context)
{
    if (context->user_ip4 != bpf_htonl(0x7f000001))
        return 0;
    return context->user_port == bpf_htons(ALLOWED_PORT);
}

SEC("cgroup/connect6")
int guard_ipv6(struct bpf_sock_addr *context)
{
    if (context->user_ip6[0] != 0 || context->user_ip6[1] != 0 ||
        context->user_ip6[2] != 0 || context->user_ip6[3] != bpf_htonl(1))
        return 0;
    return context->user_port == bpf_htons(ALLOWED_PORT);
}

char LICENSE[] SEC("license") = "GPL";
