#ifndef NETA_VMLINUX_MIN_H
#define NETA_VMLINUX_MIN_H

// Curated CO-RE type boundary. Linux UAPI supplies map enums and the native
// target's tracing register ABI; the declarations below contain only kernel
// BTF types/fields read by neta-agent BPF programs.
#include <asm/ptrace.h>
#include <linux/bpf.h>

#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#error "neta-agent eBPF requires __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

typedef __u64 __addrpair;
typedef __u32 __portpair;

struct sockaddr;
struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be32 u6_addr32[4];
    } in6_u;
};

struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct nsproxy {
    struct net *net_ns;
} __attribute__((preserve_access_index));

typedef struct {
    struct net *net;
} possible_net_t;

struct sock_common {
    union {
        __addrpair skc_addrpair;
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        unsigned int skc_hash;
        __u16 skc_u16hashes[2];
    };
    union {
        __portpair skc_portpair;
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    unsigned short skc_family;
    volatile unsigned char skc_state;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
    possible_net_t skc_net;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct task_struct {
    __u64 start_boottime;
    struct nsproxy *nsproxy;
} __attribute__((preserve_access_index));

#endif
