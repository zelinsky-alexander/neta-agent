#include "vmlinux_min.h"
#include "lifecycle_wire.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} lifecycle_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct neta_lifecycle_config);
} lifecycle_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lifecycle_drops SEC(".maps");

static __always_inline void record_drop(void)
{
    const __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&lifecycle_drops, &key);

    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline void fill_process(struct neta_lifecycle_wire_event *event)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    const __u32 key = 0;
    const struct neta_lifecycle_config *config;
    struct bpf_pidns_info namespace_ids = {};

    event->kernel_pid = (__u32)pid_tgid;
    event->kernel_tgid = (__u32)(pid_tgid >> 32);
    event->uid = (__u32)uid_gid;
    event->availability |= NETA_HAS_KERNEL_PID | NETA_HAS_UID;

    config = bpf_map_lookup_elem(&lifecycle_config, &key);
    if (config && config->agent_pid_namespace_inode != 0) {
        event->agent_pid_namespace_device = config->agent_pid_namespace_device;
        event->agent_pid_namespace_inode = config->agent_pid_namespace_inode;
        event->availability |= NETA_HAS_AGENT_PID_NAMESPACE;
        if (bpf_get_ns_current_pid_tgid(config->agent_pid_namespace_device,
                                        config->agent_pid_namespace_inode,
                                        &namespace_ids, sizeof(namespace_ids)) == 0 &&
            namespace_ids.pid != 0 && namespace_ids.tgid != 0) {
            event->agent_pid = namespace_ids.pid;
            event->agent_tgid = namespace_ids.tgid;
            event->availability |= NETA_HAS_AGENT_PID;
        }
    }
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    if (task && bpf_core_field_exists(task->start_boottime)) {
        event->process_start_time_ns = BPF_CORE_READ(task, start_boottime);
        event->availability |= NETA_HAS_START_TIME;
    }
}

static __always_inline int fill_socket(struct neta_lifecycle_wire_event *event,
                                       struct sock *sk)
{
    __u16 family;
    struct net *net;

    if (!sk)
        return -1;
    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return -1;

    event->family = (__u8)family;
    event->protocol = IPPROTO_TCP;
    event->tcp_state = BPF_CORE_READ(sk, __sk_common.skc_state);
    event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (family == AF_INET) {
        __u32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(event->local_address, &local, sizeof(local));
        __builtin_memcpy(event->remote_address, &remote, sizeof(remote));
    } else {
        struct in6_addr local = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        struct in6_addr remote = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(event->local_address, &local, sizeof(local));
        __builtin_memcpy(event->remote_address, &remote, sizeof(remote));
    }
    event->availability |= NETA_HAS_LOCAL | NETA_HAS_REMOTE;

    net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
    if (net) {
        event->network_namespace_inode = BPF_CORE_READ(net, ns.inum);
        event->availability |= NETA_HAS_NETNS;
    }
    return 0;
}

static __always_inline int emit(struct sock *sk, __u8 type, __u64 socket_cookie)
{
    struct neta_lifecycle_wire_event *event;

    event = bpf_ringbuf_reserve(&lifecycle_events, sizeof(*event), 0);
    if (!event) {
        record_drop();
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->version = NETA_LIFECYCLE_WIRE_VERSION;
    event->size = sizeof(*event);
    event->type = type;
    event->timestamp_ns = bpf_ktime_get_ns();
    fill_process(event);
    if (socket_cookie != 0) {
        event->socket_cookie = socket_cookie;
        event->availability |= NETA_HAS_COOKIE;
    }
    if (fill_socket(event, sk) != 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(neta_tcp_v4_connect, struct sock *sk, struct sockaddr *address,
             int address_length, int result)
{
    (void)address;
    (void)address_length;
    return result == 0
        ? emit(sk, NETA_LIFECYCLE_CONNECT, bpf_get_socket_cookie(sk)) : 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(neta_tcp_v6_connect, struct sock *sk, struct sockaddr *address,
             int address_length, int result)
{
    (void)address;
    (void)address_length;
    return result == 0
        ? emit(sk, NETA_LIFECYCLE_CONNECT, bpf_get_socket_cookie(sk)) : 0;
}

SEC("kretprobe/inet_csk_accept")
int neta_inet_csk_accept(struct pt_regs *ctx)
{
    // BPF_PROG_TYPE_KPROBE cannot use bpf_get_socket_cookie(). Do not read
    // sk_cookie directly: it may not have been lazily generated yet. The
    // userspace tracker correlates this event by its active tuple until
    // SOCK_DIAG supplies the canonical cookie.
    return emit((struct sock *)PT_REGS_RC(ctx), NETA_LIFECYCLE_ACCEPT, 0);
}

SEC("fentry/tcp_close")
int BPF_PROG(neta_tcp_close, struct sock *sk, long timeout)
{
    (void)timeout;
    return emit(sk, NETA_LIFECYCLE_CLOSE, bpf_get_socket_cookie(sk));
}
