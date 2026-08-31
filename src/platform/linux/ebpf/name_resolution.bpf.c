#include "vmlinux_min.h"
#include "name_resolution_wire.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} name_resolution_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct neta_name_resolution_config);
} name_resolution_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} name_resolution_drops SEC(".maps");

struct neta_name_resolution_pending {
    __u64 started_ns;
    __u64 result_out;
    __u32 depth;
    __u8 suppressed;
    __u8 partial;
    __u8 reserved[2];
    char query_name[NETA_NAME_RESOLUTION_QUERY_LENGTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct neta_name_resolution_pending);
} name_resolution_pending SEC(".maps");

// This userspace ABI layout is intentionally limited to 64-bit glibc, which is
// the only runtime advertised by the userspace loader for this collector.
struct neta_user_addrinfo {
    __s32 ai_flags;
    __s32 ai_family;
    __s32 ai_socktype;
    __s32 ai_protocol;
    __u32 ai_addrlen;
    __u32 pointer_alignment_padding;
    __u64 ai_addr;
    __u64 ai_canonname;
    __u64 ai_next;
};

struct neta_user_sockaddr_in {
    __u16 family;
    __u16 port;
    __u32 address;
    __u8 zero[8];
};

struct neta_user_sockaddr_in6 {
    __u16 family;
    __u16 port;
    __u32 flowinfo;
    __u8 address[16];
    __u32 scope_id;
};

static __always_inline void record_drop(void)
{
    const __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&name_resolution_drops, &key);

    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline void mark_partial(struct neta_name_resolution_wire_event *event)
{
    event->availability |= NETA_NAME_PARTIAL;
}

static __always_inline void fill_process(struct neta_name_resolution_wire_event *event)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    const __u32 key = 0;
    const struct neta_name_resolution_config *config;
    struct bpf_pidns_info namespace_ids = {};

    event->kernel_pid = (__u32)pid_tgid;
    event->kernel_tgid = (__u32)(pid_tgid >> 32);
    event->uid = (__u32)uid_gid;
    event->availability |= NETA_NAME_HAS_KERNEL_PID | NETA_NAME_HAS_UID;

    config = bpf_map_lookup_elem(&name_resolution_config, &key);
    if (config && config->agent_pid_namespace_inode != 0) {
        event->agent_pid_namespace_device = config->agent_pid_namespace_device;
        event->agent_pid_namespace_inode = config->agent_pid_namespace_inode;
        event->availability |= NETA_NAME_HAS_AGENT_PID_NAMESPACE;
        if (bpf_get_ns_current_pid_tgid(config->agent_pid_namespace_device,
                                        config->agent_pid_namespace_inode,
                                        &namespace_ids, sizeof(namespace_ids)) == 0 &&
            namespace_ids.pid != 0 && namespace_ids.tgid != 0) {
            event->agent_pid = namespace_ids.pid;
            event->agent_tgid = namespace_ids.tgid;
            event->availability |= NETA_NAME_HAS_AGENT_PID;
        }
    }

    bpf_get_current_comm(event->comm, sizeof(event->comm));
    if (task) {
        struct nsproxy *namespace_proxy;
        struct net *network;

        if (bpf_core_field_exists(task->start_boottime)) {
            event->process_start_time_ns = BPF_CORE_READ(task, start_boottime);
            event->availability |= NETA_NAME_HAS_START_TIME;
        }
        namespace_proxy = BPF_CORE_READ(task, nsproxy);
        if (namespace_proxy) {
            network = BPF_CORE_READ(namespace_proxy, net_ns);
            if (network) {
                event->network_namespace_inode = BPF_CORE_READ(network, ns.inum);
                event->availability |= NETA_NAME_HAS_NETNS;
            }
        }
    }
}

static __always_inline void add_ipv4_address(struct neta_name_resolution_wire_event *event,
                                              __u64 user_address)
{
    struct neta_user_sockaddr_in address = {};
    struct neta_name_resolution_wire_address *output;
    __u32 index;

    if (event->address_count >= NETA_NAME_RESOLUTION_MAX_ADDRESSES)
        return;
    if (bpf_probe_read_user(&address, sizeof(address),
                            (const void *)(unsigned long)user_address) != 0) {
        mark_partial(event);
        return;
    }

    // Re-establish the scalar bound after the helper call so newer/stricter
    // verifiers can prove the variable offset into the fixed-size array.
    index = event->address_count;
    if (index >= NETA_NAME_RESOLUTION_MAX_ADDRESSES)
        return;
    output = &event->addresses[index];
    output->family = AF_INET;
    __builtin_memcpy(output->address, &address.address, sizeof(address.address));
    event->address_count = index + 1;
}

static __always_inline void add_ipv6_address(struct neta_name_resolution_wire_event *event,
                                              __u64 user_address)
{
    struct neta_user_sockaddr_in6 address = {};
    struct neta_name_resolution_wire_address *output;
    __u32 index;

    if (event->address_count >= NETA_NAME_RESOLUTION_MAX_ADDRESSES)
        return;
    if (bpf_probe_read_user(&address, sizeof(address),
                            (const void *)(unsigned long)user_address) != 0) {
        mark_partial(event);
        return;
    }

    // Re-establish the scalar bound after the helper call so newer/stricter
    // verifiers can prove the variable offset into the fixed-size array.
    index = event->address_count;
    if (index >= NETA_NAME_RESOLUTION_MAX_ADDRESSES)
        return;
    output = &event->addresses[index];
    output->family = AF_INET6;
    __builtin_memcpy(output->address, address.address, sizeof(address.address));
    event->address_count = index + 1;
}

static __always_inline void read_results(struct neta_name_resolution_wire_event *event,
                                         __u64 result_out)
{
    __u64 node = 0;

    if (result_out == 0 ||
        bpf_probe_read_user(&node, sizeof(node),
                            (const void *)(unsigned long)result_out) != 0) {
        mark_partial(event);
        return;
    }

#pragma unroll
    for (int index = 0; index < NETA_NAME_RESOLUTION_MAX_ADDRESSES; ++index) {
        struct neta_user_addrinfo info = {};

        if (node == 0)
            break;
        if (bpf_probe_read_user(&info, sizeof(info),
                                (const void *)(unsigned long)node) != 0) {
            mark_partial(event);
            break;
        }

        if ((event->availability & NETA_NAME_HAS_CANONICAL_NAME) == 0U &&
            info.ai_canonname != 0) {
            long canonical_length = bpf_probe_read_user_str(
                event->canonical_name, sizeof(event->canonical_name),
                (const void *)(unsigned long)info.ai_canonname);
            if (canonical_length > 1) {
                event->availability |= NETA_NAME_HAS_CANONICAL_NAME;
                if (canonical_length >= (long)sizeof(event->canonical_name))
                    mark_partial(event);
            } else if (canonical_length < 0) {
                mark_partial(event);
            }
        }

        if (info.ai_addr != 0 && info.ai_family == AF_INET &&
            info.ai_addrlen >= sizeof(struct neta_user_sockaddr_in)) {
            add_ipv4_address(event, info.ai_addr);
        } else if (info.ai_addr != 0 && info.ai_family == AF_INET6 &&
                   info.ai_addrlen >= sizeof(struct neta_user_sockaddr_in6)) {
            add_ipv6_address(event, info.ai_addr);
        }

        node = info.ai_next;
        if (index == NETA_NAME_RESOLUTION_MAX_ADDRESSES - 1 && node != 0)
            mark_partial(event);
    }
}

SEC("uprobe")
int neta_getaddrinfo_enter(struct pt_regs *ctx)
{
    const char *query = (const char *)PT_REGS_PARM1(ctx);
    const void *result_out = (const void *)PT_REGS_PARM4(ctx);
    const __u64 key = bpf_get_current_pid_tgid();
    struct neta_name_resolution_pending *existing;
    struct neta_name_resolution_pending pending = {};
    long query_length;

    if (!query || !result_out)
        return 0;

    existing = bpf_map_lookup_elem(&name_resolution_pending, &key);
    if (existing) {
        if (existing->depth < 0xffffffffU)
            existing->depth++;
        existing->suppressed = 1;
        record_drop();
        return 0;
    }

    pending.started_ns = bpf_ktime_get_ns();
    pending.result_out = (__u64)(unsigned long)result_out;
    pending.depth = 1;
    query_length = bpf_probe_read_user_str(pending.query_name, sizeof(pending.query_name), query);
    if (query_length <= 1)
        return 0;
    if (query_length >= (long)sizeof(pending.query_name))
        pending.partial = 1;

    if (bpf_map_update_elem(&name_resolution_pending, &key, &pending, BPF_ANY) != 0)
        record_drop();
    return 0;
}

SEC("uretprobe")
int neta_getaddrinfo_exit(struct pt_regs *ctx)
{
    const __u64 key = bpf_get_current_pid_tgid();
    struct neta_name_resolution_pending *pending;
    struct neta_name_resolution_wire_event *event;
    int result;

    pending = bpf_map_lookup_elem(&name_resolution_pending, &key);
    if (!pending)
        return 0;
    if (pending->depth > 1) {
        pending->depth--;
        return 0;
    }
    if (pending->suppressed) {
        bpf_map_delete_elem(&name_resolution_pending, &key);
        return 0;
    }

    event = bpf_ringbuf_reserve(&name_resolution_events, sizeof(*event), 0);
    if (!event) {
        record_drop();
        bpf_map_delete_elem(&name_resolution_pending, &key);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->version = NETA_NAME_RESOLUTION_WIRE_VERSION;
    event->size = sizeof(*event);
    event->started_ns = pending->started_ns;
    event->completed_ns = bpf_ktime_get_ns();
    __builtin_memcpy(event->query_name, pending->query_name, sizeof(event->query_name));
    if (pending->partial)
        mark_partial(event);
    fill_process(event);

    result = (int)PT_REGS_RC(ctx);
    event->result_code = result;
    if (result == 0)
        read_results(event, pending->result_out);

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&name_resolution_pending, &key);
    return 0;
}
