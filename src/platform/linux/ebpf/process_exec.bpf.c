#include "vmlinux_min.h"
#include "process_exec_wire.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} process_exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} process_exec_drops SEC(".maps");

static __always_inline void record_drop(void)
{
    const __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&process_exec_drops, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline struct neta_process_exec_wire_event *reserve_event(__u16 event_type)
{
    struct neta_process_exec_wire_event *event;
    const __u64 pid_tgid = bpf_get_current_pid_tgid();
    const __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *leader = 0;
    struct task_struct *parent = 0;
    struct task_struct *parent_leader = 0;

    event = bpf_ringbuf_reserve(&process_exec_events, sizeof(*event), 0);
    if (!event) {
        record_drop();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->version = NETA_PROCESS_EXEC_WIRE_VERSION;
    event->size = sizeof(*event);
    event->event_type = event_type;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (__u32)pid_tgid;
    event->tgid = (__u32)(pid_tgid >> 32);
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);
    event->availability |= NETA_EXEC_HAS_PID | NETA_EXEC_HAS_UID | NETA_EXEC_HAS_GID;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    if (task) {
        leader = BPF_CORE_READ(task, group_leader);
        if (!leader)
            leader = task;
    }
    if (leader && bpf_core_field_exists(leader->start_boottime)) {
        event->process_start_time_ns = BPF_CORE_READ(leader, start_boottime);
        event->availability |= NETA_EXEC_HAS_START_TIME;
    }

    if (task && bpf_core_field_exists(task->real_parent)) {
        parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            parent_leader = BPF_CORE_READ(parent, group_leader);
            if (!parent_leader)
                parent_leader = parent;
            event->parent_pid = BPF_CORE_READ(parent, pid);
            event->parent_tgid = BPF_CORE_READ(parent_leader, tgid);
            event->availability |= NETA_EXEC_HAS_PARENT;
            if (bpf_core_field_exists(parent_leader->start_boottime)) {
                event->parent_process_start_time_ns = BPF_CORE_READ(parent_leader, start_boottime);
                event->availability |= NETA_EXEC_HAS_PARENT_START_TIME;
            }
        }
    }

    return event;
}

SEC("tracepoint/sched/sched_process_exec")
int neta_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct neta_process_exec_wire_event *event;
    const __u32 filename_offset = BPF_CORE_READ(ctx, __data_loc_filename) & 0xffffU;
    const char *filename = (const char *)ctx + filename_offset;

    event = reserve_event(NETA_PROCESS_EVENT_START);
    if (!event)
        return 0;

    if (filename_offset != 0 &&
        bpf_probe_read_kernel_str(event->executable_path, sizeof(event->executable_path), filename) > 0) {
        event->availability |= NETA_EXEC_HAS_PATH;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int neta_sched_process_exit(void *ctx)
{
    struct neta_process_exec_wire_event *event;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    const __u64 pid_tgid = bpf_get_current_pid_tgid();
    (void)ctx;

    if ((__u32)pid_tgid != (__u32)(pid_tgid >> 32))
        return 0;

    event = reserve_event(NETA_PROCESS_EVENT_EXIT);
    if (!event)
        return 0;

    if (task && bpf_core_field_exists(task->exit_code)) {
        event->exit_code = BPF_CORE_READ(task, exit_code);
        event->availability |= NETA_EXEC_HAS_EXIT_CODE;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
