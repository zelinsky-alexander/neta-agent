#ifndef NETA_LIFECYCLE_WIRE_H
#define NETA_LIFECYCLE_WIRE_H

#include <linux/types.h>

#define NETA_LIFECYCLE_WIRE_VERSION 2
#define NETA_LIFECYCLE_COMM_LENGTH 16

enum neta_lifecycle_wire_type {
    NETA_LIFECYCLE_CONNECT = 1,
    NETA_LIFECYCLE_ACCEPT = 2,
    NETA_LIFECYCLE_CLOSE = 3,
};

enum neta_lifecycle_availability {
    NETA_HAS_KERNEL_PID = 1U << 0,
    NETA_HAS_UID = 1U << 1,
    NETA_HAS_COOKIE = 1U << 2,
    NETA_HAS_NETNS = 1U << 3,
    NETA_HAS_LOCAL = 1U << 4,
    NETA_HAS_REMOTE = 1U << 5,
    NETA_HAS_START_TIME = 1U << 6,
    NETA_HAS_AGENT_PID = 1U << 7,
    NETA_HAS_AGENT_PID_NAMESPACE = 1U << 8,
};

struct neta_lifecycle_config {
    __u64 agent_pid_namespace_device;
    __u64 agent_pid_namespace_inode;
};

struct neta_lifecycle_wire_event {
    __u16 version;
    __u16 size;
    __u8 type;
    __u8 family;
    __u8 protocol;
    __u8 tcp_state;
    __u32 availability;
    __u32 kernel_pid;
    __u32 kernel_tgid;
    __u32 agent_pid;
    __u32 agent_tgid;
    __u32 uid;
    __u64 timestamp_ns;
    __u64 socket_cookie;
    __u64 network_namespace_inode;
    __u64 process_start_time_ns;
    __u64 agent_pid_namespace_device;
    __u64 agent_pid_namespace_inode;
    __u16 local_port;
    __u16 remote_port;
    __u8 local_address[16];
    __u8 remote_address[16];
    char comm[NETA_LIFECYCLE_COMM_LENGTH];
};

#endif
