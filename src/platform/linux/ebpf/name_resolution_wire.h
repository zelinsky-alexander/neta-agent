#ifndef NETA_NAME_RESOLUTION_WIRE_H
#define NETA_NAME_RESOLUTION_WIRE_H

#include <linux/types.h>

#define NETA_NAME_RESOLUTION_WIRE_VERSION 1
#define NETA_NAME_RESOLUTION_QUERY_LENGTH 256
#define NETA_NAME_RESOLUTION_CANONICAL_LENGTH 256
#define NETA_NAME_RESOLUTION_COMM_LENGTH 16
#define NETA_NAME_RESOLUTION_MAX_ADDRESSES 8

enum neta_name_resolution_availability {
    NETA_NAME_HAS_KERNEL_PID = 1U << 0,
    NETA_NAME_HAS_UID = 1U << 1,
    NETA_NAME_HAS_AGENT_PID = 1U << 2,
    NETA_NAME_HAS_AGENT_PID_NAMESPACE = 1U << 3,
    NETA_NAME_HAS_START_TIME = 1U << 4,
    NETA_NAME_HAS_NETNS = 1U << 5,
    NETA_NAME_HAS_CANONICAL_NAME = 1U << 6,
    NETA_NAME_PARTIAL = 1U << 7,
};

struct neta_name_resolution_config {
    __u64 agent_pid_namespace_device;
    __u64 agent_pid_namespace_inode;
};

struct neta_name_resolution_wire_address {
    __u8 family;
    __u8 reserved[3];
    __u8 address[16];
};

struct neta_name_resolution_wire_event {
    __u16 version;
    __u16 size;
    __u32 availability;
    __s32 result_code;
    __u32 address_count;
    __u32 kernel_pid;
    __u32 kernel_tgid;
    __u32 agent_pid;
    __u32 agent_tgid;
    __u32 uid;
    __u64 started_ns;
    __u64 completed_ns;
    __u64 process_start_time_ns;
    __u64 network_namespace_inode;
    __u64 agent_pid_namespace_device;
    __u64 agent_pid_namespace_inode;
    char query_name[NETA_NAME_RESOLUTION_QUERY_LENGTH];
    char canonical_name[NETA_NAME_RESOLUTION_CANONICAL_LENGTH];
    char comm[NETA_NAME_RESOLUTION_COMM_LENGTH];
    struct neta_name_resolution_wire_address addresses[NETA_NAME_RESOLUTION_MAX_ADDRESSES];
};

#endif
