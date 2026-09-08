#ifndef NETA_PROCESS_EXEC_WIRE_H
#define NETA_PROCESS_EXEC_WIRE_H

#include <linux/types.h>

#define NETA_PROCESS_EXEC_WIRE_VERSION 2
#define NETA_PROCESS_EXEC_COMM_LENGTH 16
#define NETA_PROCESS_EXEC_PATH_LENGTH 256

#define NETA_PROCESS_EVENT_START 1
#define NETA_PROCESS_EVENT_EXIT 2

enum neta_process_exec_availability {
    NETA_EXEC_HAS_PID = 1U << 0,
    NETA_EXEC_HAS_UID = 1U << 1,
    NETA_EXEC_HAS_START_TIME = 1U << 2,
    NETA_EXEC_HAS_PATH = 1U << 3,
    NETA_EXEC_HAS_PARENT = 1U << 4,
    NETA_EXEC_HAS_GID = 1U << 5,
    NETA_EXEC_HAS_EXIT_CODE = 1U << 6,
};

struct neta_process_exec_wire_event {
    __u16 version;
    __u16 size;
    __u16 event_type;
    __u16 reserved;
    __u32 availability;
    __u32 pid;
    __u32 tgid;
    __u32 parent_pid;
    __u32 parent_tgid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp_ns;
    __u64 process_start_time_ns;
    __s32 exit_code;
    __u32 reserved2;
    char comm[NETA_PROCESS_EXEC_COMM_LENGTH];
    char executable_path[NETA_PROCESS_EXEC_PATH_LENGTH];
};

#endif
