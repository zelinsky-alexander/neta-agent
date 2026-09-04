#ifndef NETA_PROCESS_EXEC_WIRE_H
#define NETA_PROCESS_EXEC_WIRE_H

#include <linux/types.h>

#define NETA_PROCESS_EXEC_WIRE_VERSION 1
#define NETA_PROCESS_EXEC_COMM_LENGTH 16
#define NETA_PROCESS_EXEC_PATH_LENGTH 256

enum neta_process_exec_availability {
    NETA_EXEC_HAS_PID = 1U << 0,
    NETA_EXEC_HAS_UID = 1U << 1,
    NETA_EXEC_HAS_START_TIME = 1U << 2,
    NETA_EXEC_HAS_PATH = 1U << 3,
};

struct neta_process_exec_wire_event {
    __u16 version;
    __u16 size;
    __u32 availability;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u64 timestamp_ns;
    __u64 process_start_time_ns;
    char comm[NETA_PROCESS_EXEC_COMM_LENGTH];
    char executable_path[NETA_PROCESS_EXEC_PATH_LENGTH];
};

#endif
