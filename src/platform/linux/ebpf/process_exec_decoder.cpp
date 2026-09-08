#include "process_exec_decoder.hpp"

#include "process_exec_wire.h"

#include <cstring>
#include <string>

namespace neta::platform::linux_ebpf {

ProcessExecDecodeResult decode_process_exec_event(std::span<const std::byte> bytes) {
    if (bytes.size() < sizeof(neta_process_exec_wire_event)) return {};

    neta_process_exec_wire_event wire{};
    std::memcpy(&wire, bytes.data(), sizeof(wire));
    if (wire.version != NETA_PROCESS_EXEC_WIRE_VERSION || wire.size != sizeof(wire)) return {};
    if (wire.event_type != NETA_PROCESS_EVENT_START && wire.event_type != NETA_PROCESS_EVENT_EXIT) {
        return {};
    }

    ProcessExecEvent event;
    event.type = wire.event_type == NETA_PROCESS_EVENT_EXIT
        ? ProcessExecEventType::Exit
        : ProcessExecEventType::Start;
    event.timestamp_ns = wire.timestamp_ns;
    if ((wire.availability & NETA_EXEC_HAS_PID) != 0U) {
        event.pid = static_cast<std::int64_t>(wire.pid);
        event.tgid = static_cast<std::int64_t>(wire.tgid);
    }
    if ((wire.availability & NETA_EXEC_HAS_PARENT) != 0U) {
        event.parent_pid = static_cast<std::int64_t>(wire.parent_pid);
        event.parent_tgid = static_cast<std::int64_t>(wire.parent_tgid);
    }
    if ((wire.availability & NETA_EXEC_HAS_UID) != 0U) event.uid = wire.uid;
    if ((wire.availability & NETA_EXEC_HAS_GID) != 0U) event.gid = wire.gid;
    if ((wire.availability & NETA_EXEC_HAS_START_TIME) != 0U) {
        event.process_start_time_ns = wire.process_start_time_ns;
    }
    if ((wire.availability & NETA_EXEC_HAS_EXIT_CODE) != 0U) event.exit_code = wire.exit_code;
    event.comm = std::string(wire.comm, strnlen(wire.comm, sizeof(wire.comm)));
    if ((wire.availability & NETA_EXEC_HAS_PATH) != 0U) {
        event.executable_path =
            std::string(wire.executable_path, strnlen(wire.executable_path, sizeof(wire.executable_path)));
    }
    return {std::move(event)};
}

}  // namespace neta::platform::linux_ebpf
