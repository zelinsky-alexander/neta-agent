#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace neta {

enum class ProcessExecEventType {
    Start,
    Exit,
};

struct ProcessExecEvent {
    ProcessExecEventType type{ProcessExecEventType::Start};
    std::uint64_t timestamp_ns{0};
    std::optional<std::int64_t> pid;
    std::optional<std::int64_t> tgid;
    std::optional<std::int64_t> parent_pid;
    std::optional<std::int64_t> parent_tgid;
    std::optional<std::uint32_t> uid;
    std::optional<std::uint32_t> gid;
    std::optional<std::uint64_t> process_start_time_ns;
    std::optional<std::uint64_t> platform_process_key;
    std::optional<std::uint32_t> session_id;
    std::string user_identity;
    std::string integrity_level;
    std::optional<bool> elevated;
    std::optional<std::int32_t> exit_code;
    std::string comm;
    std::string executable_path;
    std::string command_line;
    std::string working_directory;
};

struct ProcessExecCapability {
    bool built_in{false};
    bool btf_core_runtime{false};
    bool exec_events{false};
    bool exit_events{false};
    bool parent_identity{false};
    bool command_line{false};
    bool working_directory{false};
    bool security_identity{false};
    bool session_identity{false};
    bool drop_counter{false};
    std::string source;
    std::string unavailable_reason;

    [[nodiscard]] bool available() const noexcept { return exec_events; }
};

struct ProcessExecHealth {
    std::optional<std::uint64_t> dropped_events;
};

class ProcessExecObserver {
public:
    virtual ~ProcessExecObserver() = default;
    [[nodiscard]] virtual const ProcessExecCapability& capability() const noexcept = 0;
    [[nodiscard]] virtual ProcessExecHealth health() const = 0;
    virtual std::vector<ProcessExecEvent> poll(std::chrono::milliseconds timeout) = 0;
};

}  // namespace neta
