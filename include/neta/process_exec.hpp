#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace neta {

struct ProcessExecEvent {
    std::uint64_t timestamp_ns{0};
    std::optional<std::int64_t> pid;
    std::optional<std::int64_t> tgid;
    std::optional<std::uint32_t> uid;
    std::optional<std::uint64_t> process_start_time_ns;
    std::string comm;
    std::string executable_path;
};

struct ProcessExecCapability {
    bool built_in{false};
    bool btf_core_runtime{false};
    bool exec_events{false};
    bool drop_counter{false};
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
