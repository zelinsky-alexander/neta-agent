#pragma once

#include "neta/process_exec.hpp"

#include <cstddef>
#include <optional>
#include <span>

namespace neta::platform::linux_ebpf {

struct ProcessExecDecodeResult {
    std::optional<ProcessExecEvent> event;
};

ProcessExecDecodeResult decode_process_exec_event(std::span<const std::byte> bytes);

}  // namespace neta::platform::linux_ebpf
