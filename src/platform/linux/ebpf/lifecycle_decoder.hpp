#pragma once

#include "neta/lifecycle.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>

namespace neta::platform::linux_ebpf {

struct DecodeResult {
    std::optional<ConnectionLifecycleEvent> event;
    std::string error;
};

DecodeResult decode_lifecycle_event(std::span<const std::byte> bytes);

} // namespace neta::platform::linux_ebpf
