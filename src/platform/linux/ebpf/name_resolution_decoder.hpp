#pragma once

#include "neta/name_resolution.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>

namespace neta::platform::linux_ebpf {

struct NameResolutionDecodeResult {
    std::optional<NameResolutionObservation> observation;
    std::string error;
};

NameResolutionDecodeResult decode_name_resolution_event(std::span<const std::byte> bytes);

} // namespace neta::platform::linux_ebpf
