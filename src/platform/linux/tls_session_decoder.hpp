#pragma once

#include "neta/tls_session.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace neta::platform::linux_tls {

struct DecodeResult {
    std::optional<TlsSessionObservation> observation;
    std::string error;
};

DecodeResult decode_tls_session_event(std::span<const std::byte> bytes,
                                      std::optional<std::int64_t> credential_pid,
                                      std::optional<std::uint32_t> credential_uid);

} // namespace neta::platform::linux_tls
