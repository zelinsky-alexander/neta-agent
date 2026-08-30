#pragma once

#include "neta/model.hpp"

#include <cstdint>
#include <chrono>
#include <string>

namespace neta {

class TlsProbe {
public:
    TlsObservation probe(const std::string& host, std::uint16_t port,
                         const std::string& ca_file = {},
                         std::chrono::milliseconds post_handshake_hold = {}) const;
};

} // namespace neta
