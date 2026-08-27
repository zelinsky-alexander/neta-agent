#pragma once

#include "neta/model.hpp"

#include <cstdint>
#include <string>

namespace neta {

class TlsProbe {
public:
    TlsObservation probe(const std::string& host, std::uint16_t port,
                         const std::string& ca_file = {}) const;
};

} // namespace neta
