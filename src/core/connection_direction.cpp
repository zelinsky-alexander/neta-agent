#include "neta/connection_direction.hpp"

namespace neta {

std::string to_string(ConnectionDirection direction) {
    switch (direction) {
        case ConnectionDirection::Outbound: return "OUTBOUND";
        case ConnectionDirection::Inbound: return "INBOUND";
        case ConnectionDirection::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

ConnectionDirection connection_direction_from_string(const std::string& value) {
    if (value == "OUTBOUND") return ConnectionDirection::Outbound;
    if (value == "INBOUND") return ConnectionDirection::Inbound;
    return ConnectionDirection::Unknown;
}

} // namespace neta
