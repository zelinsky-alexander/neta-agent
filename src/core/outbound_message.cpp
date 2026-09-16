#include "neta/outbound_message.hpp"

#include <stdexcept>

namespace neta {

std::string to_string(OutboundState state) {
    switch (state) {
        case OutboundState::Pending: return "PENDING";
        case OutboundState::InFlight: return "IN_FLIGHT";
        case OutboundState::Acknowledged: return "ACKED";
        case OutboundState::DeadLetter: return "DEAD_LETTER";
    }
    throw std::runtime_error("unknown outbound state");
}

}  // namespace neta
