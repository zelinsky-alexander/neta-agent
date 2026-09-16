#pragma once

#include <cstdint>
#include <string>

namespace neta {

enum class OutboundState { Pending, InFlight, Acknowledged, DeadLetter };

struct OutboundMessage {
    std::string event_id;
    std::uint64_t event_counter{0};
    std::string producer_key;
    std::string message_type;
    std::string finding_type;
    std::string finding_key;
    int priority{0};
    std::string payload_json;
    std::string payload_hash;
    OutboundState state{OutboundState::Pending};
    std::string attempt_message_id;
    std::uint64_t attempt_sequence{0};
    std::string attempt_envelope_json;
    std::uint64_t attempt_expires_at_ns{0};
    std::uint64_t attempt_count{0};
};

[[nodiscard]] std::string to_string(OutboundState state);

}  // namespace neta
