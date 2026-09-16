#pragma once

#include <cstdint>
#include <string>

namespace neta {

struct CoordinatorAck {
    std::string protocol;
    int schema_version{0};
    std::string message_type;
    int version{0};
    std::string message_id;
    std::uint64_t sequence{0};
    std::string idempotency_key;
    std::string payload_hash;
    std::string status;
    std::string received_at;
};

[[nodiscard]] CoordinatorAck parse_coordinator_ack(const std::string& response_json);
void validate_coordinator_ack(const CoordinatorAck& ack,
                              const std::string& expected_message_id,
                              std::uint64_t expected_sequence,
                              const std::string& expected_idempotency_key,
                              const std::string& expected_payload_hash);

}  // namespace neta
