#include "neta/coordinator_ack.hpp"

#include <cctype>
#include <stdexcept>
#include <string_view>

namespace neta {
namespace {

std::size_t value_start(const std::string& json, std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\"";
    auto position = json.find(needle);
    if (position == std::string::npos) throw std::runtime_error("coordinator ACK lacks " + std::string(key));
    position = json.find(':', position + needle.size());
    if (position == std::string::npos) throw std::runtime_error("coordinator ACK is malformed");
    ++position;
    while (position < json.size() && std::isspace(static_cast<unsigned char>(json[position]))) ++position;
    return position;
}

std::string string_value(const std::string& json, std::string_view key) {
    auto position = value_start(json, key);
    if (position >= json.size() || json[position++] != '"')
        throw std::runtime_error("coordinator ACK field is not a string: " + std::string(key));
    std::string value;
    while (position < json.size()) {
        const char character = json[position++];
        if (character == '"') return value;
        if (character != '\\') {
            value.push_back(character);
            continue;
        }
        if (position >= json.size()) break;
        const char escaped = json[position++];
        if (escaped == '"' || escaped == '\\' || escaped == '/') value.push_back(escaped);
        else throw std::runtime_error("coordinator ACK contains an unsupported escape");
    }
    throw std::runtime_error("coordinator ACK contains an unterminated string");
}

std::uint64_t unsigned_value(const std::string& json, std::string_view key) {
    auto position = value_start(json, key);
    const auto first = position;
    while (position < json.size() && std::isdigit(static_cast<unsigned char>(json[position]))) ++position;
    if (position == first) throw std::runtime_error("coordinator ACK field is not unsigned: " + std::string(key));
    return std::stoull(json.substr(first, position - first));
}

}  // namespace

CoordinatorAck parse_coordinator_ack(const std::string& response_json) {
    CoordinatorAck ack;
    ack.protocol = string_value(response_json, "protocol");
    ack.schema_version = static_cast<int>(unsigned_value(response_json, "schemaVersion"));
    ack.message_type = string_value(response_json, "messageType");
    ack.version = static_cast<int>(unsigned_value(response_json, "ackVersion"));
    ack.message_id = string_value(response_json, "messageId");
    ack.sequence = unsigned_value(response_json, "sequence");
    ack.idempotency_key = string_value(response_json, "idempotencyKey");
    ack.payload_hash = string_value(response_json, "payloadHash");
    ack.status = string_value(response_json, "status");
    ack.received_at = string_value(response_json, "receivedAt");
    return ack;
}

void validate_coordinator_ack(const CoordinatorAck& ack,
                              const std::string& expected_message_id,
                              std::uint64_t expected_sequence,
                              const std::string& expected_idempotency_key,
                              const std::string& expected_payload_hash) {
    if (ack.protocol != "neta-agent/1" || ack.schema_version != 1 || ack.message_type != "Ack")
        throw std::runtime_error("response is not a supported NAP ACK");
    if (ack.version != 1) throw std::runtime_error("unsupported coordinator ACK version");
    if (ack.message_id != expected_message_id) throw std::runtime_error("coordinator ACK message mismatch");
    if (ack.sequence != expected_sequence) throw std::runtime_error("coordinator ACK sequence mismatch");
    if (ack.idempotency_key != expected_idempotency_key)
        throw std::runtime_error("coordinator ACK idempotency mismatch");
    if (ack.payload_hash != expected_payload_hash)
        throw std::runtime_error("coordinator ACK payload hash mismatch");
    if (ack.status != "ACCEPTED" && ack.status != "ALREADY_ACCEPTED")
        throw std::runtime_error("coordinator did not acknowledge the NAP event");
    if (ack.received_at.empty()) throw std::runtime_error("coordinator ACK lacks commit time");
}

}  // namespace neta
