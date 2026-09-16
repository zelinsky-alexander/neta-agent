#pragma once

#include "neta/coordinator_ack.hpp"
#include "neta/outbound_message.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

struct sqlite3;

namespace neta {

struct OutboundQueueStatus {
    std::uint64_t pending{0};
    std::uint64_t in_flight{0};
    std::uint64_t acknowledged{0};
    std::uint64_t dead_letter{0};
    std::uint64_t logical_bytes{0};
    std::uint64_t dropped_low_priority{0};
    std::uint64_t coalesced{0};
    std::uint64_t oldest_pending_ns{0};
    std::uint64_t last_ack_ns{0};
};

class OutboundQueue {
public:
    OutboundQueue(std::filesystem::path database, std::string agent_id,
                  std::uint64_t max_bytes);
    ~OutboundQueue();

    OutboundQueue(const OutboundQueue&) = delete;
    OutboundQueue& operator=(const OutboundQueue&) = delete;

    std::string enqueue(const std::string& producer_key,
                        const std::string& message_type,
                        const std::string& finding_type,
                        const std::string& finding_key,
                        int priority,
                        const std::string& payload_json,
                        const std::string& payload_hash,
                        std::uint64_t now_ns);
    [[nodiscard]] std::optional<OutboundMessage> next_ready(std::uint64_t now_ns) const;
    void store_attempt(const OutboundMessage& message, std::uint64_t now_ns);
    void mark_retry(const std::string& event_id, std::uint64_t next_attempt_ns,
                    const std::string& error);
    void mark_dead_letter(const std::string& event_id, const std::string& error);
    void mark_acknowledged(const std::string& event_id, const CoordinatorAck& ack,
                           std::uint64_t now_ns);
    [[nodiscard]] bool is_acknowledged(const std::string& event_id) const;
    [[nodiscard]] OutboundQueueStatus status() const;
    void enqueue_gap_marker(std::uint64_t now_ns);
    void prune_acknowledged(std::uint64_t older_than_ns);

private:
    void initialize_schema();
    void enforce_budget(std::uint64_t required_bytes);
    void exec(const char* sql) const;

    std::filesystem::path database_;
    std::string agent_id_;
    std::uint64_t max_bytes_{0};
    sqlite3* db_{nullptr};
};

}  // namespace neta
