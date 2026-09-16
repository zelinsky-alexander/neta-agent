#include "neta/coordinator_ack.hpp"
#include "neta/outbound_queue.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <string>

namespace {

std::filesystem::path test_database() {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
        ("neta-outbound-queue-test-" + std::to_string(nonce) + ".sqlite");
}

void remove_database(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove(path, error);
    std::filesystem::remove(path.string() + "-wal", error);
    std::filesystem::remove(path.string() + "-shm", error);
}

void capacity_gap_and_dead_letter() {
    const auto path = test_database();
    remove_database(path);
    {
        neta::OutboundQueue queue(path, "AGENT-1", 1700);
        static_cast<void>(queue.enqueue(
            "low", "FindingAnnouncement", "LOW", "low", 1,
            std::string(700, 'x'), "sha256:low", 100));
        const auto important = queue.enqueue(
            "high", "FindingAnnouncement", "HIGH", "high", 3,
            std::string(100, 'y'), "sha256:high", 101);
        assert(queue.status().dropped_low_priority == 1);

        queue.enqueue_gap_marker(102);
        const auto gap = queue.next_ready(102);
        assert(gap);
        assert(gap->finding_type == "TELEMETRY_GAP");
        const neta::CoordinatorAck ack{
            "neta-agent/1", 1, "Ack", 1, "MSG-GAP", 8, gap->event_id,
            gap->payload_hash, "ACCEPTED", "2026-09-15T18:00:00Z"};
        queue.mark_acknowledged(gap->event_id, ack, 103);
        queue.enqueue_gap_marker(104);
        assert(queue.status().acknowledged == 1);

        queue.mark_dead_letter(important, "HTTP 413");
        assert(queue.status().dead_letter == 1);
    }
    remove_database(path);
}

void ack_contract_validation() {
    const std::string body = R"JSON({
        "protocol":"neta-agent/1",
        "schemaVersion":1,
        "messageType":"Ack",
        "ackVersion":1,
        "messageId":"MSG-1",
        "sequence":7,
        "idempotencyKey":"AGENT-1:1",
        "payloadHash":"sha256:abc",
        "status":"ALREADY_ACCEPTED",
        "receivedAt":"2026-09-15T18:00:00Z"
    })JSON";
    const auto ack = neta::parse_coordinator_ack(body);
    neta::validate_coordinator_ack(
        ack, "MSG-1", 7, "AGENT-1:1", "sha256:abc");

    bool rejected = false;
    try {
        neta::validate_coordinator_ack(
            ack, "MSG-2", 7, "AGENT-1:1", "sha256:abc");
    } catch (...) {
        rejected = true;
    }
    assert(rejected);
}

void durable_state_transitions() {
    const auto path = test_database();
    remove_database(path);
    {
        neta::OutboundQueue queue(path, "AGENT-1", 1024 * 1024);
        const auto event_id = queue.enqueue(
            "producer-1", "FindingAnnouncement", "TEST-001", "finding-key", 3,
            "{\"finding_id\":\"FIND-1\"}", "sha256:abc", 100);
        assert(event_id == "AGENT-1:1");
        assert(queue.enqueue("producer-1", "FindingAnnouncement", "TEST-001",
                             "finding-key", 3, "{}", "sha256:different", 101) == event_id);

        auto message = queue.next_ready(100);
        assert(message);
        message->attempt_message_id = "MSG-1";
        message->attempt_sequence = 7;
        message->attempt_envelope_json = "{}";
        message->attempt_expires_at_ns = 1000;
        queue.store_attempt(*message, 100);
        queue.mark_retry(event_id, 200, "connection lost after write");
        assert(!queue.next_ready(199));
        assert(queue.next_ready(200));

        const neta::CoordinatorAck ack{
            "neta-agent/1", 1, "Ack", 1, "MSG-1", 7, event_id,
            "sha256:abc", "ALREADY_ACCEPTED",
            "2026-09-15T18:00:00Z"};
        queue.mark_acknowledged(event_id, ack, 300);
        assert(queue.is_acknowledged(event_id));
        const auto status = queue.status();
        assert(status.acknowledged == 1);
        assert(status.coalesced == 1);
        assert(status.last_ack_ns == 300);
    }
    {
        neta::OutboundQueue reopened(path, "AGENT-1", 1024 * 1024);
        assert(reopened.is_acknowledged("AGENT-1:1"));
    }
    remove_database(path);
}

}  // namespace

int main() {
    ack_contract_validation();
    durable_state_transitions();
    capacity_gap_and_dead_letter();
}
