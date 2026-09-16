#include "neta/reliable_fleet_client.hpp"

#include "neta/crypto.hpp"
#include "neta/rule_update.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace neta {
namespace {

std::uint64_t now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::uint64_t outbox_max_bytes() {
    constexpr std::uint64_t default_bytes = 32ULL * 1024ULL * 1024ULL;
    const char* value = std::getenv("NETA_OUTBOX_MAX_MB");
    if (value == nullptr || *value == '\0') return default_bytes;
    const auto megabytes = std::stoull(value);
    if (megabytes == 0 || megabytes > 4096)
        throw std::runtime_error("NETA_OUTBOX_MAX_MB must be between 1 and 4096");
    return megabytes * 1024ULL * 1024ULL;
}

std::string json_escape(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
        switch (character) {
            case '\\': output << "\\\\"; break;
            case '"': output << "\\\""; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20U)
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<int>(character) << std::dec;
                else output << static_cast<char>(character);
        }
    }
    return output.str();
}

std::string finding_payload(const std::filesystem::path& state_dir,
                            const FindingAnnouncementInput& finding) {
    if (finding.finding_id.empty()) throw std::runtime_error("finding_id is required");
    const bool has_subject = !finding.subject_type.empty() && !finding.subject_id.empty();
    if (!has_subject && (finding.host.empty() || finding.port == 0))
        throw std::runtime_error("finding target or subject is required");
    if (finding.evidence_root.empty()) throw std::runtime_error("evidence_root is required");

    const auto rule_state = active_rule_bundle_state(state_dir);
    const std::string rule_set_id = finding.rule_set_id.empty()
        ? (rule_state.centrally_managed ? "neta-production" : "neta-default")
        : finding.rule_set_id;
    const std::string rule_set_version = finding.rule_set_version.empty()
        ? rule_state.version : finding.rule_set_version;
    const std::string rule_hash = rule_state.sha256.starts_with("sha256:")
        ? rule_state.sha256 : "sha256:" + rule_state.sha256;

    std::ostringstream changes;
    changes << '[';
    for (std::size_t index = 0; index < finding.changes.size(); ++index) {
        if (index != 0) changes << ',';
        changes << '"' << json_escape(finding.changes[index]) << '"';
    }
    changes << ']';

    std::ostringstream payload;
    payload << "{\"finding_id\":\"" << json_escape(finding.finding_id) << "\"";
    if (!finding.finding_key.empty())
        payload << ",\"finding_key\":\"" << json_escape(finding.finding_key) << "\"";
    if (!finding.severity.empty())
        payload << ",\"severity\":\"" << json_escape(finding.severity) << "\"";
    if (!finding.rule_id.empty())
        payload << ",\"rule_id\":\"" << json_escape(finding.rule_id) << "\"";
    if (!finding.interpretation.empty())
        payload << ",\"interpretation\":\"" << json_escape(finding.interpretation) << "\"";
    if (has_subject) {
        payload << ",\"subject\":{\"type\":\"" << json_escape(finding.subject_type)
                << "\",\"id\":\"" << json_escape(finding.subject_id) << "\"";
        if (finding.subject_pid) payload << ",\"pid\":" << *finding.subject_pid;
        if (finding.subject_parent_pid) payload << ",\"parent_pid\":" << *finding.subject_parent_pid;
        if (!finding.subject_image.empty()) payload << ",\"image\":\"" << json_escape(finding.subject_image) << "\"";
        if (!finding.subject_parent_image.empty())
            payload << ",\"parent_image\":\""
                    << json_escape(finding.subject_parent_image) << "\"";
        if (!finding.subject_command_line.empty())
            payload << ",\"command_line\":\""
                    << json_escape(finding.subject_command_line) << "\"";
        payload << '}';
    } else {
        payload << ",\"target\":{\"host\":\"" << json_escape(finding.host)
                << "\",\"port\":" << finding.port
                << ",\"transport\":\"" << json_escape(finding.transport) << "\"}";
    }
    payload << ",\"changes\":" << changes.str()
            << ",\"performance_verdict\":\"" << json_escape(finding.performance_verdict) << "\""
            << ",\"trust_verdict\":\"" << json_escape(finding.trust_verdict) << "\""
            << ",\"rule_set\":{\"id\":\"" << json_escape(rule_set_id)
            << "\",\"version\":\"" << json_escape(rule_set_version)
            << "\",\"revision\":" << rule_state.revision
            << ",\"hash\":\"" << json_escape(rule_hash) << "\"}"
            << ",\"evidence_root\":\"" << json_escape(finding.evidence_root) << "\"}";
    return payload.str();
}

int finding_priority(std::string severity) {
    std::transform(severity.begin(), severity.end(), severity.begin(),
                   [](unsigned char value) { return static_cast<char>(std::toupper(value)); });
    if (severity == "CRITICAL") return 4;
    if (severity == "HIGH") return 3;
    if (severity == "MEDIUM") return 2;
    return 1;
}

OutboundQueue make_queue(const std::filesystem::path& database,
                         const std::filesystem::path& state_dir) {
    const auto identity = FleetClient::load_identity(state_dir);
    return OutboundQueue(database, identity.agent_id, outbox_max_bytes());
}

}  // namespace

bool ReliableFleetClient::submit_finding(const std::filesystem::path& database,
                                         const std::filesystem::path& state_dir,
                                         const FindingAnnouncementInput& finding) {
    auto queue = make_queue(database, state_dir);
    const auto payload = finding_payload(state_dir, finding);
    const auto payload_hash = "sha256:" + sha256_hex(payload);
    const auto producer_key = "FindingAnnouncement:" + finding.finding_id + ':' + finding.evidence_root;
    const auto event_id = queue.enqueue(producer_key, "FindingAnnouncement", finding.rule_id,
                                        finding.finding_key, finding_priority(finding.severity),
                                        payload, payload_hash, now_ns());
    OutboundDispatcher dispatcher(queue, state_dir);
    static_cast<void>(dispatcher.drain(32));
    return queue.is_acknowledged(event_id);
}

bool ReliableFleetClient::submit_evidence_summary(const std::filesystem::path& database,
                                                  const std::filesystem::path& state_dir,
                                                  const std::string& producer_key,
                                                  const std::string& summary_json) {
    if (summary_json.empty()) throw std::runtime_error("evidence summary JSON is required");
    auto queue = make_queue(database, state_dir);
    const auto payload_hash = "sha256:" + sha256_hex(summary_json);
    const auto event_id = queue.enqueue("EvidenceSummary:" + producer_key, "EvidenceSummary",
                                        "EVIDENCE_SUMMARY", "", 2, summary_json,
                                        payload_hash, now_ns());
    OutboundDispatcher dispatcher(queue, state_dir);
    static_cast<void>(dispatcher.drain(32));
    return queue.is_acknowledged(event_id);
}

OutboundDispatchResult ReliableFleetClient::drain(const std::filesystem::path& database,
                                                  const std::filesystem::path& state_dir,
                                                  std::size_t maximum_messages) {
    auto queue = make_queue(database, state_dir);
    OutboundDispatcher dispatcher(queue, state_dir);
    return dispatcher.drain(maximum_messages);
}

OutboundQueueStatus ReliableFleetClient::status(const std::filesystem::path& database,
                                                const std::filesystem::path& state_dir) {
    auto queue = make_queue(database, state_dir);
    return queue.status();
}

}  // namespace neta
