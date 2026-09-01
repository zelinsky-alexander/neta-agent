#include "neta/fleet_reporting.hpp"

#include "neta/crypto.hpp"
#include "neta/tls_session.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace neta {
namespace {

std::string with_sha256_prefix(const std::string& hash) {
    if (hash.empty()) return {};
    return hash.starts_with("sha256:") ? hash : "sha256:" + hash;
}

std::string normalized_address(std::string address) {
    constexpr const char* mapped_v4 = "::ffff:";
    if (address.starts_with(mapped_v4)) address.erase(0, std::char_traits<char>::length(mapped_v4));
    return address;
}

std::string env_value(const char* name, const std::string& fallback) {
    const char* value = std::getenv(name);
    return value == nullptr || *value == '\0' ? fallback : std::string(value);
}

std::string uppercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return value;
}

std::unordered_map<std::string, std::int64_t> load_cooldowns(const std::filesystem::path& path) {
    std::unordered_map<std::string, std::int64_t> result;
    std::ifstream in(path);
    std::string key;
    std::int64_t epoch = 0;
    while (in >> key >> epoch) result[key] = epoch;
    return result;
}

void save_cooldowns(const std::filesystem::path& path,
                    const std::unordered_map<std::string, std::int64_t>& values) {
    const auto temp = path.string() + ".tmp";
    std::ofstream out(temp, std::ios::trunc);
    if (!out) throw std::runtime_error("cannot write fleet reporting cooldown state");
    for (const auto& [key, epoch] : values) out << key << ' ' << epoch << '\n';
    out.close();
    std::filesystem::rename(temp, path);
}

std::string stable_finding_key(const ExportData& data, const FindingAnnouncementInput& finding) {
    std::ostringstream canonical;
    canonical << "direction=" << to_string(data.connection.direction)
              << "|target=" << finding.host << ':' << finding.port
              << "|transport=" << finding.transport
              << "|performance=" << finding.performance_verdict
              << "|trust=" << finding.trust_verdict;
    if (data.verdict) {
        canonical << "|performance_hypothesis=" << data.verdict->performance_hypothesis
                  << "|trust_hypothesis=" << data.verdict->trust_hypothesis;
    }
    return "sha256:" + sha256_hex(canonical.str());
}

} // namespace

FleetReportingPolicy fleet_reporting_policy_from_environment() {
    FleetReportingPolicy policy;
    const auto mode = uppercase(env_value("NETA_FLEET_REPORTING_MODE", "SIGNIFICANT_ONLY"));
    if (mode == "OFF") policy.mode = FleetReportingMode::Off;
    else if (mode == "ALL" || mode == "ALL_FINDINGS") policy.mode = FleetReportingMode::AllFindings;
    else if (mode == "SIGNIFICANT" || mode == "SIGNIFICANT_ONLY") policy.mode = FleetReportingMode::SignificantOnly;
    else throw std::runtime_error("invalid NETA_FLEET_REPORTING_MODE");

    policy.minimum_confidence = std::stod(env_value("NETA_FLEET_MIN_CONFIDENCE", "0.80"));
    if (policy.minimum_confidence < 0.0 || policy.minimum_confidence > 1.0)
        throw std::runtime_error("NETA_FLEET_MIN_CONFIDENCE must be between 0 and 1");
    policy.cooldown = std::chrono::seconds(
        std::stoll(env_value("NETA_FLEET_REPORTING_COOLDOWN_SECONDS", "1800")));
    if (policy.cooldown.count() < 0)
        throw std::runtime_error("NETA_FLEET_REPORTING_COOLDOWN_SECONDS must not be negative");
    policy.state_dir = env_value("NETA_FLEET_STATE_DIR", "/var/lib/neta/identity");
    return policy;
}

FindingAnnouncementInput finding_from_connection(HistoryStore& store, std::int64_t connection_id) {
    const ExportData data = store.export_data(connection_id);
    if (!data.verdict) throw std::runtime_error("connection has no finalized assurance verdict");

    FindingAnnouncementInput finding;
    const bool inbound = data.connection.direction == ConnectionDirection::Inbound;
    finding.host = inbound ? normalized_address(data.connection.local_ip)
                           : (!data.connection.target_host.empty()
                                  ? data.connection.target_host
                                  : normalized_address(data.connection.remote_ip));
    finding.port = inbound ? data.connection.local_port : data.connection.remote_port;
    finding.transport = "tcp";
    finding.performance_verdict = to_string(data.verdict->performance);
    finding.trust_verdict = to_string(data.verdict->trust);

    const auto tls_evidence = store.tls_session_evidence_for_connection(connection_id);
    const TlsSessionEvidence* preferred_tls = nullptr;
    for (const auto& evidence : tls_evidence) {
        if (evidence.correlation_fidelity != EvidenceFidelity::Exact) continue;
        if (inbound && evidence.relation == TlsSessionRelation::InboundClientIdentity) {
            preferred_tls = &evidence;
            break;
        }
        if (!inbound && evidence.relation == TlsSessionRelation::OutboundServerIdentity) {
            preferred_tls = &evidence;
            break;
        }
        if (preferred_tls == nullptr) preferred_tls = &evidence;
    }

    if (preferred_tls != nullptr) {
        finding.evidence_root = with_sha256_prefix(tls_session_evidence_hash(*preferred_tls));
    } else if (!data.verdict->input_hash.empty()) {
        finding.evidence_root = with_sha256_prefix(data.verdict->input_hash);
    } else {
        throw std::runtime_error("connection has no stable evidence hash to announce");
    }

    finding.finding_key = stable_finding_key(data, finding);
    std::string root_suffix = finding.evidence_root;
    if (root_suffix.starts_with("sha256:")) root_suffix.erase(0, 7);
    if (root_suffix.size() > 12) root_suffix.resize(12);
    finding.finding_id = "FINDING-CONN-" + std::to_string(connection_id) + "-" + root_suffix;

    finding.changes.emplace_back("Stored connection assurance observation");
    finding.changes.emplace_back("Performance verdict: " + finding.performance_verdict);
    finding.changes.emplace_back("Trust verdict: " + finding.trust_verdict);
    if (!data.verdict->performance_hypothesis.empty())
        finding.changes.emplace_back("Performance hypothesis: " + data.verdict->performance_hypothesis);
    if (!data.verdict->trust_hypothesis.empty())
        finding.changes.emplace_back("Trust hypothesis: " + data.verdict->trust_hypothesis);

    if (preferred_tls != nullptr && inbound &&
        preferred_tls->relation == TlsSessionRelation::InboundClientIdentity &&
        preferred_tls->observation.peer_authenticated) {
        finding.changes.emplace_back("Authenticated inbound TLS client identity observed");
        if (data.baseline && !data.baseline->accepted_spki_sha256.empty() &&
            data.baseline->accepted_spki_sha256 == preferred_tls->observation.spki_sha256) {
            finding.changes.emplace_back("Client SPKI matches accepted inbound baseline");
        }
    }

    if (finding.host.empty() || finding.port == 0)
        throw std::runtime_error("connection does not contain a usable service endpoint");
    return finding;
}

bool finding_matches_reporting_policy(const ExportData& data, const FleetReportingPolicy& policy) {
    if (policy.mode == FleetReportingMode::Off || !data.verdict) return false;
    if (policy.mode == FleetReportingMode::AllFindings) return true;

    const bool trust_issue = data.verdict->trust == TrustState::Changed ||
                             data.verdict->trust == TrustState::Suspicious;
    const bool performance_issue = data.verdict->performance == PerformanceState::Degraded ||
                                   data.verdict->performance == PerformanceState::Failed;
    const bool confident_performance = performance_issue &&
                                       data.verdict->rule_confidence >= policy.minimum_confidence;
    return trust_issue || confident_performance;
}

FleetReportingResult auto_report_connections(HistoryStore& store,
                                             const std::vector<std::int64_t>& connection_ids,
                                             const FleetReportingPolicy& policy) {
    FleetReportingResult result;
    if (policy.mode == FleetReportingMode::Off) return result;
    if (!std::filesystem::exists(policy.state_dir / "identity.conf")) return result;

    const auto state_path = policy.state_dir / "reporting.state";
    auto cooldowns = load_cooldowns(state_path);
    const auto now = std::chrono::system_clock::now();
    const auto now_epoch = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());

    bool state_changed = false;
    for (const auto connection_id : connection_ids) {
        try {
            const auto data = store.export_data(connection_id);
            if (!data.verdict) continue;
            ++result.considered;
            if (!finding_matches_reporting_policy(data, policy)) {
                ++result.suppressed_policy;
                continue;
            }

            const auto finding = finding_from_connection(store, connection_id);
            const auto previous = cooldowns.find(finding.finding_key);
            if (previous != cooldowns.end() &&
                now_epoch - previous->second < policy.cooldown.count()) {
                ++result.suppressed_cooldown;
                continue;
            }

            FleetClient::send_finding(policy.state_dir, finding);
            cooldowns[finding.finding_key] = now_epoch;
            state_changed = true;
            ++result.announced;
        } catch (const std::exception& error) {
            ++result.failed;
            std::cerr << "Fleet auto-report failed for CONN-" << connection_id << ": "
                      << error.what() << '\n';
        }
    }

    if (state_changed) save_cooldowns(state_path, cooldowns);
    return result;
}

} // namespace neta
