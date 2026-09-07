#pragma once

#include "neta/behavior_detection.hpp"
#include "neta/fleet_client.hpp"
#include "neta/fleet_reporting.hpp"
#include "neta/history_store.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

namespace neta {

struct BehaviorReportingResult {
    std::size_t considered{0};
    std::size_t detected{0};
    std::size_t persisted{0};
    std::size_t announced{0};
    std::size_t suppressed_policy{0};
    std::size_t suppressed_cooldown{0};
    std::size_t failed{0};
};

namespace behavior_reporting_detail {

inline std::filesystem::path append_suffix(std::filesystem::path path, const char* suffix) {
    path += suffix;
    return path;
}

inline std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c) << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

inline std::unordered_map<std::string, std::int64_t> load_cooldowns(
    const std::filesystem::path& path) {
    std::unordered_map<std::string, std::int64_t> result;
    std::ifstream input(path);
    std::string key;
    std::int64_t epoch = 0;
    while (input >> key >> epoch) result[key] = epoch;
    return result;
}

inline void save_cooldowns(const std::filesystem::path& path,
                           const std::unordered_map<std::string, std::int64_t>& cooldowns) {
    const auto temp = append_suffix(path, ".tmp");
    std::ofstream output(temp, std::ios::trunc);
    if (!output) throw std::runtime_error("cannot write periodic behavior cooldown state");
    for (const auto& [key, epoch] : cooldowns) output << key << ' ' << epoch << '\n';
    output.close();
    if (!output) throw std::runtime_error("cannot flush periodic behavior cooldown state");
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::rename(temp, path);
}

inline std::string connection_ids_text(const PeriodicOutboundFinding& finding) {
    std::ostringstream out;
    for (std::size_t index = 0; index < finding.connection_ids.size(); ++index) {
        if (index) out << ',';
        out << finding.connection_ids[index];
    }
    return out.str();
}

inline void rotate_if_needed(const std::filesystem::path& path) {
    constexpr std::uintmax_t max_log_bytes = 1024U * 1024U;
    std::error_code error;
    if (!std::filesystem::exists(path, error) || error) return;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size < max_log_bytes) return;
    const auto previous = append_suffix(path, ".1");
    std::filesystem::remove(previous, error);
    error.clear();
    std::filesystem::rename(path, previous, error);
    if (error) throw std::runtime_error("cannot rotate periodic behavior finding log");
}

inline void persist_finding(const std::filesystem::path& path,
                            const PeriodicOutboundFinding& finding,
                            std::int64_t created_epoch) {
    rotate_if_needed(path);
    std::ofstream output(path, std::ios::app);
    if (!output) throw std::runtime_error("cannot persist periodic behavior finding");
    output << '{'
           << "\"finding_id\":\"" << json_escape(finding.finding_id) << "\","
           << "\"finding_key\":\"" << json_escape(finding.finding_key) << "\","
           << "\"type\":\"" << finding.type << "\","
           << "\"severity\":\"" << finding.severity << "\","
           << "\"confidence\":" << finding.confidence << ','
           << "\"malicious_intent\":\"" << finding.malicious_intent << "\","
           << "\"process\":\"" << json_escape(finding.process_name) << "\","
           << "\"process_identity\":\"" << json_escape(finding.process_identity) << "\","
           << "\"host\":\"" << json_escape(finding.host) << "\","
           << "\"port\":" << finding.port << ','
           << "\"connection_count\":" << finding.connection_ids.size() << ','
           << "\"median_interval_ms\":" << (finding.median_interval_ns / 1'000'000ULL) << ','
           << "\"regular_interval_fraction\":" << finding.regular_interval_fraction << ','
           << "\"connections\":\"" << connection_ids_text(finding) << "\","
           << "\"evidence_root\":\"" << finding.evidence_root << "\","
           << "\"interpretation\":\"" << json_escape(finding.interpretation) << "\","
           << "\"created_epoch\":" << created_epoch
           << "}\n";
    if (!output) throw std::runtime_error("cannot flush periodic behavior finding");
}

inline FindingAnnouncementInput announcement_from_finding(
    const PeriodicOutboundFinding& finding) {
    FindingAnnouncementInput announcement;
    announcement.finding_id = finding.finding_id;
    announcement.finding_key = finding.finding_key;
    announcement.host = finding.host;
    announcement.port = finding.port;
    announcement.transport = "tcp";
    announcement.performance_verdict = "INSUFFICIENT_EVIDENCE";
    announcement.trust_verdict = "UNVERIFIED";
    announcement.evidence_root = finding.evidence_root;
    announcement.changes.emplace_back("Finding type: " + finding.type);
    announcement.changes.emplace_back("Severity: " + finding.severity);
    announcement.changes.emplace_back(
        "Confidence: " + std::to_string(finding.confidence));
    announcement.changes.emplace_back("Malicious intent: " + finding.malicious_intent);
    announcement.changes.emplace_back("Process: " + finding.process_name);
    announcement.changes.emplace_back(
        "Observed connections: " + std::to_string(finding.connection_ids.size()));
    announcement.changes.emplace_back(
        "Median interval ms: " + std::to_string(finding.median_interval_ns / 1'000'000ULL));
    announcement.changes.emplace_back(
        "Regular interval fraction: " + std::to_string(finding.regular_interval_fraction));
    announcement.changes.emplace_back("Evidence connections: " + connection_ids_text(finding));
    announcement.changes.emplace_back(finding.interpretation);
    return announcement;
}

} // namespace behavior_reporting_detail

inline BehaviorReportingResult auto_report_periodic_behavior(
    HistoryStore& store,
    std::int64_t trigger_connection_id,
    const FleetReportingPolicy& reporting_policy,
    const PeriodicOutboundPolicy& detector_policy = {}) {
    BehaviorReportingResult result;
    ++result.considered;
    try {
        const auto recent = store.recent_connections(detector_policy.recent_connection_limit);
        const auto finding = detect_periodic_outbound(recent, trigger_connection_id, detector_policy);
        if (!finding) return result;
        ++result.detected;

        const auto now = std::chrono::system_clock::now();
        const auto now_epoch = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
        const auto state_path = behavior_reporting_detail::append_suffix(
            store.path(), ".periodic.state");
        auto cooldowns = behavior_reporting_detail::load_cooldowns(state_path);
        const auto previous = cooldowns.find(finding->finding_key);
        if (previous != cooldowns.end() &&
            now_epoch - previous->second < reporting_policy.cooldown.count()) {
            ++result.suppressed_cooldown;
            return result;
        }

        behavior_reporting_detail::persist_finding(
            behavior_reporting_detail::append_suffix(store.path(), ".findings.jsonl"),
            *finding, now_epoch);
        ++result.persisted;
        cooldowns[finding->finding_key] = now_epoch;
        behavior_reporting_detail::save_cooldowns(state_path, cooldowns);

        if (reporting_policy.mode == FleetReportingMode::Off ||
            finding->confidence < reporting_policy.minimum_confidence) {
            ++result.suppressed_policy;
            return result;
        }
        if (!std::filesystem::exists(reporting_policy.state_dir / "identity.conf")) {
            ++result.suppressed_policy;
            return result;
        }

        FleetClient::send_finding(
            reporting_policy.state_dir,
            behavior_reporting_detail::announcement_from_finding(*finding));
        ++result.announced;
    } catch (const std::exception& error) {
        ++result.failed;
        std::cerr << "Periodic outbound behavior reporting failed for CONN-"
                  << trigger_connection_id << ": " << error.what() << '\n';
    }
    return result;
}

} // namespace neta
