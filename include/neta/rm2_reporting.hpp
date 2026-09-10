#pragma once

#include "neta/behavior_reporting.hpp"
#include "neta/context_rule_engine.hpp"
#include "neta/crypto.hpp"
#include "neta/fleet_reporting.hpp"
#include "neta/rules/rule_set_loader.hpp"
#include "neta/transfer_assurance.hpp"
#include "neta/verdict.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace neta {
namespace rm2_reporting_detail {

inline std::string upper(std::string value) {
    for (auto& ch : value) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    return value;
}
inline std::string target_host(const ConnectionSummary& connection) {
    return !connection.target_host.empty() ? connection.target_host : connection.remote_ip;
}
inline std::filesystem::path state_path(const HistoryStore& store) {
    auto path = store.path(); path += ".rm2-rules.state"; return path;
}
inline std::unordered_map<std::string, std::int64_t> load_cooldowns(const std::filesystem::path& path) {
    std::unordered_map<std::string, std::int64_t> result;
    std::ifstream input(path); std::string key; std::int64_t epoch = 0;
    while (input >> key >> epoch) result[key] = epoch;
    return result;
}
inline void save_cooldowns(const std::filesystem::path& path,
                           const std::unordered_map<std::string, std::int64_t>& values) {
    const auto temporary = path.string() + ".tmp";
    std::ofstream output(temporary, std::ios::trunc);
    if (!output) throw std::runtime_error("cannot write RM2 rule cooldown state");
    for (const auto& [key, epoch] : values) output << key << ' ' << epoch << '\n';
    output.close();
    if (!output) throw std::runtime_error("cannot flush RM2 rule cooldown state");
    std::error_code ignored; std::filesystem::remove(path, ignored); std::filesystem::rename(temporary, path);
}
inline std::int64_t now_epoch() {
    return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
inline bool cooldown_allows(const std::string& key,
                            std::unordered_map<std::string, std::int64_t>& cooldowns,
                            std::int64_t now,
                            const FleetReportingPolicy& policy) {
    const auto previous = cooldowns.find(key);
    return previous == cooldowns.end() || now - previous->second >= policy.cooldown.count();
}
inline PeriodicOutboundPolicy periodic_policy(const rules::RuleDefinition& rule) {
    constexpr std::uint64_t ns_per_ms = 1'000'000ULL;
    PeriodicOutboundPolicy policy;
    policy.minimum_connections = static_cast<std::size_t>(rule.numeric("minimum_connections"));
    policy.window_ns = static_cast<std::uint64_t>(rule.numeric("window_ms")) * ns_per_ms;
    policy.minimum_interval_ns = static_cast<std::uint64_t>(rule.numeric("minimum_interval_ms")) * ns_per_ms;
    policy.maximum_interval_ns = static_cast<std::uint64_t>(rule.numeric("maximum_interval_ms")) * ns_per_ms;
    policy.interval_tolerance_ratio = rule.numeric("interval_tolerance_ratio");
    policy.minimum_regular_fraction = rule.numeric("minimum_regular_fraction");
    policy.recent_connection_limit = static_cast<std::size_t>(rule.numeric("recent_connection_limit"));
    return policy;
}
inline std::uint64_t prevalence(const HistoryStore& store, const ConnectionSummary& target) {
    const auto host = target_host(target); if (host.empty()) return 0;
    std::uint64_t count = 0;
    for (const auto& item : store.recent_connections(512))
        if (item.direction == ConnectionDirection::Outbound && target_host(item) == host) ++count;
    return count;
}
inline std::vector<std::string> domains_for_connection(const HistoryStore& store, std::int64_t id) {
    std::vector<std::string> domains;
    for (const auto& evidence : store.name_resolution_evidence_for_connection(id)) {
        if (!evidence.observation.query_name.empty()) domains.push_back(evidence.observation.query_name);
        if (evidence.observation.canonical_name && !evidence.observation.canonical_name->empty()) domains.push_back(*evidence.observation.canonical_name);
    }
    return domains;
}
inline bool excluded_for_connection(const HistoryStore& store,const rules::RuleDefinition& rule,std::int64_t id) {
    const auto connection = store.connection(id); if (!connection) return false;
    return rules::excludes_connection(rule.exclude, *connection, domains_for_connection(store, id));
}
inline std::string context_evidence_root(const ConnectionRuleContext& context) {
    std::ostringstream canonical;
    canonical << "connection=" << context.connection.id << "|direction=" << to_string(context.connection.direction)
              << "|remote=" << context.connection.remote_ip << ':' << context.connection.remote_port
              << "|host=" << context.connection.target_host << "|rtt=" << context.metrics.observed_rtt_us
              << "|rttvar=" << context.metrics.observed_rttvar_us << "|retrans=" << context.metrics.retransmission_delta;
    if (context.route) canonical << "|route=" << context.route->sha256;
    if (!context.tls_sessions.empty()) canonical << "|tls=" << tls_session_evidence_set_hash(context.tls_sessions);
    if (!context.name_resolution.empty()) canonical << "|dns=" << name_resolution_evidence_set_hash(context.name_resolution);
    if (context.bytes_sent) canonical << "|sent=" << *context.bytes_sent;
    if (context.bytes_received) canonical << "|received=" << *context.bytes_received;
    return "sha256:" + sha256_hex(canonical.str());
}
inline FindingAnnouncementInput context_announcement(const ContextRuleMatch& match,const ConnectionRuleContext& context,const RuleSet& rules) {
    FindingAnnouncementInput finding;
    finding.host = context.connection.direction == ConnectionDirection::Inbound ? context.connection.local_ip : target_host(context.connection);
    finding.port = context.connection.direction == ConnectionDirection::Inbound ? context.connection.local_port : context.connection.remote_port;
    finding.transport = "tcp"; finding.severity = upper(match.severity); finding.rule_id = match.rule_id;
    finding.rule_set_id = rules.id; finding.rule_set_version = rules.version; finding.interpretation = match.interpretation;
    finding.performance_verdict = "INSUFFICIENT_EVIDENCE"; finding.trust_verdict = "UNVERIFIED";
    finding.evidence_root = context_evidence_root(context);
    const std::string process = !context.connection.process.executable_path.empty() ? context.connection.process.executable_path : context.connection.process.comm;
    finding.finding_key = "sha256:" + sha256_hex(match.rule_id + "|" + process + "|" + finding.host + ":" + std::to_string(finding.port));
    auto suffix = finding.evidence_root.substr(7); if (suffix.size() > 12) suffix.resize(12);
    finding.finding_id = "FINDING-RULE-" + match.rule_id + "-" + suffix;
    finding.changes.emplace_back("Rule: " + match.rule_id); finding.changes.emplace_back("Trusted engine: " + match.engine_rule_id);
    finding.changes.emplace_back("Severity: " + finding.severity); finding.changes.emplace_back(match.summary);
    return finding;
}

} // namespace rm2_reporting_detail

inline BehaviorReportingResult auto_report_rule_periodic_behavior(HistoryStore& store, std::int64_t trigger_connection_id,
    const FleetReportingPolicy& reporting_policy, const RuleSet& rules = current_rule_set()) {
    BehaviorReportingResult result;
    auto cooldowns = rm2_reporting_detail::load_cooldowns(rm2_reporting_detail::state_path(store));
    const auto now = rm2_reporting_detail::now_epoch(); bool changed = false;
    for (const auto& rule : rules.definitions) {
        if (!rule.enabled || rule.engine_rule_id != "BEH-001") continue;
        if (rm2_reporting_detail::excluded_for_connection(store, rule, trigger_connection_id)) continue;
        ++result.considered;
        try {
            const auto policy = rm2_reporting_detail::periodic_policy(rule);
            auto finding = detect_periodic_outbound(store.recent_connections(policy.recent_connection_limit), trigger_connection_id, policy);
            if (!finding) continue;
            ++result.detected; finding->type = rule.id; finding->severity = rm2_reporting_detail::upper(rule.severity);
            finding->finding_key = "sha256:" + sha256_hex(rule.id + "|" + finding->process_identity + "|" + finding->host + ":" + std::to_string(finding->port));
            auto suffix = finding->evidence_root.substr(7); if (suffix.size() > 12) suffix.resize(12);
            finding->finding_id = "FINDING-BEHAVIOR-" + rule.id + "-" + suffix;
            if (!rm2_reporting_detail::cooldown_allows(finding->finding_key, cooldowns, now, reporting_policy)) { ++result.suppressed_cooldown; continue; }
            behavior_reporting_detail::persist_finding(behavior_reporting_detail::append_suffix(store.path(), ".findings.jsonl"), *finding, now);
            ++result.persisted; cooldowns[finding->finding_key] = now; changed = true;
            if (reporting_policy.mode == FleetReportingMode::Off || finding->confidence < reporting_policy.minimum_confidence || !std::filesystem::exists(reporting_policy.state_dir / "identity.conf")) { ++result.suppressed_policy; continue; }
            auto announcement = behavior_reporting_detail::announcement_from_finding(*finding);
            announcement.severity = finding->severity; announcement.rule_id = rule.id; announcement.rule_set_id = rules.id;
            announcement.rule_set_version = rules.version; announcement.interpretation = finding->interpretation;
            FleetClient::send_finding(reporting_policy.state_dir, announcement); ++result.announced;
        } catch (const std::exception& error) { ++result.failed; std::cerr << "RM2 periodic rule reporting failed for CONN-" << trigger_connection_id << ": " << error.what() << '\n'; }
    }
    if (changed) rm2_reporting_detail::save_cooldowns(rm2_reporting_detail::state_path(store), cooldowns);
    return result;
}

inline TransferReportingResult auto_report_rule_large_ingress(HistoryStore& history, TransferEvidenceStore& transfer_store,
    std::int64_t connection_id, const FleetReportingPolicy& reporting_policy,const RuleSet& rules = current_rule_set()) {
    TransferReportingResult result;
    auto cooldowns = rm2_reporting_detail::load_cooldowns(rm2_reporting_detail::state_path(history));
    const auto now = rm2_reporting_detail::now_epoch(); bool changed = false;
    for (const auto& rule : rules.definitions) {
        if (!rule.enabled || rule.engine_rule_id != "NET-001") continue;
        if (rm2_reporting_detail::excluded_for_connection(history, rule, connection_id)) continue;
        ++result.considered;
        try {
            LargeIngressPolicy policy; policy.minimum_bytes_received = static_cast<std::uint64_t>(rule.numeric("minimum_bytes_received"));
            auto finding = detect_large_ingress(history, transfer_store, connection_id, policy); if (!finding) continue;
            ++result.detected; finding->type = rule.id; finding->severity = rm2_reporting_detail::upper(rule.severity);
            finding->finding_key = "sha256:" + sha256_hex(rule.id + "|" + finding->process_identity + "|" + finding->host + ":" + std::to_string(finding->port));
            auto suffix = finding->evidence_root.substr(7); if (suffix.size() > 12) suffix.resize(12);
            finding->finding_id = "FINDING-TRANSFER-" + rule.id + "-" + suffix;
            if (!rm2_reporting_detail::cooldown_allows(finding->finding_key, cooldowns, now, reporting_policy)) { ++result.suppressed_cooldown; continue; }
            transfer_detail::persist(transfer_detail::suffix(history.path(), ".findings.jsonl"), *finding, now);
            ++result.persisted; cooldowns[finding->finding_key] = now; changed = true;
            if (reporting_policy.mode == FleetReportingMode::Off || finding->confidence < reporting_policy.minimum_confidence || !std::filesystem::exists(reporting_policy.state_dir / "identity.conf")) { ++result.suppressed_policy; continue; }
            auto announcement = transfer_detail::announcement(*finding);
            announcement.severity = finding->severity; announcement.rule_id = rule.id; announcement.rule_set_id = rules.id;
            announcement.rule_set_version = rules.version; announcement.interpretation = finding->interpretation;
            FleetClient::send_finding(reporting_policy.state_dir, announcement); ++result.announced;
        } catch (const std::exception& error) { ++result.failed; std::cerr << "RM2 transfer rule reporting failed for CONN-" << connection_id << ": " << error.what() << '\n'; }
    }
    if (changed) rm2_reporting_detail::save_cooldowns(rm2_reporting_detail::state_path(history), cooldowns);
    return result;
}

inline FleetReportingResult auto_report_context_rules(HistoryStore& store, TransferEvidenceStore& transfer_store,
    std::int64_t connection_id, const FleetReportingPolicy& reporting_policy,const RuleSet& rules = current_rule_set()) {
    FleetReportingResult result;
    const auto connection = store.connection(connection_id); if (!connection) return result;
    ConnectionRuleContext context; context.connection = *connection;
    context.metrics = aggregate_metrics(store.samples_for_connection(connection_id));
    const auto exported = store.export_data(connection_id); context.baseline = exported.baseline;
    context.name_resolution = store.name_resolution_evidence_for_connection(connection_id);
    context.tls_sessions = store.tls_session_evidence_for_connection(connection_id);
    context.route = store.route_for_connection(connection_id);
    if (const auto transfer = transfer_store.latest(connection_id)) { context.bytes_sent = transfer->bytes_sent; context.bytes_received = transfer->bytes_received; }
    context.destination_prevalence = rm2_reporting_detail::prevalence(store, *connection);
    const auto matches = ContextRuleEngine(rules).evaluate(context);
    auto cooldowns = rm2_reporting_detail::load_cooldowns(rm2_reporting_detail::state_path(store));
    const auto now = rm2_reporting_detail::now_epoch(); bool changed = false;
    for (const auto& match : matches) {
        ++result.considered;
        try {
            auto finding = rm2_reporting_detail::context_announcement(match, context, rules);
            if (!rm2_reporting_detail::cooldown_allows(finding.finding_key, cooldowns, now, reporting_policy)) { ++result.suppressed_cooldown; continue; }
            if (reporting_policy.mode == FleetReportingMode::Off || !std::filesystem::exists(reporting_policy.state_dir / "identity.conf")) { ++result.suppressed_policy; continue; }
            FleetClient::send_finding(reporting_policy.state_dir, finding); cooldowns[finding.finding_key] = now; changed = true; ++result.announced;
        } catch (const std::exception& error) { ++result.failed; std::cerr << "RM2 context rule reporting failed for CONN-" << connection_id << ": " << error.what() << '\n'; }
    }
    if (changed) rm2_reporting_detail::save_cooldowns(rm2_reporting_detail::state_path(store), cooldowns);
    return result;
}

} // namespace neta
