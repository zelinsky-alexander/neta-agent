#include "neta/process_finding_runtime.hpp"

#include "neta/crypto.hpp"
#include "neta/fleet_client.hpp"
#include "neta/rules/rule_set_loader.hpp"
#ifndef _WIN32
#include "neta/yara_x_provider.hpp"
#endif

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>

namespace neta {
namespace {

std::uint64_t now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string json_escape_artifact(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) out << ' ';
                else out << static_cast<char>(c);
        }
    }
    return out.str();
}

std::string artifact_report_key(const StoredArtifactEvidence& row) {
    return row.artifact_sha256 + "|" + row.provider_name + "|" + row.ruleset_sha256;
}

const ProcessNode* node_for_event(const ProcessExecEvent& event,
                                  const std::vector<ProcessNode>& nodes) {
    const auto pid = event.tgid.value_or(event.pid.value_or(0));
    if (pid <= 0) return nullptr;
    for (const auto& node : nodes) {
        if (node.key.pid != pid) continue;
        if (event.platform_process_key && node.key.platform_key == event.platform_process_key) return &node;
        if (event.process_start_time_ns && node.key.start_time_ns == event.process_start_time_ns) return &node;
        if (event.type == ProcessExecEventType::Exit && node.exited_at_ns == event.timestamp_ns) return &node;
    }
    return nullptr;
}

std::string image_name(const std::string& image) {
    const auto normalized = rules::exclusion_normalized(image);
    const auto slash = normalized.find_last_of('/');
    return slash == std::string::npos ? normalized : normalized.substr(slash + 1);
}

bool excluded_process_finding(const ProcessFinding& finding, const ProcessGraph& graph) {
    const auto ruleset = rules::RuleSetLoader::active();
    const rules::RuleDefinition* rule = nullptr;
    for (const auto& candidate : ruleset.definitions) {
        if (candidate.id == finding.rule_id) { rule = &candidate; break; }
    }
    if (rule == nullptr || rule->exclude.empty()) return false;
    const auto& exclusion = rule->exclude;
    if (rules::exclusion_contains(exclusion.process_names, image_name(finding.process_image)) ||
        rules::exclusion_contains(exclusion.executable_paths, finding.process_image) ||
        rules::exclusion_prefix(exclusion.process_path_prefixes, finding.process_image) ||
        rules::exclusion_contains(exclusion.parent_process_names, image_name(finding.parent_image))) return true;
    if (const auto node = graph.find(finding.process)) {
        if (node->uid && rules::exclusion_contains(exclusion.users, std::to_string(*node->uid))) return true;
        if (rules::exclusion_contains(exclusion.process_names, node->comm) ||
            rules::exclusion_contains(exclusion.executable_paths, node->executable_path) ||
            rules::exclusion_prefix(exclusion.process_path_prefixes, node->executable_path)) return true;
    }
    return false;
}

FindingAnnouncementInput announcement(const StoredProcessFinding& finding) {
    FindingAnnouncementInput input;
    input.finding_id = finding.finding_id;
    input.finding_key = finding.finding_key;
    input.host = "process:" + finding.process_key;
    input.port = 1;
    input.transport = "process";
    input.subject_type = "PROCESS";
    input.subject_id = finding.process_key;
    input.subject_pid = finding.pid;
    input.subject_parent_pid = finding.parent_pid;
    input.subject_image = finding.process_image;
    input.subject_parent_image = finding.parent_image;
    input.subject_command_line = finding.command_line;
    input.severity = finding.severity;
    input.rule_id = finding.rule_id;
    input.rule_set_id = "neta-default";
    input.rule_set_version = finding.ruleset_version;
    input.interpretation = finding.interpretation;
    input.changes.push_back("Rule: " + finding.rule_id);
    input.changes.push_back("Severity: " + finding.severity);
    input.changes.push_back("Ruleset: " + finding.ruleset_version);
    input.changes.push_back("Process PID: " + std::to_string(finding.pid));
    if (finding.parent_pid) input.changes.push_back("Parent PID: " + std::to_string(*finding.parent_pid));
    input.changes.push_back(finding.summary);
    if (!finding.interpretation.empty()) input.changes.push_back("Interpretation: " + finding.interpretation);
    if (!finding.process_image.empty()) input.changes.push_back("Process image: " + finding.process_image);
    if (!finding.parent_image.empty()) input.changes.push_back("Parent image: " + finding.parent_image);
    if (!finding.command_line.empty()) input.changes.push_back("Command: " + finding.command_line);
    input.performance_verdict = "UNKNOWN";
    input.trust_verdict = "UNVERIFIED";
    input.evidence_root = finding.evidence_root;
    return input;
}

}  // namespace

ProcessFindingRuntime::ProcessFindingRuntime(const std::filesystem::path& database)
    : store_(database), artifact_store_(database) {
#ifndef _WIN32
    const char* rules_path = std::getenv("NETA_YARAX_RULES");
    if (rules_path != nullptr && *rules_path != '\0') {
        YaraXProviderConfig config;
        config.rules_path = rules_path;
        if (const char* ruleset = std::getenv("NETA_YARAX_RULESET_ID"); ruleset != nullptr && *ruleset != '\0')
            config.ruleset_id = ruleset;
        artifact_providers_.add(std::make_unique<YaraXProvider>(std::move(config)));
    }
#endif
}

void ProcessFindingRuntime::bootstrap(const std::vector<ProcessExecEvent>& snapshot) {
    for (const auto& event : snapshot) static_cast<void>(graph_.observe(event));
    for (const auto& node : graph_.snapshot()) store_.upsert_process(node);
    persist_findings(engine_.evaluate_snapshot(graph_));
}

void ProcessFindingRuntime::persist_current_node(const ProcessExecEvent& event) {
    const auto nodes = graph_.snapshot();
    if (const auto* node = node_for_event(event, nodes)) store_.upsert_process(*node);
}

void ProcessFindingRuntime::persist_findings(const std::vector<ProcessFinding>& findings) {
    for (const auto& finding : findings) {
        if (excluded_process_finding(finding, graph_)) continue;
        static_cast<void>(store_.upsert_finding(finding));
    }
}

void ProcessFindingRuntime::scan_executed_artifact(const ProcessExecEvent& event) {
    if (event.type != ProcessExecEventType::Start || event.executable_path.empty() || artifact_providers_.size() == 0) return;

    ArtifactIdentity artifact;
    artifact.path = event.executable_path;
    std::error_code size_error;
    const auto size = std::filesystem::file_size(artifact.path, size_error);
    if (!size_error) artifact.size = size;

    try {
        artifact.sha256 = sha256_file_hex(artifact.path);
    } catch (const std::exception&) {
        return;
    }

    auto found = artifact_scan_cache_.find(*artifact.sha256);
    if (found == artifact_scan_cache_.end()) {
        auto evidence = artifact_providers_.scan_all(artifact);
        found = artifact_scan_cache_.emplace(*artifact.sha256, std::move(evidence)).first;
    }
    for (const auto& evidence : found->second) {
        artifact_store_.record(artifact, evidence, event.timestamp_ns);
    }
}

void ProcessFindingRuntime::observe(const std::vector<ProcessExecEvent>& events) {
    for (const auto& event : events) {
        if (!graph_.observe(event)) continue;
        persist_current_node(event);
        scan_executed_artifact(event);
        persist_findings(engine_.observe(event, graph_));
    }
}

bool ProcessFindingRuntime::report_artifact_evidence(const FleetReportingPolicy& policy,
                                                     bool fleet_identity_available) {
    if (!fleet_identity_available || policy.mode == FleetReportingMode::Off) return false;
    const auto recent = artifact_store_.recent(64);
    std::vector<StoredArtifactEvidence> changed;
    for (const auto& row : recent) {
        const auto key = artifact_report_key(row);
        const auto previous = artifact_reported_counts_.find(key);
        if (previous == artifact_reported_counts_.end() || previous->second < row.observation_count)
            changed.push_back(row);
    }
    if (changed.empty()) return false;

    std::ostringstream body;
    body << "{\"artifact_evidence\":[";
    for (std::size_t i = 0; i < changed.size(); ++i) {
        const auto& row = changed[i];
        if (i != 0) body << ',';
        body << "{\"artifact_sha256\":\"" << json_escape_artifact(row.artifact_sha256) << "\""
             << ",\"artifact_path\":\"" << json_escape_artifact(row.artifact_path) << "\""
             << ",\"artifact_size\":" << row.artifact_size
             << ",\"provider_name\":\"" << json_escape_artifact(row.provider_name) << "\""
             << ",\"provider_version\":\"" << json_escape_artifact(row.provider_version) << "\""
             << ",\"ruleset_id\":\"" << json_escape_artifact(row.ruleset_id) << "\""
             << ",\"ruleset_sha256\":\"" << json_escape_artifact(row.ruleset_sha256) << "\""
             << ",\"scan_state\":\"" << json_escape_artifact(row.state) << "\""
             << ",\"detail\":\"" << json_escape_artifact(row.detail) << "\""
             << ",\"observation_count\":" << row.observation_count
             << ",\"matches\":[";
        for (std::size_t match_index = 0; match_index < row.matches.size(); ++match_index) {
            const auto& match = row.matches[match_index];
            if (match_index != 0) body << ',';
            body << "{\"rule_name\":\"" << json_escape_artifact(match.rule_name)
                 << "\",\"rule_namespace\":\"" << json_escape_artifact(match.rule_namespace)
                 << "\",\"tags\":[";
            for (std::size_t tag_index = 0; tag_index < match.tags.size(); ++tag_index) {
                if (tag_index != 0) body << ',';
                body << '"' << json_escape_artifact(match.tags[tag_index]) << '"';
            }
            body << "]}";
        }
        body << "]}";
    }
    body << "]}";

    static_cast<void>(FleetClient::send_evidence_summary(policy.state_dir, body.str()));
    for (const auto& row : changed)
        artifact_reported_counts_[artifact_report_key(row)] = row.observation_count;
    return true;
}

ProcessFindingReportResult ProcessFindingRuntime::report_pending(
    const FleetReportingPolicy& policy, bool fleet_identity_available) {
    ProcessFindingReportResult result;
    if (!fleet_identity_available || policy.mode == FleetReportingMode::Off) return result;
    constexpr std::uint64_t retry_after_ns = 60'000'000'000ULL;
    const auto current_ns = now_ns();
    for (const auto& finding : store_.pending_for_report(32, current_ns, retry_after_ns)) {
        ++result.considered;
        store_.mark_report_attempt(finding.finding_id, current_ns);
        try {
            static_cast<void>(FleetClient::send_finding(policy.state_dir, announcement(finding)));
            store_.mark_reported(finding.finding_id, now_ns());
            ++result.announced;
        } catch (const std::exception& error) {
            ++result.failed;
            std::cerr << "Process finding announcement failed for " << finding.finding_id
                      << "; retained for retry: " << error.what() << std::endl;
        }
    }
    try {
        static_cast<void>(report_artifact_evidence(policy, fleet_identity_available));
    } catch (const std::exception& error) {
        ++result.failed;
        std::cerr << "RM4 artifact evidence upload failed; retained locally for retry: "
                  << error.what() << std::endl;
    }
    return result;
}

}  // namespace neta
