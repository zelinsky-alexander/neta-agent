#include "neta/process_finding_runtime.hpp"

#include "neta/fleet_client.hpp"
#include "neta/rules/rule_set_loader.hpp"

#include <chrono>
#include <iostream>
#include <optional>
#include <string>

namespace neta {
namespace {

std::uint64_t now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
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
    : store_(database) {}

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

void ProcessFindingRuntime::observe(const std::vector<ProcessExecEvent>& events) {
    for (const auto& event : events) {
        if (!graph_.observe(event)) continue;
        persist_current_node(event);
        persist_findings(engine_.observe(event, graph_));
    }
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
    return result;
}

}  // namespace neta
