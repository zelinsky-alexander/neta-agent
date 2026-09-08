#include "neta/process_findings.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>

namespace neta {
namespace {

std::string lower_normalized(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        if (ch == '\\') return '/';
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string leaf_name(const ProcessNode& node) {
    std::string value = !node.comm.empty() ? node.comm : node.executable_path;
    value = lower_normalized(std::move(value));
    const auto slash = value.find_last_of('/');
    if (slash != std::string::npos) value.erase(0, slash + 1);
    return value;
}

bool is_shell(const ProcessNode& node) {
    const auto name = leaf_name(node);
    return name == "sh" || name == "bash" || name == "dash" || name == "zsh" ||
           name == "ksh" || name == "fish" || name == "powershell" ||
           name == "powershell.exe" || name == "pwsh" || name == "pwsh.exe" ||
           name == "cmd" || name == "cmd.exe";
}

bool is_expected_interactive_shell_parent(const ProcessNode& node) {
    if (is_shell(node)) return true;
    const auto name = leaf_name(node);
    return name == "sshd" || name == "sudo" || name == "su" || name == "login" ||
           name == "systemd" || name == "init" || name == "tmux" || name == "screen" ||
           name == "gnome-terminal-server" || name == "konsole" ||
           name == "windowsterminal.exe" || name == "wt.exe" || name == "conhost.exe" ||
           name == "explorer.exe" || name == "winlogon.exe";
}

bool is_transient_path(const std::string& raw) {
    const auto path = lower_normalized(raw);
    if (path.empty()) return false;
    return path.starts_with("/tmp/") || path.starts_with("/var/tmp/") ||
           path.starts_with("/dev/shm/") || path.find("/appdata/local/temp/") != std::string::npos ||
           path.find("/windows/temp/") != std::string::npos;
}

const ProcessNode* find_node(const std::vector<ProcessNode>& nodes, const ProcessInstanceKey& key) {
    const auto it = std::find_if(nodes.begin(), nodes.end(), [&](const ProcessNode& node) {
        return node.key == key;
    });
    return it == nodes.end() ? nullptr : &*it;
}

ProcessFinding base_finding(ProcessFindingKind kind, ProcessFindingSeverity severity,
                            const ProcessNode& node, const ProcessNode* parent,
                            std::string summary, std::string interpretation) {
    ProcessFinding finding;
    finding.kind = kind;
    finding.severity = severity;
    finding.rule_id = to_string(kind);
    finding.observed_at_ns = node.started_at_ns;
    finding.process = node.key;
    finding.parent = node.parent;
    finding.process_image = node.executable_path;
    finding.parent_image = parent == nullptr ? std::string{} : parent->executable_path;
    finding.command_line = node.command_line;
    finding.summary = std::move(summary);
    finding.interpretation = std::move(interpretation);
    return finding;
}

void trim_before(std::deque<std::uint64_t>& values, std::uint64_t now, std::uint64_t window) {
    const auto cutoff = now > window ? now - window : 0;
    while (!values.empty() && values.front() < cutoff) values.pop_front();
}

const ProcessNode* node_for_event(const ProcessExecEvent& event, const std::vector<ProcessNode>& nodes) {
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

}  // namespace

const char* to_string(ProcessFindingSeverity severity) noexcept {
    switch (severity) {
        case ProcessFindingSeverity::Low: return "LOW";
        case ProcessFindingSeverity::Medium: return "MEDIUM";
        case ProcessFindingSeverity::High: return "HIGH";
    }
    return "UNKNOWN";
}

const char* to_string(ProcessFindingKind kind) noexcept {
    switch (kind) {
        case ProcessFindingKind::ExecFromTransientPath: return "PROCESS_EXEC_FROM_TRANSIENT_PATH";
        case ProcessFindingKind::ShellFromUnexpectedParent: return "PROCESS_SHELL_FROM_UNEXPECTED_PARENT";
        case ProcessFindingKind::UnexpectedElevation: return "PROCESS_UNEXPECTED_ELEVATION";
        case ProcessFindingKind::RapidChildFanout: return "PROCESS_RAPID_CHILD_FANOUT";
        case ProcessFindingKind::ShortLivedProcessBurst: return "PROCESS_SHORT_LIVED_BURST";
    }
    return "PROCESS_UNKNOWN_PATTERN";
}

ProcessFindingEngine::ProcessFindingEngine(ProcessFindingConfig config) : config_(config) {}

std::vector<ProcessFinding> ProcessFindingEngine::evaluate_node(
    const ProcessNode& node, const std::vector<ProcessNode>& nodes) const {
    std::vector<ProcessFinding> findings;
    const ProcessNode* parent = node.parent ? find_node(nodes, *node.parent) : nullptr;

    if (is_transient_path(node.executable_path)) {
        findings.push_back(base_finding(
            ProcessFindingKind::ExecFromTransientPath, ProcessFindingSeverity::Medium, node, parent,
            "Executable started from a transient filesystem location.",
            "Execution from a transient location is compatible with staged or temporary tooling; malicious intent is not established."));
    }

    if (is_shell(node) && parent != nullptr && !is_expected_interactive_shell_parent(*parent)) {
        findings.push_back(base_finding(
            ProcessFindingKind::ShellFromUnexpectedParent, ProcessFindingSeverity::Medium, node, parent,
            "A shell was spawned by a process not classified as an expected interactive shell parent.",
            "This parent-child relationship resembles shell-spawn behavior worth investigation; exploitation is not established."));
    }

    if (node.elevated == std::optional<bool>{true} && parent != nullptr &&
        parent->elevated == std::optional<bool>{false}) {
        findings.push_back(base_finding(
            ProcessFindingKind::UnexpectedElevation, ProcessFindingSeverity::Medium, node, parent,
            "A child process is elevated while its observed parent is not elevated.",
            "A privilege-boundary transition was observed. It may be legitimate administrative activity; malicious intent is not established."));
    }

    return findings;
}

std::vector<ProcessFinding> ProcessFindingEngine::evaluate_snapshot(const ProcessGraph& graph) const {
    const auto nodes = graph.snapshot();
    std::vector<ProcessFinding> findings;
    for (const auto& node : nodes) {
        auto current = evaluate_node(node, nodes);
        findings.insert(findings.end(), current.begin(), current.end());
    }
    return findings;
}

std::vector<ProcessFinding> ProcessFindingEngine::observe(const ProcessExecEvent& event,
                                                          const ProcessGraph& graph) {
    const auto nodes = graph.snapshot();
    const auto* node = node_for_event(event, nodes);
    if (node == nullptr) return {};

    std::vector<ProcessFinding> findings;
    if (event.type == ProcessExecEventType::Start) {
        starts_[node->key] = event.timestamp_ns;
        auto static_findings = evaluate_node(*node, nodes);
        findings.insert(findings.end(), static_findings.begin(), static_findings.end());

        if (node->parent) {
            auto& starts = child_starts_[*node->parent];
            trim_before(starts, event.timestamp_ns, config_.fanout_window_ns);
            starts.push_back(event.timestamp_ns);
            if (starts.size() == config_.fanout_count) {
                const auto* parent = find_node(nodes, *node->parent);
                if (parent != nullptr) {
                    auto finding = base_finding(
                        ProcessFindingKind::RapidChildFanout, ProcessFindingSeverity::Medium,
                        *parent, parent->parent ? find_node(nodes, *parent->parent) : nullptr,
                        "A process spawned many child processes within a short window.",
                        "Rapid child-process fan-out can resemble scripted or automated execution; malicious intent is not established.");
                    finding.observed_at_ns = event.timestamp_ns;
                    findings.push_back(std::move(finding));
                }
            }
        }
        return findings;
    }

    const auto started = starts_.find(node->key);
    if (started != starts_.end()) {
        const auto duration = event.timestamp_ns >= started->second ? event.timestamp_ns - started->second : 0;
        starts_.erase(started);
        if (duration <= config_.short_lived_max_ns && node->parent) {
            auto& exits = short_exits_[*node->parent];
            trim_before(exits, event.timestamp_ns, config_.short_lived_window_ns);
            exits.push_back(event.timestamp_ns);
            if (exits.size() == config_.short_lived_count) {
                const auto* parent = find_node(nodes, *node->parent);
                if (parent != nullptr) {
                    auto finding = base_finding(
                        ProcessFindingKind::ShortLivedProcessBurst, ProcessFindingSeverity::Medium,
                        *parent, parent->parent ? find_node(nodes, *parent->parent) : nullptr,
                        "A process produced a burst of short-lived child processes.",
                        "A short-lived process burst can resemble scripted execution or repeated helper invocation; malicious intent is not established.");
                    finding.observed_at_ns = event.timestamp_ns;
                    findings.push_back(std::move(finding));
                }
            }
        }
    }
    return findings;
}

}  // namespace neta
