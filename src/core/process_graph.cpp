#include "neta/process_graph.hpp"
#include "neta/process_findings.hpp"
#include "neta/rules/rule_set_loader.hpp"

#include <algorithm>
#include <cctype>
#include <deque>
#include <stdexcept>
#include <utility>

namespace neta {

std::size_t ProcessInstanceKeyHash::operator()(const ProcessInstanceKey& key) const noexcept {
    std::size_t value = std::hash<std::int64_t>{}(key.pid);
    const auto mix = [&value](std::size_t next) {
        value ^= next + 0x9e3779b97f4a7c15ULL + (value << 6U) + (value >> 2U);
    };
    if (key.start_time_ns) mix(std::hash<std::uint64_t>{}(*key.start_time_ns));
    if (key.platform_key) mix(std::hash<std::uint64_t>{}(*key.platform_key));
    return value;
}

ProcessGraph::ProcessGraph(std::size_t max_nodes) : max_nodes_(max_nodes) {
    if (max_nodes_ == 0) throw std::invalid_argument("process graph capacity must be non-zero");
}

std::optional<ProcessInstanceKey> ProcessGraph::key_from(const ProcessExecEvent& event) const {
    if (!event.tgid || *event.tgid <= 0) return std::nullopt;
    ProcessInstanceKey key;
    key.pid = *event.tgid;
    key.platform_key = event.platform_process_key;
    if (!key.platform_key) key.start_time_ns = event.process_start_time_ns;
    if (!key.durable()) return std::nullopt;
    return key;
}

std::optional<ProcessInstanceKey> ProcessGraph::unique_active_key_for_pid(std::int64_t pid) const {
    const auto [begin, end] = active_by_pid_.equal_range(pid);
    if (begin == end) return std::nullopt;
    auto it = begin;
    const ProcessInstanceKey key = it->second;
    ++it;
    if (it != end) return std::nullopt;
    return key;
}

void ProcessGraph::index_active(const ProcessInstanceKey& key) { active_by_pid_.emplace(key.pid, key); }

void ProcessGraph::unindex_active(const ProcessInstanceKey& key) {
    const auto [begin, end] = active_by_pid_.equal_range(key.pid);
    for (auto it = begin; it != end; ++it) {
        if (it->second == key) { active_by_pid_.erase(it); return; }
    }
}

void ProcessGraph::evict_if_needed() {
    while (nodes_.size() >= max_nodes_ && !insertion_order_.empty()) {
        const auto oldest = insertion_order_.front(); insertion_order_.pop_front();
        const auto found = nodes_.find(oldest);
        if (found == nodes_.end()) continue;
        if (!found->second.exited_at_ns) unindex_active(found->first);
        nodes_.erase(found); ++health_.evicted_nodes;
    }
}

bool ProcessGraph::observe(const ProcessExecEvent& event) {
    auto key = key_from(event);
    if (!key && event.type == ProcessExecEventType::Exit && event.tgid && *event.tgid > 0) {
        key = unique_active_key_for_pid(*event.tgid);
        if (!key) { ++health_.ambiguous_exit_events; return false; }
    }
    if (!key) { ++health_.rejected_without_stable_identity; return false; }

    if (event.type == ProcessExecEventType::Exit) {
        const auto found = nodes_.find(*key);
        if (found == nodes_.end()) return false;
        found->second.exited_at_ns = event.timestamp_ns;
        found->second.exit_code = event.exit_code;
        unindex_active(found->first);
        return true;
    }

    const auto existing = nodes_.find(*key);
    if (existing != nodes_.end()) {
        auto& node = existing->second;
        node.uid = event.uid; node.gid = event.gid; node.session_id = event.session_id;
        node.user_identity = event.user_identity; node.integrity_level = event.integrity_level;
        node.elevated = event.elevated; node.comm = event.comm; node.executable_path = event.executable_path;
        node.command_line = event.command_line; node.working_directory = event.working_directory;
        return true;
    }

    evict_if_needed();
    ProcessNode node;
    node.key = *key; node.parent_pid = event.parent_tgid; node.uid = event.uid; node.gid = event.gid;
    node.session_id = event.session_id; node.user_identity = event.user_identity;
    node.integrity_level = event.integrity_level; node.elevated = event.elevated; node.comm = event.comm;
    node.executable_path = event.executable_path; node.command_line = event.command_line;
    node.working_directory = event.working_directory; node.started_at_ns = event.timestamp_ns;

    if (event.parent_tgid && *event.parent_tgid > 0) {
        ProcessInstanceKey parent_key;
        parent_key.pid = *event.parent_tgid; parent_key.platform_key = event.parent_platform_process_key;
        if (!parent_key.platform_key) parent_key.start_time_ns = event.parent_process_start_time_ns;
        if (parent_key.durable()) node.parent = parent_key;
        else {
            node.parent = unique_active_key_for_pid(*event.parent_tgid);
            if (!node.parent) {
                const auto [begin, end] = active_by_pid_.equal_range(*event.parent_tgid);
                if (begin != end) ++health_.ambiguous_parent_links;
            }
        }
    }

    const auto [inserted, ok] = nodes_.emplace(node.key, std::move(node));
    if (!ok) return false;
    insertion_order_.push_back(inserted->first); index_active(inserted->first); return true;
}

std::optional<ProcessNode> ProcessGraph::find(const ProcessInstanceKey& key) const {
    const auto found = nodes_.find(key); return found == nodes_.end() ? std::nullopt : std::optional<ProcessNode>(found->second);
}

std::vector<ProcessNode> ProcessGraph::snapshot() const {
    std::vector<ProcessNode> result; result.reserve(nodes_.size());
    for (const auto& [key, node] : nodes_) { static_cast<void>(key); result.push_back(node); }
    std::sort(result.begin(), result.end(), [](const ProcessNode& left, const ProcessNode& right) {
        if (left.started_at_ns != right.started_at_ns) return left.started_at_ns < right.started_at_ns;
        return left.key.pid < right.key.pid;
    });
    return result;
}

std::size_t ProcessGraph::active_count() const noexcept {
    std::size_t count = 0;
    for (const auto& [key, node] : nodes_) { static_cast<void>(key); if (!node.exited_at_ns) ++count; }
    return count;
}

namespace {
constexpr std::uint64_t kNanosecondsPerMillisecond = 1'000'000ULL;

std::string lower_normalized(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        if (ch == '\\') return '/'; return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string leaf_name(const ProcessNode& node) {
    std::string value = !node.comm.empty() ? node.comm : node.executable_path;
    value = lower_normalized(std::move(value));
    const auto slash = value.find_last_of('/'); if (slash != std::string::npos) value.erase(0, slash + 1);
    return value;
}

std::vector<std::string> normalized_values(const std::vector<std::string>& values) {
    std::vector<std::string> result; result.reserve(values.size());
    for (auto value : values) result.push_back(lower_normalized(std::move(value)));
    return result;
}

bool contains_name(const std::vector<std::string>& names, const ProcessNode& node) {
    const auto name = leaf_name(node); return std::find(names.begin(), names.end(), name) != names.end();
}

bool path_matches(const std::string& raw, const std::vector<std::string>& prefixes,
                  const std::vector<std::string>& substrings) {
    const auto path = lower_normalized(raw); if (path.empty()) return false;
    for (const auto& prefix : prefixes) if (path.starts_with(prefix)) return true;
    for (const auto& needle : substrings) if (path.find(needle) != std::string::npos) return true;
    return false;
}

bool is_transient_path(const std::string& raw, const ProcessFindingConfig& config) {
    return path_matches(raw, config.transient_path_prefixes, config.transient_path_substrings);
}

const ProcessNode* find_process_node(const std::vector<ProcessNode>& nodes, const ProcessInstanceKey& key) {
    const auto it = std::find_if(nodes.begin(), nodes.end(), [&](const ProcessNode& node) { return node.key == key; });
    return it == nodes.end() ? nullptr : &*it;
}

ProcessFindingSeverity severity_from_string(const std::string& severity) {
    const auto normalized = lower_normalized(severity);
    if (normalized == "low") return ProcessFindingSeverity::Low;
    if (normalized == "medium") return ProcessFindingSeverity::Medium;
    if (normalized == "high") return ProcessFindingSeverity::High;
    throw std::runtime_error("unsupported process finding severity: " + severity);
}

ProcessFindingConfig config_from_rules(const RuleSet& rules) {
    ProcessFindingConfig config; config.ruleset_version = rules.version;
    const auto& transient = rules.rule("PROC-001");
    config.transient_path_enabled = transient.enabled; config.transient_path_severity = transient.severity;
    config.transient_path_prefixes = normalized_values(transient.string_list("path_prefixes"));
    config.transient_path_substrings = normalized_values(transient.string_list("path_substrings"));
    const auto& shell = rules.rule("PROC-002");
    config.unexpected_shell_enabled = shell.enabled; config.unexpected_shell_severity = shell.severity;
    config.shell_names = normalized_values(shell.string_list("shell_names"));
    config.expected_shell_parent_names = normalized_values(shell.string_list("expected_parent_names"));
    const auto& elevation = rules.rule("PROC-003");
    config.unexpected_elevation_enabled = elevation.enabled; config.unexpected_elevation_severity = elevation.severity;
    config.expected_elevation_parent_names = normalized_values(elevation.string_list("expected_parent_names"));
    const auto& fanout = rules.rule("PROC-004");
    config.fanout_enabled = fanout.enabled; config.fanout_severity = fanout.severity;
    config.fanout_count = static_cast<std::size_t>(fanout.numeric("child_count"));
    config.fanout_window_ns = static_cast<std::uint64_t>(fanout.numeric("window_ms")) * kNanosecondsPerMillisecond;
    const auto& short_lived = rules.rule("PROC-005");
    config.short_lived_enabled = short_lived.enabled; config.short_lived_severity = short_lived.severity;
    config.short_lived_count = static_cast<std::size_t>(short_lived.numeric("child_count"));
    config.short_lived_max_ns = static_cast<std::uint64_t>(short_lived.numeric("max_lifetime_ms")) * kNanosecondsPerMillisecond;
    config.short_lived_window_ns = static_cast<std::uint64_t>(short_lived.numeric("window_ms")) * kNanosecondsPerMillisecond;
    return config;
}

ProcessFinding make_finding(ProcessFindingKind kind, const std::string& rule_id,
                            ProcessFindingSeverity severity, const std::string& ruleset_version,
                            const ProcessNode& node, const ProcessNode* parent,
                            std::string summary, std::string interpretation) {
    ProcessFinding finding; finding.kind = kind; finding.severity = severity; finding.rule_id = rule_id;
    finding.ruleset_version = ruleset_version; finding.observed_at_ns = node.started_at_ns; finding.process = node.key;
    finding.parent = node.parent; finding.process_image = node.executable_path;
    finding.parent_image = parent == nullptr ? std::string{} : parent->executable_path;
    finding.command_line = node.command_line; finding.summary = std::move(summary); finding.interpretation = std::move(interpretation);
    return finding;
}

void trim_before(std::deque<std::uint64_t>& values, std::uint64_t now, std::uint64_t window) {
    const auto cutoff = now > window ? now - window : 0;
    while (!values.empty() && values.front() < cutoff) values.pop_front();
}

const ProcessNode* node_for_event(const ProcessExecEvent& event, const std::vector<ProcessNode>& nodes) {
    const auto pid = event.tgid.value_or(event.pid.value_or(0)); if (pid <= 0) return nullptr;
    for (const auto& node : nodes) {
        if (node.key.pid != pid) continue;
        if (event.platform_process_key && node.key.platform_key == event.platform_process_key) return &node;
        if (event.process_start_time_ns && node.key.start_time_ns == event.process_start_time_ns) return &node;
        if (event.type == ProcessExecEventType::Exit && node.exited_at_ns == event.timestamp_ns) return &node;
    }
    return nullptr;
}

bool has_custom_short_lived(const std::vector<rules::RuleDefinition>& rules) {
    return std::any_of(rules.begin(), rules.end(), [](const auto& rule) {
        return rule.enabled && rule.engine_rule_id == "PROC-005";
    });
}
}  // namespace

const char* to_string(ProcessFindingSeverity severity) noexcept {
    switch (severity) { case ProcessFindingSeverity::Low: return "LOW"; case ProcessFindingSeverity::Medium: return "MEDIUM"; case ProcessFindingSeverity::High: return "HIGH"; }
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

ProcessFindingEngine::ProcessFindingEngine() : ProcessFindingEngine(rules::RuleSetLoader::active()) {}

ProcessFindingEngine::ProcessFindingEngine(const RuleSet& rules) : config_(config_from_rules(rules)) {
    for (const auto& definition : rules.definitions) {
        if (definition.id != definition.engine_rule_id && definition.category == "process") custom_process_rules_.push_back(definition);
    }
}

ProcessFindingEngine::ProcessFindingEngine(ProcessFindingConfig config) : config_(std::move(config)) {}

std::vector<ProcessFinding> ProcessFindingEngine::evaluate_node(const ProcessNode& node,
                                                                 const std::vector<ProcessNode>& nodes) const {
    std::vector<ProcessFinding> findings;
    const ProcessNode* parent = node.parent ? find_process_node(nodes, *node.parent) : nullptr;
    if (config_.transient_path_enabled && is_transient_path(node.executable_path, config_))
        findings.push_back(make_finding(ProcessFindingKind::ExecFromTransientPath, "PROC-001", severity_from_string(config_.transient_path_severity), config_.ruleset_version, node, parent,
            "Executable started from a transient filesystem location.", "Execution from a transient location is compatible with staged or temporary tooling; malicious intent is not established."));
    if (config_.unexpected_shell_enabled && contains_name(config_.shell_names, node) && parent != nullptr && !contains_name(config_.expected_shell_parent_names, *parent))
        findings.push_back(make_finding(ProcessFindingKind::ShellFromUnexpectedParent, "PROC-002", severity_from_string(config_.unexpected_shell_severity), config_.ruleset_version, node, parent,
            "A shell was spawned by a process not classified as an expected interactive shell parent.", "This parent-child relationship resembles shell-spawn behavior worth investigation; exploitation is not established."));
    if (config_.unexpected_elevation_enabled && node.elevated == std::optional<bool>{true} && parent != nullptr && parent->elevated == std::optional<bool>{false} && !contains_name(config_.expected_elevation_parent_names, *parent))
        findings.push_back(make_finding(ProcessFindingKind::UnexpectedElevation, "PROC-003", severity_from_string(config_.unexpected_elevation_severity), config_.ruleset_version, node, parent,
            "A child process is elevated while its observed parent is not elevated.", "A privilege-boundary transition was observed. It may be legitimate administrative activity; malicious intent is not established."));

    for (const auto& rule : custom_process_rules_) {
        if (!rule.enabled) continue;
        if (rule.engine_rule_id == "PROC-001") {
            if (path_matches(node.executable_path, normalized_values(rule.string_list("path_prefixes")), normalized_values(rule.string_list("path_substrings"))))
                findings.push_back(make_finding(ProcessFindingKind::ExecFromTransientPath, rule.id, severity_from_string(rule.severity), config_.ruleset_version, node, parent,
                    "Executable matched a custom transient-path rule.", "A centrally managed custom transient-path detection matched this process."));
        } else if (rule.engine_rule_id == "PROC-002") {
            const auto shells = normalized_values(rule.string_list("shell_names"));
            const auto parents = normalized_values(rule.string_list("expected_parent_names"));
            if (contains_name(shells, node) && parent != nullptr && !contains_name(parents, *parent))
                findings.push_back(make_finding(ProcessFindingKind::ShellFromUnexpectedParent, rule.id, severity_from_string(rule.severity), config_.ruleset_version, node, parent,
                    "A shell matched a custom unexpected-parent rule.", "A centrally managed custom shell parent-child detection matched this process."));
        } else if (rule.engine_rule_id == "PROC-003") {
            const auto expected = normalized_values(rule.string_list("expected_parent_names"));
            if (node.elevated == std::optional<bool>{true} && parent != nullptr && parent->elevated == std::optional<bool>{false} && !contains_name(expected, *parent))
                findings.push_back(make_finding(ProcessFindingKind::UnexpectedElevation, rule.id, severity_from_string(rule.severity), config_.ruleset_version, node, parent,
                    "A privilege transition matched a custom elevation rule.", "A centrally managed custom privilege-boundary detection matched this process."));
        }
    }
    return findings;
}

std::vector<ProcessFinding> ProcessFindingEngine::evaluate_snapshot(const ProcessGraph& graph) const {
    const auto nodes = graph.snapshot(); std::vector<ProcessFinding> findings;
    for (const auto& node : nodes) { auto current = evaluate_node(node, nodes); findings.insert(findings.end(), current.begin(), current.end()); }
    return findings;
}

std::vector<ProcessFinding> ProcessFindingEngine::observe(const ProcessExecEvent& event, const ProcessGraph& graph) {
    const auto nodes = graph.snapshot(); const auto* node = node_for_event(event, nodes); if (node == nullptr) return {};
    std::vector<ProcessFinding> findings;
    if (event.type == ProcessExecEventType::Start) {
        if (config_.short_lived_enabled || has_custom_short_lived(custom_process_rules_)) starts_[node->key] = event.timestamp_ns;
        auto static_findings = evaluate_node(*node, nodes); findings.insert(findings.end(), static_findings.begin(), static_findings.end());
        if (node->parent) {
            if (config_.fanout_enabled) {
                auto& starts = child_starts_[*node->parent]; trim_before(starts, event.timestamp_ns, config_.fanout_window_ns); starts.push_back(event.timestamp_ns);
                if (starts.size() == config_.fanout_count) {
                    const auto* parent = find_process_node(nodes, *node->parent);
                    if (parent) { auto finding = make_finding(ProcessFindingKind::RapidChildFanout, "PROC-004", severity_from_string(config_.fanout_severity), config_.ruleset_version, *parent, parent->parent ? find_process_node(nodes, *parent->parent) : nullptr,
                        "A process spawned many child processes within a short window.", "Rapid child-process fan-out can resemble scripted or automated execution; malicious intent is not established."); finding.observed_at_ns = event.timestamp_ns; findings.push_back(std::move(finding)); }
                }
            }
            for (const auto& rule : custom_process_rules_) {
                if (!rule.enabled || rule.engine_rule_id != "PROC-004") continue;
                const auto window = static_cast<std::uint64_t>(rule.numeric("window_ms")) * kNanosecondsPerMillisecond;
                const auto count = static_cast<std::size_t>(rule.numeric("child_count"));
                auto& starts = custom_child_starts_[rule.id][*node->parent]; trim_before(starts, event.timestamp_ns, window); starts.push_back(event.timestamp_ns);
                if (starts.size() == count) {
                    const auto* parent = find_process_node(nodes, *node->parent);
                    if (parent) { auto finding = make_finding(ProcessFindingKind::RapidChildFanout, rule.id, severity_from_string(rule.severity), config_.ruleset_version, *parent, parent->parent ? find_process_node(nodes, *parent->parent) : nullptr,
                        "A process matched a custom rapid child fan-out rule.", "A centrally managed custom fan-out detection matched this process."); finding.observed_at_ns = event.timestamp_ns; findings.push_back(std::move(finding)); }
                }
            }
        }
        return findings;
    }

    const auto started = starts_.find(node->key); if (started == starts_.end()) return findings;
    const auto duration = event.timestamp_ns >= started->second ? event.timestamp_ns - started->second : 0; starts_.erase(started);
    if (!node->parent) return findings;
    if (config_.short_lived_enabled && duration <= config_.short_lived_max_ns) {
        auto& exits = short_exits_[*node->parent]; trim_before(exits, event.timestamp_ns, config_.short_lived_window_ns); exits.push_back(event.timestamp_ns);
        if (exits.size() == config_.short_lived_count) {
            const auto* parent = find_process_node(nodes, *node->parent);
            if (parent) { auto finding = make_finding(ProcessFindingKind::ShortLivedProcessBurst, "PROC-005", severity_from_string(config_.short_lived_severity), config_.ruleset_version, *parent, parent->parent ? find_process_node(nodes, *parent->parent) : nullptr,
                "A process produced a burst of short-lived child processes.", "A short-lived process burst can resemble scripted execution or repeated helper invocation; malicious intent is not established."); finding.observed_at_ns = event.timestamp_ns; findings.push_back(std::move(finding)); }
        }
    }
    for (const auto& rule : custom_process_rules_) {
        if (!rule.enabled || rule.engine_rule_id != "PROC-005") continue;
        const auto max_lifetime = static_cast<std::uint64_t>(rule.numeric("max_lifetime_ms")) * kNanosecondsPerMillisecond;
        if (duration > max_lifetime) continue;
        const auto window = static_cast<std::uint64_t>(rule.numeric("window_ms")) * kNanosecondsPerMillisecond;
        const auto count = static_cast<std::size_t>(rule.numeric("child_count"));
        auto& exits = custom_short_exits_[rule.id][*node->parent]; trim_before(exits, event.timestamp_ns, window); exits.push_back(event.timestamp_ns);
        if (exits.size() == count) {
            const auto* parent = find_process_node(nodes, *node->parent);
            if (parent) { auto finding = make_finding(ProcessFindingKind::ShortLivedProcessBurst, rule.id, severity_from_string(rule.severity), config_.ruleset_version, *parent, parent->parent ? find_process_node(nodes, *parent->parent) : nullptr,
                "A process matched a custom short-lived child burst rule.", "A centrally managed custom short-lived-process detection matched this process."); finding.observed_at_ns = event.timestamp_ns; findings.push_back(std::move(finding)); }
        }
    }
    return findings;
}

}  // namespace neta
