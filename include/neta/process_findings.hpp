#pragma once

#include "neta/process_graph.hpp"
#include "neta/rules/rule_set.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace neta {

enum class ProcessFindingSeverity { Low, Medium, High };

enum class ProcessFindingKind {
    ExecFromTransientPath,
    ShellFromUnexpectedParent,
    UnexpectedElevation,
    RapidChildFanout,
    ShortLivedProcessBurst,
};

struct ProcessFinding {
    ProcessFindingKind kind{};
    ProcessFindingSeverity severity{ProcessFindingSeverity::Low};
    std::string rule_id;
    std::string ruleset_version;
    std::uint64_t observed_at_ns{0};
    ProcessInstanceKey process;
    std::optional<ProcessInstanceKey> parent;
    std::string process_image;
    std::string parent_image;
    std::string command_line;
    std::string summary;
    std::string interpretation;
};

struct ProcessFindingConfig {
    std::string ruleset_version;

    bool transient_path_enabled{false};
    std::string transient_path_severity;
    std::vector<std::string> transient_path_prefixes;
    std::vector<std::string> transient_path_substrings;
    rules::RuleExclusion transient_path_exclude;

    bool unexpected_shell_enabled{false};
    std::string unexpected_shell_severity;
    std::vector<std::string> shell_names;
    std::vector<std::string> expected_shell_parent_names;
    rules::RuleExclusion unexpected_shell_exclude;

    bool unexpected_elevation_enabled{false};
    std::string unexpected_elevation_severity;
    std::vector<std::string> expected_elevation_parent_names;
    rules::RuleExclusion unexpected_elevation_exclude;

    bool fanout_enabled{false};
    std::string fanout_severity;
    std::size_t fanout_count{0};
    std::uint64_t fanout_window_ns{0};
    rules::RuleExclusion fanout_exclude;

    bool short_lived_enabled{false};
    std::string short_lived_severity;
    std::size_t short_lived_count{0};
    std::uint64_t short_lived_max_ns{0};
    std::uint64_t short_lived_window_ns{0};
    rules::RuleExclusion short_lived_exclude;
};

class ProcessFindingEngine {
public:
    ProcessFindingEngine();
    explicit ProcessFindingEngine(const RuleSet& rules);
    explicit ProcessFindingEngine(ProcessFindingConfig config);

    [[nodiscard]] std::vector<ProcessFinding> evaluate_snapshot(const ProcessGraph& graph) const;
    [[nodiscard]] std::vector<ProcessFinding> observe(const ProcessExecEvent& event,
                                                      const ProcessGraph& graph);

private:
    using ProcessWindowMap = std::unordered_map<ProcessInstanceKey, std::deque<std::uint64_t>, ProcessInstanceKeyHash>;

    std::vector<ProcessFinding> evaluate_node(const ProcessNode& node,
                                              const std::vector<ProcessNode>& nodes) const;
    ProcessFindingConfig config_;
    std::vector<rules::RuleDefinition> custom_process_rules_;
    std::unordered_map<ProcessInstanceKey, std::uint64_t, ProcessInstanceKeyHash> starts_;
    ProcessWindowMap child_starts_;
    ProcessWindowMap short_exits_;
    std::unordered_map<std::string, ProcessWindowMap> custom_child_starts_;
    std::unordered_map<std::string, ProcessWindowMap> custom_short_exits_;
};

[[nodiscard]] const char* to_string(ProcessFindingSeverity severity) noexcept;
[[nodiscard]] const char* to_string(ProcessFindingKind kind) noexcept;

}  // namespace neta
