#pragma once

#include "neta/process_graph.hpp"

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
    std::string ruleset_version{"neta-process-rules/0.1.0"};
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
    std::size_t fanout_count{6};
    std::uint64_t fanout_window_ns{10'000'000'000ULL};
    std::size_t short_lived_count{6};
    std::uint64_t short_lived_max_ns{2'000'000'000ULL};
    std::uint64_t short_lived_window_ns{15'000'000'000ULL};
};

class ProcessFindingEngine {
public:
    explicit ProcessFindingEngine(ProcessFindingConfig config = {});

    // Stateless findings over a current graph snapshot.
    [[nodiscard]] std::vector<ProcessFinding> evaluate_snapshot(const ProcessGraph& graph) const;

    // Stateful event-time findings. Call after the graph has observed the event.
    [[nodiscard]] std::vector<ProcessFinding> observe(const ProcessExecEvent& event,
                                                      const ProcessGraph& graph);

private:
    std::vector<ProcessFinding> evaluate_node(const ProcessNode& node,
                                              const std::vector<ProcessNode>& nodes) const;
    ProcessFindingConfig config_;
    std::unordered_map<ProcessInstanceKey, std::uint64_t, ProcessInstanceKeyHash> starts_;
    std::unordered_map<ProcessInstanceKey, std::deque<std::uint64_t>, ProcessInstanceKeyHash> child_starts_;
    std::unordered_map<ProcessInstanceKey, std::deque<std::uint64_t>, ProcessInstanceKeyHash> short_exits_;
};

[[nodiscard]] const char* to_string(ProcessFindingSeverity severity) noexcept;
[[nodiscard]] const char* to_string(ProcessFindingKind kind) noexcept;

}  // namespace neta
