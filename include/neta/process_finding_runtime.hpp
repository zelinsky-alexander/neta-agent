#pragma once

#include "neta/fleet_reporting.hpp"
#include "neta/process_finding_store.hpp"

#include <cstddef>
#include <filesystem>
#include <vector>

namespace neta {

struct ProcessFindingReportResult {
    std::size_t considered{0};
    std::size_t announced{0};
    std::size_t failed{0};
};

class ProcessFindingRuntime {
public:
    explicit ProcessFindingRuntime(const std::filesystem::path& database);

    void bootstrap(const std::vector<ProcessExecEvent>& snapshot);
    void observe(const std::vector<ProcessExecEvent>& events);
    ProcessFindingReportResult report_pending(const FleetReportingPolicy& policy,
                                              bool fleet_identity_available);

    [[nodiscard]] ProcessGraph& graph() noexcept { return graph_; }
    [[nodiscard]] const ProcessGraph& graph() const noexcept { return graph_; }
    [[nodiscard]] ProcessFindingStore& store() noexcept { return store_; }

private:
    void persist_current_node(const ProcessExecEvent& event);
    void persist_findings(const std::vector<ProcessFinding>& findings);

    ProcessGraph graph_;
    ProcessFindingEngine engine_;
    ProcessFindingStore store_;
};

}  // namespace neta
