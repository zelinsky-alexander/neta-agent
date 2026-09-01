#pragma once

#include "neta/fleet_client.hpp"
#include "neta/history_store.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace neta {

enum class FleetReportingMode { Off, SignificantOnly, AllFindings };

struct FleetReportingPolicy {
    FleetReportingMode mode{FleetReportingMode::SignificantOnly};
    double minimum_confidence{0.80};
    std::chrono::seconds cooldown{1800};
    std::filesystem::path state_dir{"/var/lib/neta/identity"};
};

struct FleetReportingResult {
    std::size_t considered{0};
    std::size_t announced{0};
    std::size_t suppressed_policy{0};
    std::size_t suppressed_cooldown{0};
    std::size_t failed{0};
};

FleetReportingPolicy fleet_reporting_policy_from_environment();
FindingAnnouncementInput finding_from_connection(HistoryStore& store, std::int64_t connection_id);
bool finding_matches_reporting_policy(const ExportData& data, const FleetReportingPolicy& policy);
FleetReportingResult auto_report_connections(HistoryStore& store,
                                             const std::vector<std::int64_t>& connection_ids,
                                             const FleetReportingPolicy& policy);

} // namespace neta
