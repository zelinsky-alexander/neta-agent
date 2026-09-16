#pragma once

#include "neta/fleet_client.hpp"
#include "neta/outbound_dispatcher.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace neta {

class ReliableFleetClient {
public:
    static bool submit_finding(const std::filesystem::path& database,
                               const std::filesystem::path& state_dir,
                               const FindingAnnouncementInput& finding);
    static bool submit_evidence_summary(const std::filesystem::path& database,
                                        const std::filesystem::path& state_dir,
                                        const std::string& producer_key,
                                        const std::string& summary_json);
    static OutboundDispatchResult drain(const std::filesystem::path& database,
                                        const std::filesystem::path& state_dir,
                                        std::size_t maximum_messages = 32);
    static OutboundQueueStatus status(const std::filesystem::path& database,
                                      const std::filesystem::path& state_dir);
};

}  // namespace neta
