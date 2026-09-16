#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace neta {

struct RuleControlDecision {
    bool present{false};
    bool fetch_required{false};
    bool refresh_requested{false};
    std::uint64_t desired_revision{0};
    std::string desired_sha256;
};

RuleControlDecision parse_rule_control_response(const std::string& response_body);

// Consumes only the bounded desired-rule state advertised by AgentHello/Heartbeat.
// If convergence is needed, launches an external local rules-update worker so the
// running service never restarts itself from inside the heartbeat callback.
bool accept_rule_control_from_coordinator_response(const std::filesystem::path& state_dir,
                                                   const std::string& response_body);

} // namespace neta
