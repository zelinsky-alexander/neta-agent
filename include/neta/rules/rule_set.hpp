#pragma once

#include "neta/rules/rule_definition.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace neta {

inline constexpr const char* kLegacyRuleSetVersion = "neta-rules/0.1.0";
inline constexpr const char* kRuleSetVersion = "neta-rules/0.2.0";

struct RuleSet {
    std::string id{"neta-default"};
    std::uint64_t revision{1};
    std::uint64_t schema_version{1};
    std::string version{kRuleSetVersion};

    double rtt_ratio{2.0};
    double rttvar_ratio{2.0};
    std::uint64_t retransmission_threshold{2};
    double rtt_weight{0.50};
    double rttvar_weight{0.20};
    double retransmission_weight{0.30};
    double degraded_threshold{0.50};
    bool inbound_authenticated_identity{true};

    std::vector<rules::RuleDefinition> definitions;
};

} // namespace neta
