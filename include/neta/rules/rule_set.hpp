#pragma once

#include "neta/rules/rule_definition.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace neta {

inline constexpr const char* kLegacyRuleSetVersion = "neta-rules/0.1.0";
inline constexpr const char* kPreviousRuleSetVersion = "neta-rules/0.2.0";
inline constexpr const char* kRuleSetVersion = "neta-rules/0.3.0";

struct RuleSet {
    std::string id{"neta-default"};
    std::uint64_t revision{2};
    std::uint64_t schema_version{1};
    std::string version{kRuleSetVersion};

    bool performance_enabled{true};
    double rtt_ratio{2.0};
    double rttvar_ratio{2.0};
    std::uint64_t retransmission_threshold{2};
    double rtt_weight{0.50};
    double rttvar_weight{0.20};
    double retransmission_weight{0.30};
    double degraded_threshold{0.50};

    bool outbound_tls_identity{true};
    bool outbound_require_chain_valid{true};
    bool outbound_require_hostname_valid{true};
    bool outbound_compare_spki{true};

    bool inbound_authenticated_identity{true};
    bool inbound_require_exact_evidence{true};
    bool inbound_require_peer_certificate{true};
    bool inbound_require_peer_authentication{true};
    bool inbound_verification_failure_suspicious{true};
    bool inbound_compare_spki{true};
    bool inbound_compare_issuer{true};

    std::vector<rules::RuleDefinition> definitions;

    [[nodiscard]] const rules::RuleDefinition& rule(const std::string& rule_id) const {
        for (const auto& definition : definitions) {
            if (definition.id == rule_id) return definition;
        }
        throw std::runtime_error("rule is not present in rule set: " + rule_id);
    }
};

} // namespace neta
