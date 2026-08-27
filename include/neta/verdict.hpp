#pragma once

#include "neta/model.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neta {

inline constexpr const char* kRuleSetVersion = "neta-rules/0.1.0";

struct RuleSet {
    std::string version{kRuleSetVersion};
    double rtt_ratio{2.0};
    double rttvar_ratio{2.0};
    std::uint64_t retransmission_threshold{2};
    double rtt_weight{0.50};
    double rttvar_weight{0.20};
    double retransmission_weight{0.30};
    double degraded_threshold{0.50};
};

RuleSet current_rule_set();
std::string rule_set_canonical(const RuleSet& rules);
std::string rule_set_hash(const RuleSet& rules);
std::string rule_set_canonical();
std::string rule_set_hash();

AggregateMetrics aggregate_metrics(const std::vector<TcpSnapshot>& samples);
AssuranceVerdict evaluate(const Baseline& baseline, const AggregateMetrics& metrics,
                          const std::optional<TlsObservation>& tls, const RuleSet& rules);
AssuranceVerdict evaluate(const Baseline& baseline, const AggregateMetrics& metrics,
                          const std::optional<TlsObservation>& tls);

} // namespace neta
