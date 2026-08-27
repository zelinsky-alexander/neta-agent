#pragma once

#include "neta/model.hpp"

#include <optional>
#include <string>
#include <vector>

namespace neta {

inline constexpr const char* kRuleSetVersion = "neta-rules/0.1.0";

std::string rule_set_canonical();
std::string rule_set_hash();

AggregateMetrics aggregate_metrics(const std::vector<TcpSnapshot>& samples);
AssuranceVerdict evaluate(const Baseline& baseline, const AggregateMetrics& metrics,
                          const std::optional<TlsObservation>& tls);

} // namespace neta
