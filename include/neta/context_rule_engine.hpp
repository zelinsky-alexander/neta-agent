#pragma once

#include "neta/model.hpp"
#include "neta/name_resolution.hpp"
#include "neta/rules/rule_set.hpp"
#include "neta/tls_session.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neta {

struct ContextRuleMatch {
    std::string rule_id;
    std::string engine_rule_id;
    std::string category;
    std::string severity;
    std::string semantic_type;
    std::string summary;
    std::string interpretation;
};

struct ConnectionRuleContext {
    ConnectionSummary connection;
    AggregateMetrics metrics;
    std::optional<Baseline> baseline;
    std::vector<NameResolutionEvidence> name_resolution;
    std::vector<TlsSessionEvidence> tls_sessions;
    std::optional<RouteObservation> route;
    std::optional<std::uint64_t> bytes_sent;
    std::optional<std::uint64_t> bytes_received;
    std::optional<std::uint64_t> destination_prevalence;
};

class ContextRuleEngine {
public:
    explicit ContextRuleEngine(const RuleSet& rules);

    [[nodiscard]] std::vector<ContextRuleMatch> evaluate(
        const ConnectionRuleContext& context) const;

private:
    const RuleSet& rules_;
};

}  // namespace neta
