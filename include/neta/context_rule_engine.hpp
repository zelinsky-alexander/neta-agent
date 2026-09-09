#pragma once

#include "neta/model.hpp"
#include "neta/name_resolution.hpp"
#include "neta/rules/rule_set.hpp"
#include "neta/tls_session.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace neta {

struct ContextRuleMatch {
    std::string rule_id;
    std::string engine_rule_id;
    std::string category;
    std::string severity;
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

namespace context_rule_detail {

inline std::vector<std::string> correlated_domains(const std::vector<NameResolutionEvidence>& evidence) {
    std::vector<std::string> result;
    for (const auto& item : evidence) {
        if (!item.observation.query_name.empty()) result.push_back(item.observation.query_name);
        if (item.observation.canonical_name && !item.observation.canonical_name->empty())
            result.push_back(*item.observation.canonical_name);
    }
    return result;
}

inline bool port_allowed(const rules::RuleDefinition& rule, std::uint16_t port) {
    const auto& allowed = rule.string_list("allowed_ports");
    const auto text = std::to_string(port);
    return std::find(allowed.begin(), allowed.end(), text) != allowed.end();
}

inline const TlsSessionEvidence* exact_outbound_tls(const std::vector<TlsSessionEvidence>& evidence) {
    for (const auto& item : evidence) {
        if (item.correlation_fidelity != EvidenceFidelity::Exact) continue;
        if (item.relation == TlsSessionRelation::OutboundServerIdentity ||
            item.relation == TlsSessionRelation::OutboundTlsSession) return &item;
    }
    return nullptr;
}

inline std::size_t failed_dns_count(const std::vector<NameResolutionEvidence>& evidence) {
    std::size_t count = 0;
    for (const auto& item : evidence)
        if (item.observation.result_code && *item.observation.result_code != 0) ++count;
    return count;
}

inline bool dns_contains_remote(const ConnectionRuleContext& context) {
    if (context.connection.remote_ip.empty()) return false;
    bool had_forward_answer = false;
    for (const auto& item : context.name_resolution) {
        if (item.observation.query_kind != NameResolutionQueryKind::Forward) continue;
        if (item.correlation_fidelity != EvidenceFidelity::Exact &&
            item.correlation_fidelity != EvidenceFidelity::StronglyCorrelated) continue;
        for (const auto& address : item.observation.addresses) {
            had_forward_answer = true;
            if (address.address == context.connection.remote_ip ||
                (context.connection.remote_ip.starts_with("::ffff:") &&
                 address.address == context.connection.remote_ip.substr(7))) return true;
        }
    }
    return !had_forward_answer;
}

inline std::size_t distinct_dns_answers(const std::vector<NameResolutionEvidence>& evidence) {
    std::set<std::string> answers;
    for (const auto& item : evidence) {
        if (item.observation.query_kind != NameResolutionQueryKind::Forward) continue;
        for (const auto& address : item.observation.addresses) answers.insert(address.address);
    }
    return answers.size();
}

inline bool list_contains(const std::vector<std::string>& values, const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

inline ContextRuleMatch match(const rules::RuleDefinition& rule,
                              std::string summary,
                              std::string interpretation) {
    return ContextRuleMatch{rule.id, rule.engine_rule_id, rule.category, rule.severity,
                            std::move(summary), std::move(interpretation)};
}

inline std::optional<ContextRuleMatch> evaluate_one(const rules::RuleDefinition& rule,
                                                     const ConnectionRuleContext& context) {
    if (!rule.enabled) return std::nullopt;
    const auto domains = correlated_domains(context.name_resolution);
    if (rules::excludes_connection(rule.exclude, context.connection, domains)) return std::nullopt;
    const auto& engine = rule.engine_rule_id;

    if (engine == "NETA-NET-002") {
        const auto threshold = static_cast<std::uint64_t>(rule.numeric("retransmission_threshold"));
        if (context.metrics.retransmission_delta >= threshold)
            return match(rule,"TCP retransmissions exceeded the configured rule threshold.",
                "Repeated retransmissions can indicate path degradation, packet loss, interference, or deliberate disruption; malicious intent is not established.");
        return std::nullopt;
    }
    if (engine == "NETA-NET-003") {
        if (context.connection.direction != ConnectionDirection::Outbound || context.connection.remote_port == 0) return std::nullopt;
        if (!port_allowed(rule, context.connection.remote_port))
            return match(rule,"Outbound connection used a destination port outside the configured allowlist.",
                "An unusual destination port can be legitimate application behavior or a sign of tunneling/custom protocol use; malicious intent is not established.");
        return std::nullopt;
    }
    if (engine == "NETA-NET-004") {
        if (context.connection.direction != ConnectionDirection::Outbound || !context.destination_prevalence) return std::nullopt;
        const auto maximum = static_cast<std::uint64_t>(rule.numeric("maximum_prevalence"));
        if (*context.destination_prevalence <= maximum)
            return match(rule,"Outbound connection targeted a destination with low local prevalence.",
                "Rare destinations deserve additional context, especially when combined with process, DNS, TLS, or transfer anomalies; rarity alone is not malicious.");
        return std::nullopt;
    }
    if (engine == "NETA-DNS-001") {
        const auto minimum = static_cast<std::size_t>(rule.numeric("minimum_failures"));
        if (failed_dns_count(context.name_resolution) >= minimum)
            return match(rule,"Correlated DNS activity contained repeated resolution failures.",
                "Repeated resolver failures can result from outages, stale configuration, blocked domains, or generated-domain behavior; malicious intent is not established.");
        return std::nullopt;
    }
    if (engine == "NETA-DNS-002") {
        if (context.connection.direction != ConnectionDirection::Outbound || context.name_resolution.empty()) return std::nullopt;
        if (rule.boolean("require_remote_ip_match") && !dns_contains_remote(context))
            return match(rule,"Correlated DNS answers did not contain the remote address used by the connection.",
                "A DNS-to-connection mismatch may indicate stale correlation, proxying, address rewriting, or unexpected name resolution behavior and should be investigated.");
        return std::nullopt;
    }
    if (engine == "NETA-DNS-003") {
        const auto maximum = static_cast<std::size_t>(rule.numeric("maximum_distinct_answers"));
        if (distinct_dns_answers(context.name_resolution) > maximum)
            return match(rule,"Correlated DNS evidence contained more distinct answers than the configured limit.",
                "High DNS answer churn can be normal for CDNs but can also accompany fast-flux or rapidly changing infrastructure; malicious intent is not established.");
        return std::nullopt;
    }
    if (engine == "NETA-TLS-001") {
        const auto* tls = exact_outbound_tls(context.tls_sessions); if (!tls) return std::nullopt;
        bool bad = false;
        if (rule.boolean("require_peer_authentication") && !tls->observation.peer_authenticated) bad = true;
        if (rule.boolean("verification_failure_match") && tls->observation.verify_result && *tls->observation.verify_result != 0) bad = true;
        if (bad)
            return match(rule,"Exact application TLS evidence failed the configured validation/authentication policy.",
                "A failed or unauthenticated TLS peer can reflect interception, misconfiguration, certificate problems, or an untrusted endpoint and warrants investigation.");
        return std::nullopt;
    }
    if (engine == "NETA-TLS-002") {
        const auto* tls = exact_outbound_tls(context.tls_sessions); if (!tls || !context.baseline) return std::nullopt;
        bool changed = false;
        if (rule.boolean("compare_spki") && !context.baseline->accepted_spki_sha256.empty() && context.baseline->accepted_spki_sha256 != tls->observation.spki_sha256) changed = true;
        if (rule.boolean("compare_issuer") && !context.baseline->accepted_issuer.empty() && context.baseline->accepted_issuer != tls->observation.issuer) changed = true;
        if (changed)
            return match(rule,"TLS peer identity differed from the accepted baseline.",
                "A changed TLS identity can result from legitimate certificate rotation, load-balancer changes, interception, or endpoint replacement and should be verified.");
        return std::nullopt;
    }
    if (engine == "NETA-ROUTE-001") {
        if (!context.route) return std::nullopt;
        const auto& gateways = rule.string_list("allowed_gateways");
        const auto& interfaces = rule.string_list("allowed_interfaces");
        bool unexpected = false;
        if (!gateways.empty() && !list_contains(gateways, context.route->gateway)) unexpected = true;
        if (!interfaces.empty() && !list_contains(interfaces, context.route->interface_name)) unexpected = true;
        if (unexpected)
            return match(rule,"Observed route used a gateway or interface outside the configured allowlist.",
                "Unexpected route selection can result from VPNs, failover, local reconfiguration, or traffic redirection and should be correlated with host/network changes.");
        return std::nullopt;
    }
    return std::nullopt;
}

} // namespace context_rule_detail

class ContextRuleEngine {
public:
    explicit ContextRuleEngine(const RuleSet& rules) : rules_(rules) {}
    [[nodiscard]] std::vector<ContextRuleMatch> evaluate(const ConnectionRuleContext& context) const {
        std::vector<ContextRuleMatch> matches;
        for (const auto& rule : rules_.definitions)
            if (auto result = context_rule_detail::evaluate_one(rule, context)) matches.push_back(std::move(*result));
        return matches;
    }
private:
    const RuleSet& rules_;
};

} // namespace neta
