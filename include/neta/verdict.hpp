#pragma once

#include "neta/model.hpp"
#include "neta/tls_session.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neta {

inline constexpr const char* kLegacyRuleSetVersion = "neta-rules/0.1.0";
inline constexpr const char* kRuleSetVersion = "neta-rules/0.2.0";

struct RuleSet {
    std::string version{kRuleSetVersion};
    double rtt_ratio{2.0};
    double rttvar_ratio{2.0};
    std::uint64_t retransmission_threshold{2};
    double rtt_weight{0.50};
    double rttvar_weight{0.20};
    double retransmission_weight{0.30};
    double degraded_threshold{0.50};
    bool inbound_authenticated_identity{true};
};

struct InboundTrustContext {
    bool tls_session_observed{false};
    bool exact_evidence{false};
    bool ambiguous{false};
    bool peer_certificate_present{false};
    bool peer_verification_required{false};
    std::optional<std::int64_t> verify_result;
    bool peer_authenticated{false};
    std::string spki_sha256;
    std::string subject;
    std::string issuer;
    std::string evidence_hash;
};

RuleSet current_rule_set();
std::optional<RuleSet> rule_set_for_version(const std::string& version);
std::string rule_set_canonical(const RuleSet& rules);
std::string rule_set_hash(const RuleSet& rules);
std::string rule_set_canonical();
std::string rule_set_hash();

AggregateMetrics aggregate_metrics(const std::vector<TcpSnapshot>& samples);
InboundTrustContext inbound_trust_context(const std::vector<TlsSessionEvidence>& evidence);
std::string inbound_client_baseline_key(const ConnectionSummary& connection,
                                        const std::string& client_subject);

AssuranceVerdict evaluate(const Baseline& baseline, const AggregateMetrics& metrics,
                          const std::optional<TlsObservation>& tls, const RuleSet& rules);
AssuranceVerdict evaluate(const Baseline& baseline, const AggregateMetrics& metrics,
                          const std::optional<TlsObservation>& tls);

AssuranceVerdict evaluate_inbound(const std::optional<Baseline>& accepted_identity,
                                  const AggregateMetrics& metrics,
                                  const InboundTrustContext& context,
                                  const RuleSet& rules);
AssuranceVerdict evaluate_inbound(const std::optional<Baseline>& accepted_identity,
                                  const AggregateMetrics& metrics,
                                  const InboundTrustContext& context);

} // namespace neta
