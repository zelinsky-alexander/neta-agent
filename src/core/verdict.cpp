#include "neta/verdict.hpp"
#include "neta/crypto.hpp"

#include <algorithm>
#include <sstream>
#include <utility>

namespace neta {
namespace {

constexpr const char* kNetworkRule =
    "|network_path_degradation:rtt_ratio=2.0,rttvar_ratio=2.0,retransmissions=2,weights=0.50/0.20/0.30,threshold=0.50";

void evaluate_performance(AssuranceVerdict& verdict, const Baseline& baseline,
                          const AggregateMetrics& metrics, const RuleSet& rules) {
    if (baseline.sample_count == 0 || baseline.rtt_median_us == 0) {
        verdict.performance = PerformanceState::InsufficientEvidence;
        return;
    }

    double score = 0.0;
    if (metrics.observed_rtt_us >=
        static_cast<std::uint64_t>(static_cast<double>(baseline.rtt_median_us) * rules.rtt_ratio)) {
        score += rules.rtt_weight;
    }
    if (baseline.rttvar_median_us > 0 &&
        metrics.observed_rttvar_us >=
            static_cast<std::uint64_t>(static_cast<double>(baseline.rttvar_median_us) *
                                       rules.rttvar_ratio)) {
        score += rules.rttvar_weight;
    }
    if (metrics.retransmission_delta >= rules.retransmission_threshold) {
        score += rules.retransmission_weight;
    }
    verdict.rule_confidence = score;
    if (score >= rules.degraded_threshold) {
        verdict.performance = PerformanceState::Degraded;
        verdict.performance_hypothesis = "NETWORK_PATH_DEGRADATION";
    } else {
        verdict.performance = PerformanceState::Normal;
    }
}

std::string bool_text(bool value) { return value ? "1" : "0"; }

} // namespace

RuleSet current_rule_set() { return RuleSet{}; }

std::optional<RuleSet> rule_set_for_version(const std::string& version) {
    if (version == kRuleSetVersion) return current_rule_set();
    if (version == kLegacyRuleSetVersion) {
        RuleSet legacy;
        legacy.version = kLegacyRuleSetVersion;
        legacy.inbound_authenticated_identity = false;
        return legacy;
    }
    return std::nullopt;
}

std::string rule_set_canonical(const RuleSet& rules) {
    if (rules.version == kLegacyRuleSetVersion) {
        return std::string(kLegacyRuleSetVersion) + kNetworkRule;
    }

    if (rules.version == kRuleSetVersion) {
        return std::string(kRuleSetVersion) + kNetworkRule +
               "|outbound_tls_identity:supporting_probe,invalid=SUSPICIOUS,spki_change=CHANGED,match=STABLE" +
               "|inbound_mtls_identity:exact_application_session_only,principal=certificate_subject,"
               "accepted_identity=issuer+spki,no_cert=UNVERIFIED,present_not_authenticated=UNVERIFIED,"
               "verification_failure=SUSPICIOUS,authenticated_without_accepted_principal=UNVERIFIED,"
               "accepted_issuer_spki=STABLE,accepted_principal_identity_change=CHANGED";
    }

    return rules.version + kNetworkRule;
}

std::string rule_set_hash(const RuleSet& rules) {
    return sha256_hex(rule_set_canonical(rules));
}

std::string rule_set_canonical() { return rule_set_canonical(current_rule_set()); }

std::string rule_set_hash() { return rule_set_hash(current_rule_set()); }

AggregateMetrics aggregate_metrics(const std::vector<TcpSnapshot>& samples) {
    AggregateMetrics result;
    if (samples.empty()) return result;
    for (const auto& sample : samples) {
        if (sample.rtt_us != 0) {
            result.observed_rtt_us = std::max<std::uint64_t>(result.observed_rtt_us,
                                                             sample.rtt_us);
            result.observed_rttvar_us = std::max<std::uint64_t>(result.observed_rttvar_us,
                                                                 sample.rtt_variance_us);
        }
    }
    const auto first = samples.front().total_retrans;
    const auto last = samples.back().total_retrans;
    result.retransmission_delta = last >= first ? last - first : 0;
    return result;
}

InboundTrustContext inbound_trust_context(const std::vector<TlsSessionEvidence>& evidence) {
    InboundTrustContext context;
    std::vector<const TlsSessionEvidence*> relevant;
    std::vector<const TlsSessionEvidence*> exact;

    for (const auto& item : evidence) {
        const bool inbound_relation =
            item.relation == TlsSessionRelation::InboundTlsSession ||
            item.relation == TlsSessionRelation::InboundClientIdentity;
        if (item.observation.local_role != TlsSessionRole::Server || !inbound_relation) continue;
        relevant.push_back(&item);
        if (item.observation.fidelity == EvidenceFidelity::Exact &&
            item.correlation_fidelity == EvidenceFidelity::Exact) {
            exact.push_back(&item);
        }
    }

    context.tls_session_observed = !relevant.empty();
    if (exact.empty()) {
        std::vector<TlsSessionEvidence> copy;
        copy.reserve(relevant.size());
        for (const auto* item : relevant) copy.push_back(*item);
        context.evidence_hash = tls_session_evidence_set_hash(copy);
        return context;
    }
    if (exact.size() != 1) {
        context.ambiguous = true;
        std::vector<TlsSessionEvidence> copy;
        copy.reserve(exact.size());
        for (const auto* item : exact) copy.push_back(*item);
        context.evidence_hash = tls_session_evidence_set_hash(copy);
        return context;
    }

    const auto& selected = *exact.front();
    const auto& observation = selected.observation;
    context.exact_evidence = true;
    context.peer_certificate_present = observation.peer_certificate_present;
    context.peer_verification_required = observation.peer_verification_required;
    context.verify_result = observation.verify_result;
    context.peer_authenticated = observation.peer_authenticated;
    context.spki_sha256 = observation.spki_sha256;
    context.subject = observation.subject;
    context.issuer = observation.issuer;
    context.evidence_hash = tls_session_evidence_hash(selected);
    return context;
}

std::string inbound_client_baseline_key(const ConnectionSummary& connection,
                                        const std::string& client_subject) {
    if (connection.direction != ConnectionDirection::Inbound || client_subject.empty()) return {};
    const std::string process_identity = !connection.process.executable_path.empty()
        ? "exe=" + connection.process.executable_path
        : !connection.process.comm.empty() ? "comm=" + connection.process.comm : std::string{};
    if (process_identity.empty()) return {};

    std::string canonical = "uid=" + std::to_string(connection.process.uid) + "|" + process_identity;
    if (connection.network_namespace_inode) {
        canonical += "|netns=" + std::to_string(*connection.network_namespace_inode);
    }
    canonical += "|subject=" + client_subject;
    return "inbound-client:" + sha256_hex(canonical);
}

AssuranceVerdict evaluate(const Baseline& baseline, const AggregateMetrics& metrics,
                          const std::optional<TlsObservation>& tls, const RuleSet& rules) {
    AssuranceVerdict verdict;
    verdict.rule_set_version = rules.version;
    verdict.rule_set_hash = rule_set_hash(rules);
    verdict.baseline_hash = baseline.sha256;

    evaluate_performance(verdict, baseline, metrics, rules);

    if (!tls || baseline.accepted_spki_sha256.empty()) {
        verdict.trust = TrustState::Unverified;
    } else if (!tls->chain_valid || !tls->hostname_valid) {
        verdict.trust = TrustState::Suspicious;
        verdict.trust_hypothesis = "TLS_VALIDATION_FAILURE";
    } else if (tls->spki_sha256 != baseline.accepted_spki_sha256) {
        verdict.trust = TrustState::Changed;
        verdict.trust_hypothesis = "TLS_IDENTITY_CHANGE";
    } else {
        verdict.trust = TrustState::Stable;
    }

    std::ostringstream canonical;
    canonical << "baseline=" << baseline.sha256
              << "|rtt=" << metrics.observed_rtt_us
              << "|rttvar=" << metrics.observed_rttvar_us
              << "|retrans=" << metrics.retransmission_delta
              << "|tls=" << (tls ? tls->sha256 : std::string("none"))
              << "|rules=" << verdict.rule_set_hash;
    verdict.input_hash = sha256_hex(canonical.str());
    return verdict;
}

AssuranceVerdict evaluate(const Baseline& baseline, const AggregateMetrics& metrics,
                          const std::optional<TlsObservation>& tls) {
    return evaluate(baseline, metrics, tls, current_rule_set());
}

AssuranceVerdict evaluate_inbound(const std::optional<Baseline>& accepted_identity,
                                  const AggregateMetrics& metrics,
                                  const InboundTrustContext& context,
                                  const RuleSet& rules) {
    AssuranceVerdict verdict;
    verdict.rule_set_version = rules.version;
    verdict.rule_set_hash = rule_set_hash(rules);
    verdict.baseline_hash = accepted_identity ? accepted_identity->sha256 : std::string{};
    verdict.performance = PerformanceState::InsufficientEvidence;

    if (!rules.inbound_authenticated_identity) {
        verdict.trust = TrustState::Unverified;
        verdict.trust_hypothesis = "INBOUND_TRUST_POLICY_UNAVAILABLE";
    } else if (context.ambiguous) {
        verdict.trust = TrustState::Unverified;
        verdict.trust_hypothesis = "INBOUND_CLIENT_IDENTITY_AMBIGUOUS";
    } else if (!context.tls_session_observed) {
        verdict.trust = TrustState::Unverified;
        verdict.trust_hypothesis = "INBOUND_TLS_EVIDENCE_UNAVAILABLE";
    } else if (!context.exact_evidence) {
        verdict.trust = TrustState::Unverified;
        verdict.trust_hypothesis = "INBOUND_TLS_EVIDENCE_NOT_EXACT";
    } else if (!context.peer_certificate_present) {
        verdict.trust = TrustState::Unverified;
        verdict.trust_hypothesis = "INBOUND_CLIENT_CERTIFICATE_ABSENT";
    } else if (context.peer_verification_required && context.verify_result &&
               *context.verify_result != 0) {
        verdict.trust = TrustState::Suspicious;
        verdict.trust_hypothesis = "INBOUND_CLIENT_CERTIFICATE_VERIFICATION_FAILURE";
    } else if (!context.peer_authenticated) {
        verdict.trust = TrustState::Unverified;
        verdict.trust_hypothesis = "INBOUND_CLIENT_CERTIFICATE_NOT_AUTHENTICATED";
    } else if (context.subject.empty()) {
        verdict.trust = TrustState::Unverified;
        verdict.trust_hypothesis = "INBOUND_CLIENT_PRINCIPAL_UNAVAILABLE";
    } else if (!accepted_identity || accepted_identity->accepted_spki_sha256.empty()) {
        verdict.trust = TrustState::Unverified;
        verdict.trust_hypothesis = "INBOUND_CLIENT_IDENTITY_NOT_ACCEPTED";
    } else if (context.spki_sha256 != accepted_identity->accepted_spki_sha256 ||
               (!accepted_identity->accepted_issuer.empty() &&
                context.issuer != accepted_identity->accepted_issuer)) {
        verdict.trust = TrustState::Changed;
        verdict.trust_hypothesis = "INBOUND_CLIENT_IDENTITY_CHANGE";
    } else {
        verdict.trust = TrustState::Stable;
    }

    std::ostringstream canonical;
    canonical << "baseline=" << (accepted_identity ? accepted_identity->sha256 : std::string("none"))
              << "|rtt=" << metrics.observed_rtt_us
              << "|rttvar=" << metrics.observed_rttvar_us
              << "|retrans=" << metrics.retransmission_delta
              << "|direction=INBOUND"
              << "|tls_session=" << (context.evidence_hash.empty() ? "none" : context.evidence_hash)
              << "|tls_observed=" << bool_text(context.tls_session_observed)
              << "|tls_exact=" << bool_text(context.exact_evidence)
              << "|tls_ambiguous=" << bool_text(context.ambiguous)
              << "|peer_cert=" << bool_text(context.peer_certificate_present)
              << "|verify_required=" << bool_text(context.peer_verification_required)
              << "|verify_result="
              << (context.verify_result ? std::to_string(*context.verify_result) : std::string("none"))
              << "|peer_authenticated=" << bool_text(context.peer_authenticated)
              << "|client_subject=" << context.subject
              << "|client_issuer=" << context.issuer
              << "|client_spki=" << context.spki_sha256
              << "|rules=" << verdict.rule_set_hash;
    verdict.input_hash = sha256_hex(canonical.str());
    return verdict;
}

AssuranceVerdict evaluate_inbound(const std::optional<Baseline>& accepted_identity,
                                  const AggregateMetrics& metrics,
                                  const InboundTrustContext& context) {
    return evaluate_inbound(accepted_identity, metrics, context, current_rule_set());
}

} // namespace neta
