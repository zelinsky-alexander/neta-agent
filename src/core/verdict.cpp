#include "neta/verdict.hpp"
#include "neta/crypto.hpp"

#include <algorithm>
#include <sstream>

namespace neta {

std::string rule_set_canonical() {
    return std::string(kRuleSetVersion) +
           "|network_path_degradation:rtt_ratio=2.0,rttvar_ratio=2.0,retransmissions=2,weights=0.50/0.20/0.30,threshold=0.50";
}

std::string rule_set_hash() { return sha256_hex(rule_set_canonical()); }

AggregateMetrics aggregate_metrics(const std::vector<TcpSnapshot>& samples) {
    AggregateMetrics result;
    if (samples.empty()) return result;
    for (const auto& sample : samples) {
        result.observed_rtt_us = std::max<std::uint64_t>(result.observed_rtt_us, sample.rtt_us);
        result.observed_rttvar_us = std::max<std::uint64_t>(result.observed_rttvar_us, sample.rtt_variance_us);
    }
    const auto first = samples.front().total_retrans;
    const auto last = samples.back().total_retrans;
    result.retransmission_delta = last >= first ? last - first : 0;
    return result;
}

AssuranceVerdict evaluate(const Baseline& baseline, const AggregateMetrics& metrics,
                          const std::optional<TlsObservation>& tls) {
    AssuranceVerdict verdict;
    verdict.rule_set_version = kRuleSetVersion;
    verdict.rule_set_hash = rule_set_hash();
    verdict.baseline_hash = baseline.sha256;

    if (baseline.sample_count == 0 || baseline.rtt_median_us == 0) {
        verdict.performance = PerformanceState::InsufficientEvidence;
    } else {
        double score = 0.0;
        if (metrics.observed_rtt_us >= baseline.rtt_median_us * 2ULL) score += 0.50;
        if (baseline.rttvar_median_us > 0 &&
            metrics.observed_rttvar_us >= baseline.rttvar_median_us * 2ULL) score += 0.20;
        if (metrics.retransmission_delta >= 2) score += 0.30;
        verdict.rule_confidence = score;
        if (score >= 0.50) {
            verdict.performance = PerformanceState::Degraded;
            verdict.performance_hypothesis = "NETWORK_PATH_DEGRADATION";
        } else {
            verdict.performance = PerformanceState::Normal;
        }
    }

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

} // namespace neta
