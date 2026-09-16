#include "neta/outbound_baseline.hpp"

#include "neta/crypto.hpp"
#include "neta/tls_session.hpp"
#include "neta/verdict.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

namespace neta {
namespace {

std::string target_host(const ConnectionSummary& connection) {
    return !connection.target_host.empty() ? connection.target_host : connection.remote_ip;
}

std::uint64_t median(std::vector<std::uint64_t> values) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const auto middle = values.size() / 2;
    return values.size() % 2 != 0
        ? values[middle]
        : (values[middle - 1] + values[middle]) / 2;
}

std::uint64_t wall_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

const TlsSessionEvidence* exact_outbound_identity(
    const std::vector<TlsSessionEvidence>& evidence) {
    for (const auto& item : evidence) {
        if (item.correlation_fidelity != EvidenceFidelity::Exact ||
            item.observation.fidelity != EvidenceFidelity::Exact) {
            continue;
        }
        if (item.relation == TlsSessionRelation::OutboundServerIdentity) return &item;
    }
    return nullptr;
}

std::optional<TlsObservation> exact_tls_observation(
    const ConnectionSummary& connection,
    const std::vector<TlsSessionEvidence>& evidence) {
    const auto* exact = exact_outbound_identity(evidence);
    if (exact == nullptr) return std::nullopt;
    const auto& session = exact->observation;

    TlsObservation observation;
    observation.target_host = target_host(connection);
    observation.target_port = connection.remote_port;
    observation.observed_ns = session.observed_ns;
    observation.tls_version = session.tls_version;
    observation.cipher = session.cipher;
    observation.alpn = session.alpn;
    observation.leaf_sha256 = session.leaf_sha256;
    observation.spki_sha256 = session.spki_sha256;
    observation.subject = session.subject;
    observation.issuer = session.issuer;
    observation.not_before = session.not_before;
    observation.not_after = session.not_after;
    observation.chain_valid = session.peer_authenticated &&
        (!session.verify_result || *session.verify_result == 0);
    observation.hostname_valid = session.expected_peer_name &&
        session.matched_peer_name &&
        *session.expected_peer_name == *session.matched_peer_name;
    observation.sha256 = tls_session_evidence_hash(*exact);
    return observation;
}

} // namespace

Baseline accept_outbound_connection_baseline(HistoryStore& store,
                                             std::int64_t connection_id) {
    const auto connection = store.connection(connection_id);
    if (!connection) throw std::runtime_error("connection not found");
    if (connection->direction != ConnectionDirection::Outbound) {
        throw std::runtime_error("outbound baselines require an OUTBOUND connection");
    }
    const auto host = target_host(*connection);
    if (host.empty() || connection->remote_port == 0) {
        throw std::runtime_error("connection has no stable remote target");
    }

    const auto samples = store.recent_samples_for_target(host, connection->remote_port, 200);
    std::vector<std::uint64_t> rtts;
    std::vector<std::uint64_t> rtt_variances;
    for (const auto& sample : samples) {
        if (sample.rtt_us == 0) continue;
        rtts.push_back(sample.rtt_us);
        if (sample.rtt_variance_us != 0) rtt_variances.push_back(sample.rtt_variance_us);
    }
    if (rtts.size() < 5) {
        throw std::runtime_error(
            "outbound baseline requires at least 5 persisted RTT-bearing target samples");
    }

    const auto tls = exact_tls_observation(
        *connection, store.tls_session_evidence_for_connection(connection_id));
    if (tls && (!tls->chain_valid || !tls->hostname_valid || tls->spki_sha256.empty())) {
        throw std::runtime_error(
            "refusing to accept invalid or incomplete exact TLS server identity");
    }

    Baseline baseline;
    baseline.target_host = host;
    baseline.target_port = connection->remote_port;
    baseline.rtt_median_us = median(rtts);
    baseline.rttvar_median_us = median(rtt_variances);
    baseline.sample_count = samples.size();
    baseline.created_ns = wall_now_ns();
    if (tls) {
        baseline.accepted_spki_sha256 = tls->spki_sha256;
        baseline.accepted_issuer = tls->issuer;
    }
    baseline.sha256 = sha256_hex(
        baseline.target_host + ':' + std::to_string(baseline.target_port) + '|' +
        std::to_string(baseline.rtt_median_us) + '|' +
        std::to_string(baseline.rttvar_median_us) + '|' +
        baseline.accepted_spki_sha256 + '|' + baseline.accepted_issuer + '|' +
        std::to_string(baseline.sample_count));
    store.save_baseline(baseline);

    const auto verdict = evaluate(
        baseline, aggregate_metrics(store.samples_for_connection(connection_id)), tls);
    store.save_verdict(connection_id, verdict);
    return baseline;
}

std::optional<AssuranceVerdict> evaluate_outbound_connection(
    HistoryStore& store, std::int64_t connection_id) {
    const auto connection = store.connection(connection_id);
    if (!connection || connection->direction != ConnectionDirection::Outbound) {
        return std::nullopt;
    }
    const auto baseline = store.baseline_for(target_host(*connection), connection->remote_port);
    if (!baseline) return std::nullopt;

    const auto tls = exact_tls_observation(
        *connection, store.tls_session_evidence_for_connection(connection_id));
    const auto verdict = evaluate(
        *baseline, aggregate_metrics(store.samples_for_connection(connection_id)), tls);
    store.save_verdict(connection_id, verdict);
    return verdict;
}

} // namespace neta
