#include "neta/tls_session.hpp"

#include "neta/crypto.hpp"

#include <algorithm>
#include <utility>

namespace neta {
namespace {

bool valid_cookie(const std::optional<std::uint64_t>& cookie) {
    return cookie && *cookie != 0 && *cookie != ~std::uint64_t{0};
}

ConnectionDirection direction_for(TlsSessionRole role) {
    switch (role) {
        case TlsSessionRole::Client: return ConnectionDirection::Outbound;
        case TlsSessionRole::Server: return ConnectionDirection::Inbound;
        case TlsSessionRole::Unknown: return ConnectionDirection::Unknown;
    }
    return ConnectionDirection::Unknown;
}

bool same_process(const TlsSessionObservation& observation,
                  const ConnectionSummary& connection) {
    if (observation.process.pid < 0 || connection.process.pid < 0 ||
        observation.process.pid != connection.process.pid) {
        return false;
    }
    if (observation.process.start_ticks && connection.process.start_ticks &&
        *observation.process.start_ticks != *connection.process.start_ticks) {
        return false;
    }
    return true;
}

bool same_namespace(const TlsSessionObservation& observation,
                    const ConnectionSummary& connection) {
    return !observation.network_namespace_inode || !connection.network_namespace_inode ||
           *observation.network_namespace_inode == *connection.network_namespace_inode;
}

bool same_tuple(const TlsSessionObservation& observation,
                const ConnectionSummary& connection) {
    return observation.local.address == connection.local_ip &&
           observation.local.port == connection.local_port &&
           observation.remote.address == connection.remote_ip &&
           observation.remote.port == connection.remote_port;
}

bool within_connection_time(const TlsSessionObservation& observation,
                            const ConnectionSummary& connection,
                            const TlsSessionCorrelationPolicy& policy,
                            bool cookie_match) {
    if (observation.observed_ns == 0 || connection.first_seen_ns == 0 ||
        observation.observed_ns < connection.first_seen_ns) {
        return false;
    }
    if (connection.lifecycle_state == "CLOSED" && connection.last_seen_ns != 0 &&
        observation.observed_ns > connection.last_seen_ns) {
        return false;
    }
    if (!cookie_match && observation.observed_ns - connection.first_seen_ns >
                             policy.tuple_max_age_ns) {
        return false;
    }
    return true;
}

enum class CandidateKind { None, AwaitingIdentity, Exact, Tuple };

CandidateKind candidate_kind(const TlsSessionObservation& observation,
                             const ConnectionSummary& connection,
                             const TlsSessionCorrelationPolicy& policy) {
    const auto direction = direction_for(observation.local_role);
    if (direction == ConnectionDirection::Unknown || connection.direction != direction) {
        return CandidateKind::None;
    }
    if (!same_process(observation, connection) || !same_namespace(observation, connection)) {
        return CandidateKind::None;
    }

    if (valid_cookie(observation.socket_cookie)) {
        if (connection.socket_cookie != 0) {
            if (*observation.socket_cookie != connection.socket_cookie) {
                return CandidateKind::None;
            }
            return within_connection_time(observation, connection, policy, true)
                ? CandidateKind::Exact : CandidateKind::None;
        }
        // A tuple match identifies a connection whose canonical identity may become
        // exact later. It is deliberately not sufficient to attach cookie-bearing
        // evidence weakly.
        if (!same_tuple(observation, connection)) return CandidateKind::None;
        return within_connection_time(observation, connection, policy, false)
            ? CandidateKind::AwaitingIdentity : CandidateKind::None;
    }
    if (!same_tuple(observation, connection)) return CandidateKind::None;
    return within_connection_time(observation, connection, policy, false)
        ? CandidateKind::Tuple : CandidateKind::None;
}

TlsSessionRelation relation_for(const TlsSessionObservation& observation) {
    if (observation.local_role == TlsSessionRole::Client) {
        return observation.peer_certificate_present
            ? TlsSessionRelation::OutboundServerIdentity
            : TlsSessionRelation::OutboundTlsSession;
    }
    if (observation.local_role == TlsSessionRole::Server) {
        return observation.peer_certificate_present
            ? TlsSessionRelation::InboundClientIdentity
            : TlsSessionRelation::InboundTlsSession;
    }
    return TlsSessionRelation::Unknown;
}

EvidenceFidelity correlation_fidelity(const TlsSessionObservation& observation,
                                      bool cookie_match) {
    if (observation.fidelity == EvidenceFidelity::Contextual) {
        return EvidenceFidelity::Contextual;
    }
    if (observation.fidelity == EvidenceFidelity::Supporting) {
        return EvidenceFidelity::Supporting;
    }
    return cookie_match ? EvidenceFidelity::Exact
                        : EvidenceFidelity::StronglyCorrelated;
}

void append_optional(std::string& out, const std::optional<std::string>& value) {
    out += value.value_or("");
}

void append_optional(std::string& out, const std::optional<std::uint64_t>& value) {
    if (value) out += std::to_string(*value);
}

void append_optional(std::string& out, const std::optional<std::int64_t>& value) {
    if (value) out += std::to_string(*value);
}

std::string canonical_observation(const TlsSessionObservation& observation,
                                  bool include_observed_ns) {
    std::string material;
    if (include_observed_ns) material += std::to_string(observation.observed_ns);
    material += "|" + to_string(observation.local_role) + "|";
    material += std::to_string(observation.process.pid) + "|";
    material += std::to_string(observation.process.uid) + "|";
    append_optional(material, observation.process.start_ticks);
    material += "|" + observation.process.comm + "|";
    append_optional(material, observation.network_namespace_inode);
    material += "|";
    append_optional(material, observation.socket_cookie);
    material += "|" + observation.local.address + ":" + std::to_string(observation.local.port) +
                "->" + observation.remote.address + ":" + std::to_string(observation.remote.port) +
                "|" + observation.tls_version + "|" + observation.cipher + "|" +
                observation.alpn + "|" + observation.sni + "|";
    append_optional(material, observation.expected_peer_name);
    material += "|";
    append_optional(material, observation.matched_peer_name);
    material += "|" + std::to_string(observation.peer_certificate_present) + "|" +
                std::to_string(observation.peer_verification_required) + "|";
    append_optional(material, observation.verify_result);
    material += "|" + std::to_string(observation.peer_authenticated) + "|" +
                observation.leaf_sha256 + "|" + observation.spki_sha256 + "|" +
                observation.subject + "|" + observation.issuer + "|" +
                observation.not_before + "|" + observation.not_after + "|" +
                to_string(observation.fidelity) + "|" + observation.source;
    return material;
}

} // namespace

std::string to_string(TlsSessionRole value) {
    switch (value) {
        case TlsSessionRole::Client: return "CLIENT";
        case TlsSessionRole::Server: return "SERVER";
        case TlsSessionRole::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string to_string(TlsSessionRelation value) {
    switch (value) {
        case TlsSessionRelation::OutboundTlsSession: return "OUTBOUND_TLS_SESSION";
        case TlsSessionRelation::OutboundServerIdentity: return "OUTBOUND_SERVER_IDENTITY";
        case TlsSessionRelation::InboundTlsSession: return "INBOUND_TLS_SESSION";
        case TlsSessionRelation::InboundClientIdentity: return "INBOUND_CLIENT_IDENTITY";
        case TlsSessionRelation::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string to_string(TlsSessionCorrelationStatus value) {
    switch (value) {
        case TlsSessionCorrelationStatus::NoMatch: return "NO_MATCH";
        case TlsSessionCorrelationStatus::AwaitingIdentity: return "AWAITING_IDENTITY";
        case TlsSessionCorrelationStatus::Matched: return "MATCHED";
        case TlsSessionCorrelationStatus::Ambiguous: return "AMBIGUOUS";
    }
    return "NO_MATCH";
}

TlsSessionRole tls_session_role_from_string(const std::string& value) {
    if (value == "CLIENT") return TlsSessionRole::Client;
    if (value == "SERVER") return TlsSessionRole::Server;
    return TlsSessionRole::Unknown;
}

TlsSessionRelation tls_session_relation_from_string(const std::string& value) {
    if (value == "OUTBOUND_TLS_SESSION") return TlsSessionRelation::OutboundTlsSession;
    if (value == "OUTBOUND_SERVER_IDENTITY") return TlsSessionRelation::OutboundServerIdentity;
    if (value == "INBOUND_TLS_SESSION") return TlsSessionRelation::InboundTlsSession;
    if (value == "INBOUND_CLIENT_IDENTITY") return TlsSessionRelation::InboundClientIdentity;
    return TlsSessionRelation::Unknown;
}

TlsSessionCorrelationResult correlate_tls_session(
    const TlsSessionObservation& observation,
    const std::vector<ConnectionSummary>& connections,
    const TlsSessionCorrelationPolicy& policy) {
    TlsSessionCorrelationResult result;
    const ConnectionSummary* match = nullptr;
    bool matched_by_cookie = false;
    std::size_t awaiting_identity_count = 0;
    for (const auto& connection : connections) {
        const auto kind = candidate_kind(observation, connection, policy);
        if (kind == CandidateKind::AwaitingIdentity) {
            ++awaiting_identity_count;
            continue;
        }
        if (kind == CandidateKind::None) continue;
        ++result.candidate_count;
        if (!match) {
            match = &connection;
            matched_by_cookie = kind == CandidateKind::Exact;
        }
    }
    if (result.candidate_count == 0 && awaiting_identity_count != 0) {
        result.candidate_count = awaiting_identity_count;
        result.status = awaiting_identity_count == 1
            ? TlsSessionCorrelationStatus::AwaitingIdentity
            : TlsSessionCorrelationStatus::Ambiguous;
        return result;
    }
    if (result.candidate_count == 0) return result;
    if (result.candidate_count != 1 || !match) {
        result.status = TlsSessionCorrelationStatus::Ambiguous;
        return result;
    }

    result.status = TlsSessionCorrelationStatus::Matched;
    result.connection_id = match->id;
    TlsSessionEvidence evidence;
    evidence.observation = observation;
    evidence.relation = relation_for(observation);
    evidence.correlation_fidelity = correlation_fidelity(observation, matched_by_cookie);
    result.evidence = std::move(evidence);
    return result;
}

std::string tls_session_identity_key(const TlsSessionObservation& observation) {
    return sha256_hex(canonical_observation(observation, false));
}

std::string tls_session_evidence_hash(const TlsSessionEvidence& evidence) {
    return sha256_hex(canonical_observation(evidence.observation, true) + "|" +
                      to_string(evidence.relation) + "|" +
                      to_string(evidence.correlation_fidelity));
}

std::string tls_session_evidence_set_hash(const std::vector<TlsSessionEvidence>& evidence) {
    if (evidence.empty()) return {};
    std::vector<std::string> hashes;
    hashes.reserve(evidence.size());
    for (const auto& item : evidence) hashes.push_back(tls_session_evidence_hash(item));
    std::sort(hashes.begin(), hashes.end());
    std::string material;
    for (const auto& hash : hashes) {
        if (!material.empty()) material.push_back('|');
        material += hash;
    }
    return sha256_hex(material);
}

} // namespace neta
