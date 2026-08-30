#include "neta/name_resolution.hpp"

#include <algorithm>
#include <utility>

namespace neta {
namespace {

std::optional<std::int64_t> agent_process_id(const LifecycleProcessContext& process) {
    if (process.agent_visible.tgid) return process.agent_visible.tgid;
    return process.agent_visible.pid;
}

bool contains_remote_address(const NameResolutionObservation& observation,
                             const std::string& remote_ip) {
    return std::any_of(observation.addresses.begin(), observation.addresses.end(),
                       [&](const NameResolutionAddress& address) {
                           return address.address == remote_ip;
                       });
}

bool is_candidate(const ConnectionSummary& connection,
                  const NameResolutionObservation& observation,
                  const NameResolutionCorrelationPolicy& policy) {
    if (connection.direction != ConnectionDirection::Outbound) return false;
    if (observation.query_kind != NameResolutionQueryKind::Forward) return false;
    if (connection.first_seen_ns == 0 || observation.completed_ns == 0) return false;
    if (observation.started_ns != 0 && observation.started_ns > observation.completed_ns) return false;
    if (observation.completed_ns > connection.first_seen_ns) return false;
    if (connection.first_seen_ns - observation.completed_ns > policy.max_age_ns) return false;
    if (observation.query_name.empty() || !contains_remote_address(observation, connection.remote_ip)) {
        return false;
    }

    const auto observed_process_id = agent_process_id(observation.process);
    if (!observed_process_id || connection.process.pid < 0 ||
        *observed_process_id != connection.process.pid) {
        return false;
    }

    if (observation.process.start_ticks && connection.process.start_ticks &&
        *observation.process.start_ticks != *connection.process.start_ticks) {
        return false;
    }
    if (observation.network_namespace_inode && connection.network_namespace_inode &&
        *observation.network_namespace_inode != *connection.network_namespace_inode) {
        return false;
    }
    return true;
}

EvidenceFidelity correlation_fidelity(const ConnectionSummary& connection,
                                      const NameResolutionObservation& observation) {
    if (observation.fidelity == EvidenceFidelity::Contextual) {
        return EvidenceFidelity::Contextual;
    }
    if (observation.fidelity == EvidenceFidelity::Supporting) {
        return EvidenceFidelity::Supporting;
    }

    const bool durable_process = observation.process.start_ticks &&
                                 connection.process.start_ticks &&
                                 *observation.process.start_ticks == *connection.process.start_ticks;
    const bool same_network_namespace = observation.network_namespace_inode &&
                                        connection.network_namespace_inode &&
                                        *observation.network_namespace_inode ==
                                            *connection.network_namespace_inode;
    return durable_process && same_network_namespace
        ? EvidenceFidelity::StronglyCorrelated
        : EvidenceFidelity::Supporting;
}

} // namespace

std::string to_string(NameResolutionQueryKind value) {
    switch (value) {
        case NameResolutionQueryKind::Forward: return "FORWARD";
        case NameResolutionQueryKind::Reverse: return "REVERSE";
        case NameResolutionQueryKind::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string to_string(NameResolutionMechanism value) {
    switch (value) {
        case NameResolutionMechanism::ApplicationResolverApi: return "APPLICATION_RESOLVER_API";
        case NameResolutionMechanism::SystemResolverEvent: return "SYSTEM_RESOLVER_EVENT";
        case NameResolutionMechanism::ApplicationProvided: return "APPLICATION_PROVIDED";
        case NameResolutionMechanism::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string to_string(NameResolutionRelation value) {
    switch (value) {
        case NameResolutionRelation::ResolvedAddressForOutboundConnection:
            return "RESOLVED_ADDRESS_FOR_OUTBOUND_CONNECTION";
        case NameResolutionRelation::ReverseLookupForInboundPeer:
            return "REVERSE_LOOKUP_FOR_INBOUND_PEER";
        case NameResolutionRelation::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string to_string(NameResolutionCorrelationStatus value) {
    switch (value) {
        case NameResolutionCorrelationStatus::NoMatch: return "NO_MATCH";
        case NameResolutionCorrelationStatus::Matched: return "MATCHED";
        case NameResolutionCorrelationStatus::Ambiguous: return "AMBIGUOUS";
    }
    return "NO_MATCH";
}

NameResolutionQueryKind name_resolution_query_kind_from_string(const std::string& value) {
    if (value == "FORWARD") return NameResolutionQueryKind::Forward;
    if (value == "REVERSE") return NameResolutionQueryKind::Reverse;
    return NameResolutionQueryKind::Unknown;
}

NameResolutionMechanism name_resolution_mechanism_from_string(const std::string& value) {
    if (value == "APPLICATION_RESOLVER_API") {
        return NameResolutionMechanism::ApplicationResolverApi;
    }
    if (value == "SYSTEM_RESOLVER_EVENT") return NameResolutionMechanism::SystemResolverEvent;
    if (value == "APPLICATION_PROVIDED") return NameResolutionMechanism::ApplicationProvided;
    return NameResolutionMechanism::Unknown;
}

NameResolutionRelation name_resolution_relation_from_string(const std::string& value) {
    if (value == "RESOLVED_ADDRESS_FOR_OUTBOUND_CONNECTION") {
        return NameResolutionRelation::ResolvedAddressForOutboundConnection;
    }
    if (value == "REVERSE_LOOKUP_FOR_INBOUND_PEER") {
        return NameResolutionRelation::ReverseLookupForInboundPeer;
    }
    return NameResolutionRelation::Unknown;
}

NameResolutionCorrelationResult correlate_name_resolution(
    const ConnectionSummary& connection,
    const std::vector<NameResolutionObservation>& observations,
    const NameResolutionCorrelationPolicy& policy) {
    NameResolutionCorrelationResult result;
    const NameResolutionObservation* match = nullptr;
    for (const auto& observation : observations) {
        if (!is_candidate(connection, observation, policy)) continue;
        ++result.candidate_count;
        if (!match) match = &observation;
    }

    if (result.candidate_count == 0) return result;
    if (result.candidate_count != 1) {
        result.status = NameResolutionCorrelationStatus::Ambiguous;
        return result;
    }

    result.status = NameResolutionCorrelationStatus::Matched;
    NameResolutionEvidence evidence;
    evidence.observation = *match;
    evidence.relation = NameResolutionRelation::ResolvedAddressForOutboundConnection;
    evidence.correlation_fidelity = correlation_fidelity(connection, *match);
    result.evidence = std::move(evidence);
    return result;
}

} // namespace neta
