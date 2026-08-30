#pragma once

#include "neta/lifecycle.hpp"
#include "neta/model.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neta {

enum class NameResolutionQueryKind { Unknown, Forward, Reverse };
enum class NameResolutionMechanism {
    Unknown,
    ApplicationResolverApi,
    SystemResolverEvent,
    ApplicationProvided
};
enum class NameResolutionRelation {
    Unknown,
    ResolvedAddressForOutboundConnection,
    ReverseLookupForInboundPeer
};

struct NameResolutionAddress {
    NetworkAddressFamily family{NetworkAddressFamily::Unknown};
    std::string address;
};

struct NameResolutionObservation {
    std::uint64_t started_ns{0};
    std::uint64_t completed_ns{0};
    NameResolutionQueryKind query_kind{NameResolutionQueryKind::Unknown};
    NameResolutionMechanism mechanism{NameResolutionMechanism::Unknown};
    LifecycleProcessContext process;
    std::optional<std::uint64_t> network_namespace_inode;
    std::string query_name;
    std::optional<std::string> canonical_name;
    std::vector<NameResolutionAddress> addresses;
    EvidenceFidelity fidelity{EvidenceFidelity::Contextual};
    std::string source;
};

struct NameResolutionEvidence {
    NameResolutionObservation observation;
    NameResolutionRelation relation{NameResolutionRelation::Unknown};
    EvidenceFidelity correlation_fidelity{EvidenceFidelity::Contextual};
};

enum class NameResolutionCorrelationStatus { NoMatch, Matched, Ambiguous };

struct NameResolutionCorrelationPolicy {
    std::uint64_t max_age_ns{5'000'000'000ULL};
};

struct NameResolutionCorrelationResult {
    NameResolutionCorrelationStatus status{NameResolutionCorrelationStatus::NoMatch};
    std::optional<NameResolutionEvidence> evidence;
    std::size_t candidate_count{0};
};

std::string to_string(NameResolutionQueryKind value);
std::string to_string(NameResolutionMechanism value);
std::string to_string(NameResolutionRelation value);
std::string to_string(NameResolutionCorrelationStatus value);

NameResolutionQueryKind name_resolution_query_kind_from_string(const std::string& value);
NameResolutionMechanism name_resolution_mechanism_from_string(const std::string& value);
NameResolutionRelation name_resolution_relation_from_string(const std::string& value);

NameResolutionCorrelationResult correlate_name_resolution(
    const ConnectionSummary& connection,
    const std::vector<NameResolutionObservation>& observations,
    const NameResolutionCorrelationPolicy& policy = {});

} // namespace neta
