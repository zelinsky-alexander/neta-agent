#pragma once

#include "neta/lifecycle.hpp"
#include "neta/model.hpp"

#include <chrono>
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
    std::optional<int> result_code;
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

struct NameResolutionCapability {
    bool built_in{false};
    bool application_resolver_api{false};
    bool glibc_getaddrinfo{false};
    bool drop_counter{false};
    std::string source;
    std::string unavailable_reason;

    [[nodiscard]] bool available() const noexcept {
        return application_resolver_api && glibc_getaddrinfo;
    }
};

struct NameResolutionHealth {
    std::optional<std::uint64_t> dropped_events;

    [[nodiscard]] bool evidence_may_be_incomplete() const noexcept {
        return dropped_events && *dropped_events != 0;
    }
};

class NameResolutionObserver {
public:
    virtual ~NameResolutionObserver() = default;
    [[nodiscard]] virtual const NameResolutionCapability& capability() const noexcept = 0;
    [[nodiscard]] virtual NameResolutionHealth health() const = 0;
    virtual std::vector<NameResolutionObservation> poll(std::chrono::milliseconds timeout) = 0;
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

std::string name_resolution_evidence_hash(const NameResolutionEvidence& evidence);
std::string name_resolution_evidence_set_hash(
    const std::vector<NameResolutionEvidence>& evidence);

} // namespace neta
