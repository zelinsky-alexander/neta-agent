#pragma once

#include "neta/model.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neta {

enum class TlsSessionRole { Unknown, Client, Server };
enum class TlsSessionRelation {
    Unknown,
    OutboundTlsSession,
    OutboundServerIdentity,
    InboundTlsSession,
    InboundClientIdentity
};

struct TlsSessionEndpoint {
    std::string address;
    std::uint16_t port{0};
};

struct TlsSessionObservation {
    std::uint64_t observed_ns{0};
    TlsSessionRole local_role{TlsSessionRole::Unknown};
    ProcessIdentity process;
    std::optional<std::uint64_t> network_namespace_inode;
    std::optional<std::uint64_t> socket_cookie;
    TlsSessionEndpoint local;
    TlsSessionEndpoint remote;
    std::string tls_version;
    std::string cipher;
    std::string alpn;
    std::string sni;
    std::optional<std::string> expected_peer_name;
    std::optional<std::string> matched_peer_name;
    bool peer_certificate_present{false};
    bool peer_verification_required{false};
    std::optional<std::int64_t> verify_result;
    bool peer_authenticated{false};
    std::string leaf_sha256;
    std::string spki_sha256;
    std::string subject;
    std::string issuer;
    std::string not_before;
    std::string not_after;
    EvidenceFidelity fidelity{EvidenceFidelity::Contextual};
    std::string source;
};

struct TlsSessionEvidence {
    TlsSessionObservation observation;
    TlsSessionRelation relation{TlsSessionRelation::Unknown};
    EvidenceFidelity correlation_fidelity{EvidenceFidelity::Contextual};
};

enum class TlsSessionCorrelationStatus { NoMatch, Matched, Ambiguous };

struct TlsSessionCorrelationPolicy {
    std::uint64_t tuple_max_age_ns{30'000'000'000ULL};
};

struct TlsSessionCorrelationResult {
    TlsSessionCorrelationStatus status{TlsSessionCorrelationStatus::NoMatch};
    std::optional<std::int64_t> connection_id;
    std::optional<TlsSessionEvidence> evidence;
    std::size_t candidate_count{0};
};

struct TlsSessionCapability {
    bool application_instrumentation{false};
    bool sender_credentials_verified{false};
    bool receive_drop_counter{false};
    std::string source;
    std::string endpoint;
    std::string unavailable_reason;

    bool available() const noexcept {
        return application_instrumentation && sender_credentials_verified;
    }
};

struct TlsSessionHealth {
    std::optional<std::uint64_t> dropped_events;
    std::uint64_t rejected_events{0};

    bool evidence_may_be_incomplete() const noexcept {
        return (dropped_events && *dropped_events != 0) || rejected_events != 0;
    }
};

class TlsSessionObserver {
public:
    virtual ~TlsSessionObserver() = default;
    virtual const TlsSessionCapability& capability() const noexcept = 0;
    virtual TlsSessionHealth health() const = 0;
    virtual std::vector<TlsSessionObservation> poll(std::chrono::milliseconds timeout) = 0;
};

std::string to_string(TlsSessionRole value);
std::string to_string(TlsSessionRelation value);
std::string to_string(TlsSessionCorrelationStatus value);
TlsSessionRole tls_session_role_from_string(const std::string& value);
TlsSessionRelation tls_session_relation_from_string(const std::string& value);

TlsSessionCorrelationResult correlate_tls_session(
    const TlsSessionObservation& observation,
    const std::vector<ConnectionSummary>& connections,
    const TlsSessionCorrelationPolicy& policy = {});

std::string tls_session_identity_key(const TlsSessionObservation& observation);
std::string tls_session_evidence_hash(const TlsSessionEvidence& evidence);
std::string tls_session_evidence_set_hash(const std::vector<TlsSessionEvidence>& evidence);

} // namespace neta
