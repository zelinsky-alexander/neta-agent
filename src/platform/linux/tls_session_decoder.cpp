#include "tls_session_decoder.hpp"

#include "tls_session_wire.h"

#include <cstring>
#include <string>

namespace neta::platform::linux_tls {
namespace {

template <std::size_t N>
std::string text(const char (&value)[N]) {
    return std::string(value, ::strnlen(value, N));
}

std::optional<std::string> optional_text(std::uint32_t availability, std::uint32_t flag,
                                         const char* value, std::size_t capacity) {
    if ((availability & flag) == 0U) return std::nullopt;
    return std::string(value, ::strnlen(value, capacity));
}

} // namespace

DecodeResult decode_tls_session_event(std::span<const std::byte> bytes,
                                      std::optional<std::int64_t> credential_pid,
                                      std::optional<std::uint32_t> credential_uid) {
    if (bytes.size() != sizeof(neta_tls_session_wire_event)) {
        return {std::nullopt, "unexpected TLS session event size"};
    }
    neta_tls_session_wire_event wire{};
    std::memcpy(&wire, bytes.data(), sizeof(wire));
    if (wire.version != NETA_TLS_SESSION_WIRE_VERSION || wire.size != sizeof(wire)) {
        return {std::nullopt, "unsupported TLS session wire version or size"};
    }
    if (!credential_pid || !credential_uid) {
        return {std::nullopt, "TLS session event has no kernel sender credentials"};
    }
    if (*credential_pid != static_cast<std::int64_t>(wire.pid) || *credential_uid != wire.uid) {
        return {std::nullopt, "TLS session sender credentials do not match payload identity"};
    }

    TlsSessionObservation observation;
    switch (wire.role) {
        case NETA_TLS_ROLE_CLIENT: observation.local_role = TlsSessionRole::Client; break;
        case NETA_TLS_ROLE_SERVER: observation.local_role = TlsSessionRole::Server; break;
        default: return {std::nullopt, "unknown TLS session role"};
    }
    observation.observed_ns = wire.observed_ns;
    observation.process.pid = static_cast<std::int64_t>(wire.pid);
    observation.process.uid = wire.uid;
    observation.process.comm = text(wire.comm);
    if ((wire.availability & NETA_TLS_HAS_START_TICKS) != 0U && wire.process_start_ticks != 0) {
        observation.process.start_ticks = wire.process_start_ticks;
    }
    if ((wire.availability & NETA_TLS_HAS_NETNS) != 0U && wire.network_namespace_inode != 0) {
        observation.network_namespace_inode = wire.network_namespace_inode;
    }
    if ((wire.availability & NETA_TLS_HAS_COOKIE) != 0U && wire.socket_cookie != 0) {
        observation.socket_cookie = wire.socket_cookie;
    }
    if ((wire.availability & NETA_TLS_HAS_LOCAL) != 0U) {
        observation.local.address = text(wire.local_address);
        observation.local.port = wire.local_port;
    }
    if ((wire.availability & NETA_TLS_HAS_REMOTE) != 0U) {
        observation.remote.address = text(wire.remote_address);
        observation.remote.port = wire.remote_port;
    }
    observation.tls_version = text(wire.tls_version);
    observation.cipher = text(wire.cipher);
    if ((wire.availability & NETA_TLS_HAS_ALPN) != 0U) {
        if (wire.alpn_length > sizeof(wire.alpn)) {
            return {std::nullopt, "invalid TLS session ALPN length"};
        }
        observation.alpn.assign(wire.alpn, wire.alpn + wire.alpn_length);
    }
    if ((wire.availability & NETA_TLS_HAS_SNI) != 0U) observation.sni = text(wire.sni);
    observation.expected_peer_name = optional_text(
        wire.availability, NETA_TLS_HAS_EXPECTED_PEER_NAME,
        wire.expected_peer_name, sizeof(wire.expected_peer_name));
    observation.matched_peer_name = optional_text(
        wire.availability, NETA_TLS_HAS_MATCHED_PEER_NAME,
        wire.matched_peer_name, sizeof(wire.matched_peer_name));
    observation.peer_certificate_present = (wire.availability & NETA_TLS_HAS_PEER_CERT) != 0U;
    observation.peer_verification_required =
        (wire.availability & NETA_TLS_PEER_VERIFICATION_REQUIRED) != 0U;
    if ((wire.availability & NETA_TLS_HAS_VERIFY_RESULT) != 0U) {
        observation.verify_result = wire.verify_result;
    }
    observation.peer_authenticated = (wire.availability & NETA_TLS_PEER_AUTHENTICATED) != 0U;
    if (observation.peer_certificate_present) {
        observation.leaf_sha256 = text(wire.leaf_sha256);
        observation.spki_sha256 = text(wire.spki_sha256);
    }
    if ((wire.availability & NETA_TLS_HAS_SUBJECT) != 0U) observation.subject = text(wire.subject);
    if ((wire.availability & NETA_TLS_HAS_ISSUER) != 0U) observation.issuer = text(wire.issuer);
    if ((wire.availability & NETA_TLS_HAS_NOT_BEFORE) != 0U) observation.not_before = text(wire.not_before);
    if ((wire.availability & NETA_TLS_HAS_NOT_AFTER) != 0U) observation.not_after = text(wire.not_after);
    observation.fidelity = (wire.availability & NETA_TLS_PARTIAL) != 0U
        ? EvidenceFidelity::Supporting : EvidenceFidelity::Exact;
    observation.source = "openssl3:application-shim";
    return {observation, {}};
}

} // namespace neta::platform::linux_tls
