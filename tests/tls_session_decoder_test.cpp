#include "tls_session_decoder.hpp"
#include "tls_session_wire.h"

#include <cassert>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <span>

namespace {

neta_tls_session_wire_event wire_event() {
    neta_tls_session_wire_event wire{};
    wire.version = NETA_TLS_SESSION_WIRE_VERSION;
    wire.size = sizeof(wire);
    wire.role = NETA_TLS_ROLE_CLIENT;
    wire.pid = 42;
    wire.uid = 1000;
    wire.observed_ns = 5000;
    wire.process_start_ticks = 88;
    wire.network_namespace_inode = 77;
    wire.socket_cookie = 900;
    wire.local_port = 45000;
    wire.remote_port = 443;
    wire.verify_result = 0;
    wire.verify_mode = 1;
    wire.availability = NETA_TLS_HAS_START_TICKS | NETA_TLS_HAS_NETNS |
                        NETA_TLS_HAS_COOKIE | NETA_TLS_HAS_LOCAL |
                        NETA_TLS_HAS_REMOTE | NETA_TLS_HAS_ALPN |
                        NETA_TLS_HAS_SNI | NETA_TLS_HAS_EXPECTED_PEER_NAME |
                        NETA_TLS_HAS_MATCHED_PEER_NAME | NETA_TLS_HAS_PEER_CERT |
                        NETA_TLS_PEER_VERIFICATION_REQUIRED |
                        NETA_TLS_HAS_VERIFY_RESULT | NETA_TLS_PEER_AUTHENTICATED;
    std::strcpy(wire.comm, "client");
    std::strcpy(wire.local_address, "192.0.2.10");
    std::strcpy(wire.remote_address, "203.0.113.20");
    std::strcpy(wire.tls_version, "TLSv1.3");
    std::strcpy(wire.cipher, "TLS_AES_256_GCM_SHA384");
    wire.alpn[0] = 'h'; wire.alpn[1] = '2'; wire.alpn_length = 2;
    std::strcpy(wire.sni, "api.example.test");
    std::strcpy(wire.expected_peer_name, "api.example.test");
    std::strcpy(wire.matched_peer_name, "api.example.test");
    std::strcpy(wire.leaf_sha256, "leaf");
    std::strcpy(wire.spki_sha256, "spki");
    return wire;
}

std::span<const std::byte> bytes(const neta_tls_session_wire_event& wire) {
    return {reinterpret_cast<const std::byte*>(&wire), sizeof(wire)};
}

void trusted_credentials_decode_exact_event() {
    const auto wire = wire_event();
    const auto decoded = neta::platform::linux_tls::decode_tls_session_event(
        bytes(wire), 42, 1000);
    assert(decoded.observation);
    assert(decoded.observation->local_role == neta::TlsSessionRole::Client);
    assert(decoded.observation->socket_cookie == 900);
    assert(decoded.observation->alpn == "h2");
    assert(decoded.observation->peer_authenticated);
    assert(decoded.observation->fidelity == neta::EvidenceFidelity::Exact);
}

void credential_mismatch_is_rejected() {
    const auto wire = wire_event();
    const auto decoded = neta::platform::linux_tls::decode_tls_session_event(
        bytes(wire), 43, 1000);
    assert(!decoded.observation);
}

void partial_capture_is_supporting() {
    auto wire = wire_event();
    wire.availability |= NETA_TLS_PARTIAL;
    const auto decoded = neta::platform::linux_tls::decode_tls_session_event(
        bytes(wire), 42, 1000);
    assert(decoded.observation);
    assert(decoded.observation->fidelity == neta::EvidenceFidelity::Supporting);
}

} // namespace

int main() {
    trusted_credentials_decode_exact_event();
    credential_mismatch_is_rejected();
    partial_capture_is_supporting();
    std::cout << "TLS session decoder tests passed\n";
}
