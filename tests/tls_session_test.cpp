#include "neta/tls_session.hpp"

#include <cassert>
#include <iostream>
#include <vector>

namespace {

neta::ConnectionSummary connection(neta::ConnectionDirection direction,
                                   std::int64_t id,
                                   std::uint64_t cookie) {
    neta::ConnectionSummary value;
    value.id = id;
    value.first_seen_ns = 1'000;
    value.last_seen_ns = 20'000;
    value.direction = direction;
    value.socket_cookie = cookie;
    value.process.pid = 42;
    value.process.uid = 1000;
    value.process.start_ticks = 88;
    value.network_namespace_inode = 77;
    value.local_ip = "192.0.2.10";
    value.local_port = direction == neta::ConnectionDirection::Outbound ? 45000 : 443;
    value.remote_ip = "203.0.113.20";
    value.remote_port = direction == neta::ConnectionDirection::Outbound ? 443 : 55000;
    value.lifecycle_state = "ACTIVE";
    return value;
}

neta::TlsSessionObservation outbound_event(std::optional<std::uint64_t> cookie = 900) {
    neta::TlsSessionObservation event;
    event.observed_ns = 5'000;
    event.local_role = neta::TlsSessionRole::Client;
    event.process.pid = 42;
    event.process.uid = 1000;
    event.process.start_ticks = 88;
    event.network_namespace_inode = 77;
    event.socket_cookie = cookie;
    event.local = {"192.0.2.10", 45000};
    event.remote = {"203.0.113.20", 443};
    event.tls_version = "TLSv1.3";
    event.cipher = "TLS_AES_256_GCM_SHA384";
    event.sni = "api.example.test";
    event.peer_certificate_present = true;
    event.leaf_sha256 = "leaf";
    event.spki_sha256 = "spki";
    event.fidelity = neta::EvidenceFidelity::Exact;
    event.source = "openssl3:application-shim";
    return event;
}

void cookie_match_is_exact() {
    const auto result = neta::correlate_tls_session(
        outbound_event(), {connection(neta::ConnectionDirection::Outbound, 7, 900)});
    assert(result.status == neta::TlsSessionCorrelationStatus::Matched);
    assert(result.connection_id == 7);
    assert(result.evidence);
    assert(result.evidence->relation == neta::TlsSessionRelation::OutboundServerIdentity);
    assert(result.evidence->correlation_fidelity == neta::EvidenceFidelity::Exact);
}

void tuple_fallback_is_strongly_correlated() {
    const auto result = neta::correlate_tls_session(
        outbound_event(std::nullopt),
        {connection(neta::ConnectionDirection::Outbound, 7, 900)});
    assert(result.status == neta::TlsSessionCorrelationStatus::Matched);
    assert(result.evidence);
    assert(result.evidence->correlation_fidelity ==
           neta::EvidenceFidelity::StronglyCorrelated);
}

void cookie_mismatch_never_falls_back_to_tuple() {
    const auto result = neta::correlate_tls_session(
        outbound_event(901), {connection(neta::ConnectionDirection::Outbound, 7, 900)});
    assert(result.status == neta::TlsSessionCorrelationStatus::NoMatch);
}

void cookie_waits_for_canonical_connection_identity() {
    auto pending = connection(neta::ConnectionDirection::Inbound, 9, 0);
    pending.local_ip = "::ffff:127.0.0.1";
    pending.local_port = 9443;
    pending.remote_ip = "::ffff:127.0.0.1";
    pending.remote_port = 55000;
    auto event = outbound_event(902);
    event.local_role = neta::TlsSessionRole::Server;
    event.local = {"::ffff:127.0.0.1", 9443};
    event.remote = {"::ffff:127.0.0.1", 55000};

    auto result = neta::correlate_tls_session(event, {pending});
    assert(result.status == neta::TlsSessionCorrelationStatus::AwaitingIdentity);
    assert(result.candidate_count == 1);
    assert(!result.connection_id);
    assert(!result.evidence);

    pending.socket_cookie = 902;
    result = neta::correlate_tls_session(event, {pending});
    assert(result.status == neta::TlsSessionCorrelationStatus::Matched);
    assert(result.evidence);
    assert(result.evidence->correlation_fidelity == neta::EvidenceFidelity::Exact);

    pending.socket_cookie = 903;
    result = neta::correlate_tls_session(event, {pending});
    assert(result.status == neta::TlsSessionCorrelationStatus::NoMatch);
}

void multiple_connections_awaiting_identity_are_ambiguous() {
    auto first = connection(neta::ConnectionDirection::Outbound, 7, 0);
    auto second = first;
    second.id = 8;
    const auto result = neta::correlate_tls_session(
        outbound_event(900), {first, second});
    assert(result.status == neta::TlsSessionCorrelationStatus::Ambiguous);
    assert(result.candidate_count == 2);
    assert(!result.evidence);
}

void tuple_ambiguity_is_not_guessed() {
    auto first = connection(neta::ConnectionDirection::Outbound, 7, 0);
    auto second = first;
    second.id = 8;
    const auto result = neta::correlate_tls_session(
        outbound_event(std::nullopt), {first, second});
    assert(result.status == neta::TlsSessionCorrelationStatus::Ambiguous);
    assert(result.candidate_count == 2);
    assert(!result.evidence);
}

void direction_and_inbound_identity_are_explicit() {
    auto inbound = connection(neta::ConnectionDirection::Inbound, 9, 902);
    auto event = outbound_event(902);
    auto result = neta::correlate_tls_session(event, {inbound});
    assert(result.status == neta::TlsSessionCorrelationStatus::NoMatch);

    event.local_role = neta::TlsSessionRole::Server;
    event.local = {"192.0.2.10", 443};
    event.remote = {"203.0.113.20", 55000};
    event.peer_authenticated = true;
    result = neta::correlate_tls_session(event, {inbound});
    assert(result.status == neta::TlsSessionCorrelationStatus::Matched);
    assert(result.evidence);
    assert(result.evidence->relation == neta::TlsSessionRelation::InboundClientIdentity);
    assert(result.evidence->correlation_fidelity == neta::EvidenceFidelity::Exact);
}

void partial_observation_caps_fidelity() {
    auto event = outbound_event();
    event.fidelity = neta::EvidenceFidelity::Supporting;
    const auto result = neta::correlate_tls_session(
        event, {connection(neta::ConnectionDirection::Outbound, 7, 900)});
    assert(result.status == neta::TlsSessionCorrelationStatus::Matched);
    assert(result.evidence->correlation_fidelity == neta::EvidenceFidelity::Supporting);
}

} // namespace

int main() {
    cookie_match_is_exact();
    tuple_fallback_is_strongly_correlated();
    cookie_mismatch_never_falls_back_to_tuple();
    cookie_waits_for_canonical_connection_identity();
    multiple_connections_awaiting_identity_are_ambiguous();
    tuple_ambiguity_is_not_guessed();
    direction_and_inbound_identity_are_explicit();
    partial_observation_caps_fidelity();
    std::cout << "TLS session correlation tests passed\n";
}
