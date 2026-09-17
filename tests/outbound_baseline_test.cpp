#include "neta/outbound_baseline.hpp"
#include "neta/tls_session.hpp"
#include "neta/verdict.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

namespace {

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

std::int64_t add_connection(neta::HistoryStore& store, std::uint16_t local_port,
                            const char* spki) {
    neta::SocketObservation socket;
    socket.socket_cookie = local_port;
    socket.socket_inode = local_port + 1000;
    socket.local_ip = "127.0.0.1";
    socket.local_port = local_port;
    socket.remote_ip = "127.0.0.2";
    socket.remote_port = 18462;
    socket.endpoint_kind = neta::TcpEndpointKind::Connection;
    socket.transport.observed_ns = local_port;

    neta::ProcessIdentity process;
    process.pid = local_port;
    process.uid = 1000;
    process.start_ticks = local_port;
    process.comm = "openssl";
    const auto id = store.begin_connection(
        socket, process, "", socket.transport.observed_ns,
        neta::ConnectionDirection::Outbound);
    for (std::uint64_t index = 0; index < 6; ++index) {
        auto sample = socket.transport;
        sample.observed_ns += index;
        sample.rtt_us = static_cast<std::uint32_t>(1000 + index);
        sample.rtt_variance_us = 100;
        store.add_tcp_sample(id, sample);
    }

    neta::TlsSessionEvidence tls;
    tls.relation = neta::TlsSessionRelation::OutboundServerIdentity;
    tls.correlation_fidelity = neta::EvidenceFidelity::Exact;
    tls.observation.observed_ns = socket.transport.observed_ns;
    tls.observation.local_role = neta::TlsSessionRole::Client;
    tls.observation.fidelity = neta::EvidenceFidelity::Exact;
    tls.observation.peer_certificate_present = true;
    tls.observation.peer_verification_required = true;
    tls.observation.verify_result = 0;
    tls.observation.peer_authenticated = true;
    tls.observation.expected_peer_name = "neta-lab.local";
    tls.observation.matched_peer_name = "neta-lab.local";
    tls.observation.spki_sha256 = spki;
    tls.observation.issuer = "CN=NETA Lab CA";
    tls.observation.source = "test:exact-session";
    store.add_tls_session_evidence(id, tls);
    return id;
}

} // namespace

int main() {
    {
        neta::TcpSnapshot first;
        first.observed_ns = 1;
        first.rtt_us = 1'000;
        first.total_retrans = 2;
        auto second = first;
        second.observed_ns = 2;
        second.total_retrans = 9;
        const auto metrics = neta::aggregate_metrics({first, second});
        assert(metrics.retransmission_delta == 7);
    }
    const auto path = std::filesystem::temp_directory_path() /
                      "neta-outbound-baseline-test.sqlite";
    remove_database(path);
    {
        neta::HistoryStore store(path);
        const auto baseline_connection = add_connection(store, 41001, "SPKI-A");
        const auto baseline = neta::accept_outbound_connection_baseline(
            store, baseline_connection);
        assert(baseline.target_host == "127.0.0.2");
        assert(baseline.accepted_spki_sha256 == "SPKI-A");
        assert(store.verdict_for_connection(baseline_connection)->trust ==
               neta::TrustState::Stable);

        const auto changed_connection = add_connection(store, 41002, "SPKI-B");
        const auto changed = neta::evaluate_outbound_connection(store, changed_connection);
        assert(changed);
        assert(changed->performance == neta::PerformanceState::Normal);
        assert(changed->trust == neta::TrustState::Changed);
        assert(changed->trust_hypothesis == "TLS_IDENTITY_CHANGE");
    }
    remove_database(path);
    std::cout << "Outbound baseline acceptance and evaluation tests passed\n";
}
