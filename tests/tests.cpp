#include "neta/crypto.hpp"
#include "neta/history_store.hpp"
#include "neta/verdict.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>
#include <optional>
#include <vector>

using namespace neta;

namespace {

std::filesystem::path temp_db_path() {
    return std::filesystem::temp_directory_path() / "neta-agent-test.sqlite";
}

void remove_db_files(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void test_verdicts() {
    Baseline baseline;
    baseline.target_host = "lab";
    baseline.target_port = 443;
    baseline.rtt_median_us = 30'000;
    baseline.rttvar_median_us = 4'000;
    baseline.accepted_spki_sha256 = "A";
    baseline.sample_count = 20;
    baseline.sha256 = "baseline";

    TlsObservation tls;
    tls.spki_sha256 = "A";
    tls.chain_valid = true;
    tls.hostname_valid = true;
    tls.sha256 = "tlsA";

    AggregateMetrics normal{35'000, 5'000, 0};
    auto verdict = evaluate(baseline, normal, tls);
    assert(verdict.performance == PerformanceState::Normal);
    assert(verdict.trust == TrustState::Stable);
    assert(verdict.rule_set_version == kRuleSetVersion);
    assert(verdict.rule_set_hash == rule_set_hash());

    const auto repeated = evaluate(baseline, normal, tls);
    assert(repeated.input_hash == verdict.input_hash);
    assert(repeated.performance == verdict.performance);
    assert(repeated.trust == verdict.trust);

    AggregateMetrics degraded{90'000, 12'000, 3};
    verdict = evaluate(baseline, degraded, tls);
    assert(verdict.performance == PerformanceState::Degraded);
    assert(verdict.performance_hypothesis == "NETWORK_PATH_DEGRADATION");
    assert(verdict.rule_confidence == 1.0);

    tls.spki_sha256 = "B";
    tls.sha256 = "tlsB";
    verdict = evaluate(baseline, normal, tls);
    assert(verdict.trust == TrustState::Changed);
    assert(verdict.trust_hypothesis == "TLS_IDENTITY_CHANGE");

    tls.chain_valid = false;
    verdict = evaluate(baseline, normal, tls);
    assert(verdict.trust == TrustState::Suspicious);
    assert(verdict.trust_hypothesis == "TLS_VALIDATION_FAILURE");
}

void test_store_and_exact_replay_inputs() {
    const auto path = temp_db_path();
    remove_db_files(path);

    {
        HistoryStore store(path);
        SocketObservation socket;
        socket.socket_cookie = 1;
        socket.socket_inode = 2;
        socket.local_ip = "127.0.0.1";
        socket.local_port = 12345;
        socket.remote_ip = "127.0.0.2";
        socket.remote_port = 443;
        socket.transport.observed_ns = 1;
        socket.transport.rtt_us = 30'000;
        socket.transport.rtt_variance_us = 4'000;

        ProcessIdentity process;
        process.pid = 1;
        process.uid = 0;
        process.start_ticks = 1;
        process.comm = "test";
        process.executable_path = "/test";

        const auto connection_id = store.begin_connection(socket, process, "lab", 1);
        store.add_tcp_sample(connection_id, socket.transport);
        store.touch_connection(connection_id, 2, "DISAPPEARED");

        auto rows = store.recent_connections(10);
        assert(rows.size() == 1);
        assert(rows[0].id == connection_id);

        Baseline baseline;
        baseline.target_host = "lab";
        baseline.target_port = 443;
        baseline.rtt_median_us = 30'000;
        baseline.rttvar_median_us = 4'000;
        baseline.accepted_spki_sha256 = "A";
        baseline.sample_count = 20;
        baseline.created_ns = 10;
        baseline.sha256 = "baseline-v1";
        store.save_baseline(baseline);

        TlsObservation tls;
        tls.target_host = "lab";
        tls.target_port = 443;
        tls.observed_ns = 11;
        tls.spki_sha256 = "A";
        tls.chain_valid = true;
        tls.hostname_valid = true;
        tls.sha256 = "tls-v1";
        const auto tls_id = store.add_tls(tls);

        const auto verdict = evaluate(baseline, aggregate_metrics(store.samples_for_connection(connection_id)), tls);
        store.save_verdict(connection_id, verdict, tls_id);

        Baseline later_baseline = baseline;
        later_baseline.created_ns = 20;
        later_baseline.sha256 = "baseline-v2";
        later_baseline.rtt_median_us = 99'000;
        store.save_baseline(later_baseline);

        TlsObservation later_tls = tls;
        later_tls.observed_ns = 21;
        later_tls.spki_sha256 = "B";
        later_tls.sha256 = "tls-v2";
        store.add_tls(later_tls);

        const auto exported = store.export_data(connection_id);
        assert(exported.baseline);
        assert(exported.tls);
        assert(exported.verdict);
        assert(exported.baseline->sha256 == "baseline-v1");
        assert(exported.tls->sha256 == "tls-v1");
        assert(exported.verdict->baseline_hash == "baseline-v1");

        const auto replay = evaluate(*exported.baseline, aggregate_metrics(exported.samples), exported.tls);
        assert(replay.performance == exported.verdict->performance);
        assert(replay.trust == exported.verdict->trust);
        assert(replay.input_hash == exported.verdict->input_hash);
        assert(replay.rule_set_hash == exported.verdict->rule_set_hash);

        const auto status = store.status(200ULL * 1024ULL * 1024ULL);
        assert(status.connection_count == 1);
        assert(status.sample_count == 1);
        assert(status.bytes > 0);
    }

    remove_db_files(path);
}

} // namespace

int main() {
    assert(sha256_hex("abc") ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    test_verdicts();
    test_store_and_exact_replay_inputs();
    std::cout << "All neta-agent tests passed\n";
}
