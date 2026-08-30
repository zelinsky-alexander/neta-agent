#include "neta/crypto.hpp"
#include "neta/history_store.hpp"
#include "neta/verdict.hpp"

#include <sqlite3.h>

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace neta;

namespace {

std::filesystem::path temp_db_path() {
    return std::filesystem::temp_directory_path() / "neta-agent-test.sqlite";
}

std::filesystem::path retention_db_path() {
    return std::filesystem::temp_directory_path() / "neta-agent-retention-test.sqlite";
}

void remove_db_files(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void checkpoint_db(const std::filesystem::path& path) {
    sqlite3* db = nullptr;
    assert(sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    char* error = nullptr;
    const auto rc = sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE);", nullptr, nullptr, &error);
    if (error) sqlite3_free(error);
    assert(rc == SQLITE_OK);
    assert(sqlite3_close(db) == SQLITE_OK);
}

std::int64_t scalar_query(const std::filesystem::path& path, const char* sql) {
    sqlite3* db = nullptr;
    assert(sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    assert(sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK);
    assert(sqlite3_step(stmt) == SQLITE_ROW);
    const auto value = sqlite3_column_int64(stmt, 0);
    assert(sqlite3_finalize(stmt) == SQLITE_OK);
    assert(sqlite3_close(db) == SQLITE_OK);
    return value;
}

SocketObservation make_socket(std::uint64_t index, std::uint64_t observed_ns) {
    SocketObservation socket;
    socket.socket_cookie = 10'000 + index;
    socket.socket_inode = 20'000 + index;
    socket.local_ip = "127.0.0.1";
    socket.local_port = static_cast<std::uint16_t>(10'000 + (index % 40'000));
    socket.remote_ip = "127.0.0.2";
    socket.remote_port = 443;
    socket.endpoint_kind = TcpEndpointKind::Connection;
    socket.transport.observed_ns = observed_ns;
    socket.transport.state = 1;
    socket.transport.rtt_us = 30'000;
    socket.transport.rtt_variance_us = 4'000;
    socket.transport.snd_cwnd = 10;
    return socket;
}

ProcessIdentity make_process(std::uint64_t index) {
    ProcessIdentity process;
    process.pid = static_cast<std::int64_t>(1'000 + index);
    process.uid = 1'000;
    process.start_ticks = 50'000 + index;
    process.comm = "retention-test";
    process.executable_path = "/retention-test";
    return process;
}

AssuranceVerdict make_verdict(PerformanceState performance, TrustState trust,
                              std::string baseline_hash = {}) {
    AssuranceVerdict verdict;
    verdict.performance = performance;
    verdict.trust = trust;
    verdict.rule_set_version = "retention-test";
    verdict.rule_set_hash = "retention-rule-hash";
    verdict.baseline_hash = std::move(baseline_hash);
    verdict.input_hash = "retention-input-hash";
    return verdict;
}

void add_samples(HistoryStore& store, std::int64_t connection_id,
                 std::uint64_t base_ns, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        TcpSnapshot sample;
        sample.observed_ns = base_ns + static_cast<std::uint64_t>(i);
        sample.state = 1;
        sample.rtt_us = 30'000 + static_cast<std::uint32_t>(i);
        sample.rtt_variance_us = 4'000 + static_cast<std::uint32_t>(i);
        sample.total_retrans = static_cast<std::uint32_t>(i / 10);
        sample.unacked = static_cast<std::uint32_t>(i % 4);
        sample.snd_cwnd = 10 + static_cast<std::uint32_t>(i % 8);
        sample.snd_ssthresh = 32;
        sample.snd_mss = 1'448;
        sample.rcv_mss = 1'448;
        store.add_tcp_sample(connection_id, sample);
    }
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

void test_bounded_retention_policy() {
    const auto path = retention_db_path();
    remove_db_files(path);

    {
        HistoryStore store(path);
        checkpoint_db(path);
        const auto sqlite_floor_bytes = store.status(1).bytes;
        assert(sqlite_floor_bytes > 0);

        Baseline obsolete;
        obsolete.target_host = "retention.example";
        obsolete.target_port = 443;
        obsolete.rtt_median_us = 30'000;
        obsolete.rttvar_median_us = 4'000;
        obsolete.accepted_spki_sha256 = "obsolete";
        obsolete.accepted_issuer = "test";
        obsolete.sample_count = 20;
        obsolete.created_ns = 10;
        obsolete.sha256 = "retention-baseline-obsolete";
        store.save_baseline(obsolete);

        Baseline referenced = obsolete;
        referenced.created_ns = 20;
        referenced.accepted_spki_sha256 = "referenced";
        referenced.sha256 = "retention-baseline-referenced";
        store.save_baseline(referenced);

        Baseline latest = obsolete;
        latest.created_ns = 30;
        latest.accepted_spki_sha256 = "latest";
        latest.sha256 = "retention-baseline-latest";
        store.save_baseline(latest);

        TlsObservation orphan_tls;
        orphan_tls.target_host = "orphan.example";
        orphan_tls.target_port = 443;
        orphan_tls.observed_ns = 1;
        orphan_tls.spki_sha256 = "orphan";
        orphan_tls.sha256 = "orphan-tls";
        store.add_tls(orphan_tls);

        TlsObservation retained_tls = orphan_tls;
        retained_tls.target_host = "retention.example";
        retained_tls.observed_ns = 2;
        retained_tls.spki_sha256 = "retained";
        retained_tls.sha256 = "retained-tls";
        const auto retained_tls_id = store.add_tls(retained_tls);

        std::vector<std::int64_t> normal_ids;
        normal_ids.reserve(256);
        for (std::uint64_t i = 0; i < 256; ++i) {
            const auto socket = make_socket(i, 1'000 + i);
            const auto process = make_process(i);
            const auto connection_id = store.begin_connection(socket, process, "retention.example", socket.transport.observed_ns);
            add_samples(store, connection_id, 100'000 + i * 100, 20);
            store.save_verdict(connection_id,
                               make_verdict(PerformanceState::Normal, TrustState::Stable,
                                            latest.sha256));
            normal_ids.push_back(connection_id);
        }

        std::vector<std::int64_t> protected_ids;
        const std::vector<std::pair<PerformanceState, TrustState>> protected_states{
            {PerformanceState::Degraded, TrustState::Stable},
            {PerformanceState::Failed, TrustState::Stable},
            {PerformanceState::Normal, TrustState::Changed},
            {PerformanceState::Normal, TrustState::Suspicious},
        };

        for (std::size_t i = 0; i < protected_states.size(); ++i) {
            const auto index = 10'000ULL + static_cast<std::uint64_t>(i);
            const auto socket = make_socket(index, 1'000'000 + index);
            const auto process = make_process(index);
            const auto connection_id = store.begin_connection(socket, process, "retention.example", socket.transport.observed_ns);
            add_samples(store, connection_id, 2'000'000 + index * 100, 20);
            auto verdict = make_verdict(protected_states[i].first, protected_states[i].second,
                                        i == 0 ? referenced.sha256 : latest.sha256);
            store.save_verdict(connection_id, verdict, i == 0 ? std::optional<std::int64_t>{retained_tls_id}
                                                               : std::nullopt);
            protected_ids.push_back(connection_id);
        }

        checkpoint_db(path);
        const auto before = store.status(1);
        assert(before.bytes > sqlite_floor_bytes);

        const auto retained_data_bytes = before.bytes - sqlite_floor_bytes;
        const auto desired_target_bytes = sqlite_floor_bytes + retained_data_bytes * 2ULL / 3ULL;
        const auto max_bytes = desired_target_bytes * 10ULL / 9ULL;
        const auto target_bytes = max_bytes - (max_bytes / 10ULL);
        assert(before.bytes > max_bytes);
        assert(target_bytes >= sqlite_floor_bytes);

        store.prune_to_budget(max_bytes);

        const auto after = store.status(max_bytes);
        assert(after.bytes <= target_bytes);
        assert(after.connection_count < before.connection_count);
        assert(!store.connection(normal_ids.front()));
        assert(store.connection(normal_ids.back()));

        for (const auto id : protected_ids) {
            assert(store.connection(id));
        }

        const auto protected_export = store.export_data(protected_ids.front());
        assert(protected_export.baseline);
        assert(protected_export.baseline->sha256 == referenced.sha256);
        assert(protected_export.tls);
        assert(protected_export.tls->sha256 == retained_tls.sha256);

        const auto current_baseline = store.baseline_for("retention.example", 443);
        assert(current_baseline);
        assert(current_baseline->sha256 == latest.sha256);

        assert(scalar_query(path,
            "SELECT COUNT(*) FROM processes p WHERE NOT EXISTS (SELECT 1 FROM connections c WHERE c.process_id=p.id);") == 0);
        assert(scalar_query(path,
            "SELECT COUNT(*) FROM tls_observations t WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.tls_observation_id=t.id);") == 0);
        assert(scalar_query(path,
            "SELECT COUNT(*) FROM baselines b WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.baseline_hash=b.sha256) AND EXISTS (SELECT 1 FROM baselines newer WHERE newer.target_host=b.target_host AND newer.target_port=b.target_port AND (newer.created_ns>b.created_ns OR (newer.created_ns=b.created_ns AND newer.id>b.id)));") == 0);
    }

    remove_db_files(path);
}

} // namespace

int main() {
    assert(sha256_hex("abc") ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    test_verdicts();
    test_store_and_exact_replay_inputs();
    test_bounded_retention_policy();
    std::cout << "All neta-agent tests passed\n";
}
