#include "neta/connection_admission.hpp"
#include "neta/history_store.hpp"
#include "neta/tls_session.hpp"
#include "neta/verdict.hpp"

#include <sqlite3.h>

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace neta;

namespace {

constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;

std::filesystem::path db_path(const std::string& name) {
    return std::filesystem::temp_directory_path() / ("neta-agent-" + name + ".sqlite");
}

void remove_db_files(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void checkpoint_db(const std::filesystem::path& path) {
    sqlite3* db = nullptr;
    assert(sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    sqlite3_busy_timeout(db, 5000);
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
    socket.socket_cookie = 100'000 + index;
    socket.socket_inode = 200'000 + index;
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
    process.pid = static_cast<std::int64_t>(10'000 + index);
    process.uid = 1'000;
    process.start_ticks = 50'000 + index;
    process.comm = "ms0-test";
    process.executable_path = "/ms0-test";
    return process;
}

void add_samples(HistoryStore& store, std::int64_t connection_id,
                 std::uint64_t base_ns, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        TcpSnapshot sample;
        sample.observed_ns = base_ns + static_cast<std::uint64_t>(i);
        sample.state = 1;
        sample.rtt_us = 30'000 + static_cast<std::uint32_t>(i % 2'000);
        sample.rtt_variance_us = 4'000 + static_cast<std::uint32_t>(i % 500);
        sample.total_retrans = static_cast<std::uint32_t>(i / 100);
        sample.unacked = static_cast<std::uint32_t>(i % 4);
        sample.snd_cwnd = 10 + static_cast<std::uint32_t>(i % 8);
        sample.snd_ssthresh = 32;
        sample.snd_mss = 1'448;
        sample.rcv_mss = 1'448;
        store.add_tcp_sample(connection_id, sample);
    }
}

AssuranceVerdict retention_verdict(PerformanceState performance, TrustState trust,
                                   const std::string& baseline_hash) {
    AssuranceVerdict verdict;
    verdict.performance = performance;
    verdict.trust = trust;
    verdict.rule_set_version = "ms0-storage-test";
    verdict.rule_set_hash = "ms0-storage-rule-hash";
    verdict.baseline_hash = baseline_hash;
    verdict.input_hash = "ms0-storage-input-hash";
    return verdict;
}

class RetryResolver final : public platform::ProcessResolver {
public:
    std::optional<ProcessIdentity> resolve(std::uint64_t socket_inode) override {
        ++calls;
        last_inode = socket_inode;
        if (calls == 1) return std::nullopt;
        return make_process(77);
    }

    int calls{0};
    std::uint64_t last_inode{0};
};

void test_process_attribution_retry() {
    const auto path = db_path("ms0-process-retry");
    remove_db_files(path);

    {
        HistoryStore store(path);
        RetryResolver resolver;
        const auto socket = make_socket(77, 1'000);

        const auto first = begin_attributed_connection(store, resolver, socket, "retry.example");
        assert(!first);
        assert(resolver.calls == 1);
        assert(resolver.last_inode == socket.socket_inode);
        assert(store.status(10 * kMiB).connection_count == 0);

        const auto second = begin_attributed_connection(store, resolver, socket, "retry.example");
        assert(second);
        assert(resolver.calls == 2);
        assert(store.status(10 * kMiB).connection_count == 1);

        const auto connection = store.connection(*second);
        assert(connection);
        assert(connection->process.pid == make_process(77).pid);
        assert(connection->process.comm == "ms0-test");
    }

    remove_db_files(path);
}

void test_tls_link_exists_without_verdict() {
    const auto path = db_path("ms0-prebaseline-tls");
    remove_db_files(path);

    {
        HistoryStore store(path);

        TlsObservation tls;
        tls.target_host = "tls-link.example";
        tls.target_port = 443;
        tls.observed_ns = 100;
        tls.tls_version = "TLSv1.3";
        tls.cipher = "TLS_AES_256_GCM_SHA384";
        tls.spki_sha256 = "SPKI-A";
        tls.chain_valid = true;
        tls.hostname_valid = true;
        tls.sha256 = "tls-link-a";
        store.add_tls(tls);

        const auto socket = make_socket(88, 200);
        const auto connection_id = store.begin_connection(
            socket, make_process(88), tls.target_host, socket.transport.observed_ns);
        store.add_tcp_sample(connection_id, socket.transport);

        const auto exported = store.export_data(connection_id);
        assert(!exported.verdict);
        assert(exported.tls);
        assert(exported.tls->sha256 == tls.sha256);
        assert(exported.tls->spki_sha256 == tls.spki_sha256);

        assert(scalar_query(path,
            "SELECT COUNT(*) FROM connection_tls_observations WHERE relation='contemporaneous_check_for' AND fidelity='SUPPORTING';") == 1);
    }

    remove_db_files(path);
}

void test_changed_and_combined_replay() {
    Baseline baseline;
    baseline.target_host = "localhost";
    baseline.target_port = 18443;
    baseline.rtt_median_us = 30'000;
    baseline.rttvar_median_us = 4'000;
    baseline.accepted_spki_sha256 = "SPKI-A";
    baseline.sample_count = 20;
    baseline.sha256 = "baseline-a";

    TlsObservation cert_b;
    cert_b.target_host = "localhost";
    cert_b.target_port = 18443;
    cert_b.spki_sha256 = "SPKI-B";
    cert_b.chain_valid = true;
    cert_b.hostname_valid = true;
    cert_b.sha256 = "tls-b";

    const AggregateMetrics normal{35'000, 5'000, 0};
    const auto changed = evaluate(baseline, normal, cert_b);
    assert(changed.performance == PerformanceState::Normal);
    assert(changed.trust == TrustState::Changed);
    assert(changed.trust_hypothesis == "TLS_IDENTITY_CHANGE");

    const auto changed_replay = evaluate(baseline, normal, cert_b);
    assert(changed_replay.performance == changed.performance);
    assert(changed_replay.trust == changed.trust);
    assert(changed_replay.input_hash == changed.input_hash);
    assert(changed_replay.rule_set_hash == changed.rule_set_hash);

    const AggregateMetrics degraded{90'000, 12'000, 3};
    const auto combined = evaluate(baseline, degraded, cert_b);
    assert(combined.performance == PerformanceState::Degraded);
    assert(combined.performance_hypothesis == "NETWORK_PATH_DEGRADATION");
    assert(combined.trust == TrustState::Changed);
    assert(combined.trust_hypothesis == "TLS_IDENTITY_CHANGE");

    const auto combined_replay = evaluate(baseline, degraded, cert_b);
    assert(combined_replay.performance == combined.performance);
    assert(combined_replay.trust == combined.trust);
    assert(combined_replay.input_hash == combined.input_hash);
    assert(combined_replay.rule_set_hash == combined.rule_set_hash);
}

TlsSessionEvidence inbound_evidence(std::string spki, bool certificate_present,
                                    bool verification_required, std::optional<std::int64_t> verify_result,
                                    bool authenticated,
                                    EvidenceFidelity correlation = EvidenceFidelity::Exact,
                                    std::string subject = "CN=client-a",
                                    std::string issuer = "CN=test-ca") {
    TlsSessionEvidence evidence;
    evidence.observation.observed_ns = 50'000;
    evidence.observation.local_role = TlsSessionRole::Server;
    evidence.observation.process.pid = 333;
    evidence.observation.process.uid = 1000;
    evidence.observation.process.start_ticks = 444;
    evidence.observation.process.comm = "mtls-server";
    evidence.observation.network_namespace_inode = 55;
    evidence.observation.socket_cookie = 66;
    evidence.observation.local = {"127.0.0.1", 9443};
    evidence.observation.remote = {"127.0.0.2", 50123};
    evidence.observation.tls_version = "TLSv1.3";
    evidence.observation.cipher = "TLS_AES_256_GCM_SHA384";
    evidence.observation.peer_certificate_present = certificate_present;
    evidence.observation.peer_verification_required = verification_required;
    evidence.observation.verify_result = verify_result;
    evidence.observation.peer_authenticated = authenticated;
    evidence.observation.spki_sha256 = std::move(spki);
    evidence.observation.subject = std::move(subject);
    evidence.observation.issuer = std::move(issuer);
    evidence.observation.fidelity = EvidenceFidelity::Exact;
    evidence.observation.source = "openssl3:application-shim";
    evidence.relation = certificate_present
        ? TlsSessionRelation::InboundClientIdentity
        : TlsSessionRelation::InboundTlsSession;
    evidence.correlation_fidelity = correlation;
    return evidence;
}

void test_ms33_inbound_trust_policy() {
    const AggregateMetrics metrics{10'000, 1'000, 0};

    const auto no_tls = inbound_trust_context({});
    const auto no_tls_verdict = evaluate_inbound(std::nullopt, metrics, no_tls);
    assert(no_tls_verdict.trust == TrustState::Unverified);
    assert(no_tls_verdict.trust_hypothesis == "INBOUND_TLS_EVIDENCE_UNAVAILABLE");

    const auto no_cert_context = inbound_trust_context(
        {inbound_evidence("", false, true, 0, false)});
    const auto no_cert = evaluate_inbound(std::nullopt, metrics, no_cert_context);
    assert(no_cert.trust == TrustState::Unverified);
    assert(no_cert.trust_hypothesis == "INBOUND_CLIENT_CERTIFICATE_ABSENT");

    const auto presented_context = inbound_trust_context(
        {inbound_evidence("client-a", true, false, 0, false)});
    const auto presented = evaluate_inbound(std::nullopt, metrics, presented_context);
    assert(presented.trust == TrustState::Unverified);
    assert(presented.trust_hypothesis == "INBOUND_CLIENT_CERTIFICATE_NOT_AUTHENTICATED");

    const auto failed_context = inbound_trust_context(
        {inbound_evidence("client-a", true, true, 18, false)});
    const auto failed = evaluate_inbound(std::nullopt, metrics, failed_context);
    assert(failed.trust == TrustState::Suspicious);
    assert(failed.trust_hypothesis == "INBOUND_CLIENT_CERTIFICATE_VERIFICATION_FAILURE");

    const auto authenticated_context = inbound_trust_context(
        {inbound_evidence("client-a", true, true, 0, true)});
    const auto unaccepted = evaluate_inbound(std::nullopt, metrics, authenticated_context);
    assert(unaccepted.trust == TrustState::Unverified);
    assert(unaccepted.trust_hypothesis == "INBOUND_CLIENT_IDENTITY_NOT_ACCEPTED");

    Baseline accepted;
    accepted.target_host = "inbound-client:test";
    accepted.target_port = 9443;
    accepted.accepted_spki_sha256 = "client-a";
    accepted.accepted_issuer = "CN=test-ca";
    accepted.sha256 = "accepted-client-a";

    const auto stable = evaluate_inbound(accepted, metrics, authenticated_context);
    assert(stable.performance == PerformanceState::InsufficientEvidence);
    assert(stable.trust == TrustState::Stable);
    assert(stable.rule_set_version == kRuleSetVersion);
    assert(stable.baseline_hash == accepted.sha256);

    const auto changed_spki_context = inbound_trust_context(
        {inbound_evidence("client-b", true, true, 0, true)});
    const auto changed_spki = evaluate_inbound(accepted, metrics, changed_spki_context);
    assert(changed_spki.trust == TrustState::Changed);
    assert(changed_spki.trust_hypothesis == "INBOUND_CLIENT_IDENTITY_CHANGE");

    const auto changed_issuer_context = inbound_trust_context(
        {inbound_evidence("client-a", true, true, 0, true, EvidenceFidelity::Exact,
                          "CN=client-a", "CN=other-ca")});
    const auto changed_issuer = evaluate_inbound(accepted, metrics, changed_issuer_context);
    assert(changed_issuer.trust == TrustState::Changed);

    const auto missing_subject_context = inbound_trust_context(
        {inbound_evidence("client-a", true, true, 0, true, EvidenceFidelity::Exact, "")});
    const auto missing_subject = evaluate_inbound(std::nullopt, metrics, missing_subject_context);
    assert(missing_subject.trust == TrustState::Unverified);
    assert(missing_subject.trust_hypothesis == "INBOUND_CLIENT_PRINCIPAL_UNAVAILABLE");

    const auto weak_context = inbound_trust_context(
        {inbound_evidence("client-a", true, true, 0, true,
                          EvidenceFidelity::StronglyCorrelated)});
    const auto weak = evaluate_inbound(accepted, metrics, weak_context);
    assert(weak.trust == TrustState::Unverified);
    assert(weak.trust_hypothesis == "INBOUND_TLS_EVIDENCE_NOT_EXACT");

    auto first = inbound_evidence("client-a", true, true, 0, true);
    auto second = inbound_evidence("client-b", true, true, 0, true);
    second.observation.observed_ns += 1;
    second.observation.socket_cookie = 67;
    const auto ambiguous_context = inbound_trust_context({first, second});
    assert(ambiguous_context.ambiguous);
    const auto ambiguous = evaluate_inbound(accepted, metrics, ambiguous_context);
    assert(ambiguous.trust == TrustState::Unverified);
    assert(ambiguous.trust_hypothesis == "INBOUND_CLIENT_IDENTITY_AMBIGUOUS");

    const auto legacy_rules = rule_set_for_version(kLegacyRuleSetVersion);
    assert(legacy_rules);
    const auto legacy = evaluate_inbound(accepted, metrics, authenticated_context, *legacy_rules);
    assert(legacy.trust == TrustState::Unverified);
    assert(legacy.trust_hypothesis == "INBOUND_TRUST_POLICY_UNAVAILABLE");

    ConnectionSummary service;
    service.direction = ConnectionDirection::Inbound;
    service.local_port = 9443;
    service.network_namespace_inode = 123;
    service.process.uid = 1000;
    service.process.comm = "mtls-server";
    service.process.executable_path = "/usr/bin/mtls-server";
    const auto key_a = inbound_client_baseline_key(service, "CN=client-a");
    assert(!key_a.empty());
    auto restarted = service;
    restarted.process.pid = 9999;
    restarted.process.start_ticks = 123456;
    assert(inbound_client_baseline_key(restarted, "CN=client-a") == key_a);
    assert(inbound_client_baseline_key(restarted, "CN=client-b") != key_a);
    restarted.network_namespace_inode = 124;
    assert(inbound_client_baseline_key(restarted, "CN=client-a") != key_a);
}

void test_ten_mib_storage_stress() {
    const auto path = db_path("ms0-storage-stress");
    remove_db_files(path);

    constexpr std::uint64_t cap_bytes = 10ULL * kMiB;
    constexpr std::uint64_t target_bytes = 9ULL * kMiB;

    {
        HistoryStore store(path);

        Baseline obsolete;
        obsolete.target_host = "storage.example";
        obsolete.target_port = 443;
        obsolete.rtt_median_us = 30'000;
        obsolete.rttvar_median_us = 4'000;
        obsolete.accepted_spki_sha256 = "obsolete";
        obsolete.accepted_issuer = "ms0";
        obsolete.sample_count = 20;
        obsolete.created_ns = 10;
        obsolete.sha256 = "ms0-baseline-obsolete";
        store.save_baseline(obsolete);

        Baseline referenced = obsolete;
        referenced.created_ns = 20;
        referenced.accepted_spki_sha256 = "referenced";
        referenced.sha256 = "ms0-baseline-referenced";
        store.save_baseline(referenced);

        Baseline latest = obsolete;
        latest.created_ns = 30;
        latest.accepted_spki_sha256 = "latest";
        latest.sha256 = "ms0-baseline-latest";
        store.save_baseline(latest);

        std::vector<std::int64_t> normal_ids;
        for (std::uint64_t i = 0; i < 1'024; ++i) {
            const auto socket = make_socket(i, 1'000 + i);
            const auto connection_id = store.begin_connection(
                socket, make_process(i), "storage.example", socket.transport.observed_ns);
            add_samples(store, connection_id, 100'000 + i * 1'000, 512);
            store.save_verdict(connection_id,
                               retention_verdict(PerformanceState::Normal,
                                                 TrustState::Stable,
                                                 latest.sha256));
            normal_ids.push_back(connection_id);

            if ((i + 1) % 8 == 0) {
                checkpoint_db(path);
                if (store.status(cap_bytes).bytes > cap_bytes + 2ULL * kMiB) break;
            }
        }

        assert(!normal_ids.empty());

        TlsObservation retained_tls;
        retained_tls.target_host = "storage.example";
        retained_tls.target_port = 443;
        retained_tls.observed_ns = 5'000'000;
        retained_tls.spki_sha256 = "retained-spki";
        retained_tls.chain_valid = true;
        retained_tls.hostname_valid = true;
        retained_tls.sha256 = "ms0-retained-tls";
        const auto retained_tls_id = store.add_tls(retained_tls);

        const std::vector<std::pair<PerformanceState, TrustState>> protected_states{
            {PerformanceState::Degraded, TrustState::Stable},
            {PerformanceState::Failed, TrustState::Stable},
            {PerformanceState::Normal, TrustState::Changed},
            {PerformanceState::Normal, TrustState::Suspicious},
        };

        std::vector<std::int64_t> protected_ids;
        for (std::size_t i = 0; i < protected_states.size(); ++i) {
            const auto index = 20'000ULL + static_cast<std::uint64_t>(i);
            const auto socket = make_socket(index, 10'000'000 + index);
            const auto connection_id = store.begin_connection(
                socket, make_process(index), "storage.example", socket.transport.observed_ns);
            add_samples(store, connection_id, 20'000'000 + index * 100, 32);
            store.save_verdict(
                connection_id,
                retention_verdict(protected_states[i].first,
                                  protected_states[i].second,
                                  i == 0 ? referenced.sha256 : latest.sha256),
                i == 0 ? std::optional<std::int64_t>{retained_tls_id} : std::nullopt);
            protected_ids.push_back(connection_id);
        }

        TlsObservation orphan_tls = retained_tls;
        orphan_tls.target_host = "orphan.example";
        orphan_tls.observed_ns = 6'000'000;
        orphan_tls.sha256 = "ms0-orphan-tls";
        store.add_tls(orphan_tls);

        checkpoint_db(path);
        const auto before = store.status(cap_bytes);
        assert(before.bytes > cap_bytes);

        store.prune_to_budget(cap_bytes);

        const auto after = store.status(cap_bytes);
        assert(after.bytes <= target_bytes);
        assert(after.connection_count < before.connection_count);
        assert(!store.connection(normal_ids.front()));

        for (const auto id : protected_ids) {
            assert(store.connection(id));
        }

        const auto retained = store.export_data(protected_ids.front());
        assert(retained.baseline);
        assert(retained.baseline->sha256 == referenced.sha256);
        assert(retained.tls);
        assert(retained.tls->sha256 == retained_tls.sha256);

        const auto current_baseline = store.baseline_for("storage.example", 443);
        assert(current_baseline);
        assert(current_baseline->sha256 == latest.sha256);

        assert(scalar_query(path,
            "SELECT COUNT(*) FROM processes p WHERE NOT EXISTS (SELECT 1 FROM connections c WHERE c.process_id=p.id);") == 0);
        assert(scalar_query(path,
            "SELECT COUNT(*) FROM tls_observations t WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.tls_observation_id=t.id) AND NOT EXISTS (SELECT 1 FROM connection_tls_observations l WHERE l.tls_observation_id=t.id);") == 0);
        assert(scalar_query(path,
            "SELECT COUNT(*) FROM tls_observations WHERE sha256='ms0-orphan-tls';") == 0);
        assert(scalar_query(path,
            "SELECT COUNT(*) FROM baselines WHERE sha256='ms0-baseline-obsolete';") == 0);
    }

    remove_db_files(path);
}

} // namespace

int main() {
    test_process_attribution_retry();
    test_tls_link_exists_without_verdict();
    test_changed_and_combined_replay();
    test_ms33_inbound_trust_policy();
    test_ten_mib_storage_stress();
    std::cout << "All MS0/MS3.3 closure tests passed\n";
}
