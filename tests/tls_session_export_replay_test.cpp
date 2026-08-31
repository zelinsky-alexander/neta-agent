#include "neta/history_store.hpp"
#include "neta/tls_session.hpp"
#include "neta/verdict.hpp"

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {

std::filesystem::path path_for(const char* name) {
    return std::filesystem::temp_directory_path() /
           (std::string("neta-ms32-export-") + name);
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

std::string shell_quote(const std::filesystem::path& path) {
    return "'" + path.string() + "'";
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::ostringstream output;
    output << input.rdbuf();
    return output.str();
}

void write_file(const std::filesystem::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::trunc);
    output << text;
}

std::int64_t create_connection(neta::HistoryStore& store) {
    neta::SocketObservation socket;
    socket.socket_cookie = 701;
    socket.network_namespace_inode = 77;
    socket.local_ip = "192.0.2.10";
    socket.local_port = 45001;
    socket.remote_ip = "203.0.113.21";
    socket.remote_port = 443;
    neta::ProcessIdentity process;
    process.pid = 4242;
    process.uid = 1000;
    process.start_ticks = 900;
    process.comm = "tls-client";
    return store.begin_connection(socket, process, "api.example.test", 10'000,
                                  neta::ConnectionDirection::Outbound);
}

neta::TlsSessionEvidence tls_evidence() {
    neta::TlsSessionEvidence evidence;
    auto& observation = evidence.observation;
    observation.observed_ns = 10'500;
    observation.local_role = neta::TlsSessionRole::Client;
    observation.process.pid = 4242;
    observation.process.uid = 1000;
    observation.process.start_ticks = 900;
    observation.process.comm = "tls-client";
    observation.network_namespace_inode = 77;
    observation.socket_cookie = 701;
    observation.local = {"192.0.2.10", 45001};
    observation.remote = {"203.0.113.21", 443};
    observation.tls_version = "TLSv1.3";
    observation.cipher = "TLS_AES_256_GCM_SHA384";
    observation.alpn = "h2";
    observation.sni = "api.example.test";
    observation.expected_peer_name = "api.example.test";
    observation.matched_peer_name = "api.example.test";
    observation.peer_certificate_present = true;
    observation.peer_verification_required = true;
    observation.verify_result = 0;
    observation.peer_authenticated = true;
    observation.leaf_sha256 = "leaf-hash";
    observation.spki_sha256 = "spki-hash";
    observation.subject = "CN=api.example.test";
    observation.issuer = "CN=test-ca";
    observation.not_before = "Aug 30 00:00:00 2026 GMT";
    observation.not_after = "Aug 31 00:00:00 2026 GMT";
    observation.fidelity = neta::EvidenceFidelity::Exact;
    observation.source = "openssl3:application-shim";
    evidence.relation = neta::TlsSessionRelation::OutboundServerIdentity;
    evidence.correlation_fidelity = neta::EvidenceFidelity::Exact;
    return evidence;
}

void export_and_replay_preserve_tls_session_evidence(const char* binary) {
    const auto database = path_for("database.sqlite");
    const auto bundle = path_for("bundle.json");
    const auto replay_output = path_for("replay.txt");
    const auto tampered_bundle = path_for("tampered.json");
    const auto tampered_output = path_for("tampered-replay.txt");
    remove_database(database);
    std::int64_t connection_id = 0;
    {
        neta::HistoryStore store(database);
        connection_id = create_connection(store);
        neta::TcpSnapshot sample;
        sample.observed_ns = 10'100;
        sample.state = 1;
        sample.rtt_us = 1'100;
        sample.rtt_variance_us = 120;
        store.add_tcp_sample(connection_id, sample);

        neta::Baseline baseline;
        baseline.target_host = "api.example.test";
        baseline.target_port = 443;
        baseline.rtt_median_us = 1'000;
        baseline.rttvar_median_us = 100;
        baseline.sample_count = 5;
        baseline.sha256 = "baseline-test";
        store.save_baseline(baseline);
        const auto verdict = neta::evaluate(
            baseline, neta::aggregate_metrics({sample}), std::nullopt);
        store.save_verdict(connection_id, verdict);
        store.add_tls_session_evidence(connection_id, tls_evidence());
    }

    const auto export_command = shell_quote(binary) + " export " +
        std::to_string(connection_id) + " --db " + shell_quote(database) +
        " > " + shell_quote(bundle);
    assert(std::system(export_command.c_str()) == 0);
    const auto exported = read_file(bundle);
    assert(exported.find("\"schema_version\":4") != std::string::npos);
    assert(exported.find("\"kind\":\"TLS_SESSION\"") != std::string::npos);
    assert(exported.find("\"relation\":\"OUTBOUND_SERVER_IDENTITY\"") != std::string::npos);
    assert(exported.find("\"tls_session_count\":1") != std::string::npos);

    const auto replay_command = shell_quote(binary) + " replay " + shell_quote(bundle) +
        " > " + shell_quote(replay_output);
    assert(std::system(replay_command.c_str()) == 0);
    const auto replay = read_file(replay_output);
    assert(replay.find("TLS application sessions:    MATCH") != std::string::npos);
    assert(replay.find("Verdict:                    MATCH") != std::string::npos);

    auto tampered = exported;
    const auto kind = tampered.find("\"kind\":\"TLS_SESSION\"");
    assert(kind != std::string::npos);
    const auto hash_key = tampered.find("\"sha256\":\"", kind);
    assert(hash_key != std::string::npos);
    const auto hash_value = hash_key + std::string("\"sha256\":\"").size();
    assert(hash_value < tampered.size());
    tampered[hash_value] = tampered[hash_value] == '0' ? '1' : '0';
    write_file(tampered_bundle, tampered);
    const auto tampered_command = shell_quote(binary) + " replay " + shell_quote(tampered_bundle) +
        " > " + shell_quote(tampered_output);
    assert(std::system(tampered_command.c_str()) == 0);
    const auto tampered_replay = read_file(tampered_output);
    assert(tampered_replay.find("TLS application sessions:    MISMATCH") != std::string::npos);
    assert(tampered_replay.find("Verdict:                    MATCH") != std::string::npos);

    remove_database(database);
    std::filesystem::remove(bundle);
    std::filesystem::remove(replay_output);
    std::filesystem::remove(tampered_bundle);
    std::filesystem::remove(tampered_output);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    export_and_replay_preserve_tls_session_evidence(argv[1]);
    std::cout << "TLS-session export/replay tests passed\n";
}
