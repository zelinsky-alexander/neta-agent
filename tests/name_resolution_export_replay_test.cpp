#include "neta/history_store.hpp"
#include "neta/name_resolution.hpp"
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
           (std::string("neta-ms3-export-") + name);
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
    socket.socket_cookie = 700;
    socket.network_namespace_inode = 77;
    socket.local_ip = "192.0.2.10";
    socket.local_port = 45000;
    socket.remote_ip = "203.0.113.20";
    socket.remote_port = 443;
    neta::ProcessIdentity process;
    process.pid = 4242;
    process.uid = 1000;
    process.start_ticks = 900;
    process.comm = "resolver-client";
    return store.begin_connection(socket, process, "api.example.test", 10'000,
                                  neta::ConnectionDirection::Outbound);
}

neta::NameResolutionEvidence name_evidence() {
    neta::NameResolutionEvidence evidence;
    evidence.observation.started_ns = 8'000;
    evidence.observation.completed_ns = 9'000;
    evidence.observation.query_kind = neta::NameResolutionQueryKind::Forward;
    evidence.observation.mechanism = neta::NameResolutionMechanism::ApplicationResolverApi;
    evidence.observation.process.agent_visible.pid = 4242;
    evidence.observation.process.agent_visible.tgid = 4242;
    evidence.observation.process.uid = 1000;
    evidence.observation.process.start_ticks = 900;
    evidence.observation.network_namespace_inode = 77;
    evidence.observation.query_name = "api.example.test";
    evidence.observation.addresses.push_back(
        {neta::NetworkAddressFamily::IPv4, "203.0.113.20"});
    evidence.observation.result_code = 0;
    evidence.observation.fidelity = neta::EvidenceFidelity::Exact;
    evidence.observation.source = "glibc:getaddrinfo";
    evidence.relation = neta::NameResolutionRelation::ResolvedAddressForOutboundConnection;
    evidence.correlation_fidelity = neta::EvidenceFidelity::StronglyCorrelated;
    return evidence;
}

void export_and_replay_preserve_name_evidence(const char* binary) {
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
        const auto verdict = neta::evaluate(baseline, neta::aggregate_metrics({sample}), std::nullopt);
        store.save_verdict(connection_id, verdict);
        store.add_name_resolution_evidence(connection_id, name_evidence());
    }

    const auto export_command = shell_quote(binary) + " export " +
        std::to_string(connection_id) + " --db " + shell_quote(database) +
        " > " + shell_quote(bundle);
    assert(std::system(export_command.c_str()) == 0);
    const auto exported = read_file(bundle);
    assert(exported.find("\"schema_version\":3") != std::string::npos);
    assert(exported.find("\"kind\":\"NAME_RESOLUTION\"") != std::string::npos);
    assert(exported.find("\"query\":\"api.example.test\"") != std::string::npos);
    assert(exported.find("\"name_resolution_count\":1") != std::string::npos);

    const auto replay_command = shell_quote(binary) + " replay " + shell_quote(bundle) +
        " > " + shell_quote(replay_output);
    assert(std::system(replay_command.c_str()) == 0);
    const auto replay = read_file(replay_output);
    assert(replay.find("Name-resolution evidence:   MATCH") != std::string::npos);
    assert(replay.find("Verdict:                    MATCH") != std::string::npos);

    auto tampered = exported;
    const auto kind = tampered.find("\"kind\":\"NAME_RESOLUTION\"");
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
    assert(tampered_replay.find("Name-resolution evidence:   MISMATCH") != std::string::npos);
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
    export_and_replay_preserve_name_evidence(argv[1]);
    std::cout << "Name-resolution export/replay tests passed\n";
}
