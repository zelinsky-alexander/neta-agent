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
           (std::string("neta-ms33-export-") + name);
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

std::string shell_quote(const std::filesystem::path& path) {
    return "'" + path.string() + "'";
}

std::string shell_quote(const char* path) {
    return "'" + std::string(path) + "'";
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

neta::HostNetworkEnvironmentEvidence environment_evidence() {
    neta::HostNetworkEnvironmentEvidence environment;
    environment.captured_at_ns = 10'050;
    environment.fidelity = neta::EvidenceFidelity::StronglyCorrelated;
    environment.source = "test:host-network-environment";
    environment.host_id = "host-hash";
    environment.hostname = "test-host";
    environment.os = "Linux";
    environment.boot_id = "boot-a";
    environment.kernel_release = "6.test";
    environment.architecture = "x86_64";
    environment.environment_class = "LINUX_HOST";
    environment.network_namespace_inode = 77;
    environment.interface_index = 2;
    environment.interface_name = "eth0";
    environment.interface_mac = "00:11:22:33:44:55";
    environment.interface_mtu = 1500;
    environment.local_address = "192.0.2.10";
    environment.gateway = "192.0.2.1";
    environment.preferred_source = "192.0.2.10";
    environment.route_table = 254;
    environment.route_metric = 100;
    environment.environment_fingerprint = neta::host_network_environment_fingerprint(environment);
    return environment;
}

neta::TlsSessionEvidence outbound_tls_evidence() {
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
    observation.fidelity = neta::EvidenceFidelity::Exact;
    observation.source = "openssl3:application-shim";
    evidence.relation = neta::TlsSessionRelation::OutboundServerIdentity;
    evidence.correlation_fidelity = neta::EvidenceFidelity::Exact;
    return evidence;
}

neta::TlsSessionEvidence inbound_tls_evidence() {
    neta::TlsSessionEvidence evidence;
    auto& observation = evidence.observation;
    observation.observed_ns = 20'500;
    observation.local_role = neta::TlsSessionRole::Server;
    observation.process.pid = 5252;
    observation.process.uid = 1000;
    observation.process.start_ticks = 901;
    observation.process.comm = "mtls-server";
    observation.network_namespace_inode = 88;
    observation.socket_cookie = 801;
    observation.local = {"192.0.2.20", 9443};
    observation.remote = {"203.0.113.31", 51001};
    observation.tls_version = "TLSv1.3";
    observation.cipher = "TLS_AES_256_GCM_SHA384";
    observation.peer_certificate_present = true;
    observation.peer_verification_required = true;
    observation.verify_result = 0;
    observation.peer_authenticated = true;
    observation.leaf_sha256 = "client-leaf";
    observation.spki_sha256 = "client-spki";
    observation.subject = "CN=client-a";
    observation.issuer = "CN=test-client-ca";
    observation.fidelity = neta::EvidenceFidelity::Exact;
    observation.source = "openssl3:application-shim";
    evidence.relation = neta::TlsSessionRelation::InboundClientIdentity;
    evidence.correlation_fidelity = neta::EvidenceFidelity::Exact;
    return evidence;
}

void export_and_replay_outbound_tls_session(const char* binary) {
    const auto database = path_for("outbound.sqlite");
    const auto bundle = path_for("outbound.json");
    const auto replay_output = path_for("outbound-replay.txt");
    const auto tampered_bundle = path_for("outbound-tampered.json");
    const auto tampered_output = path_for("outbound-tampered-replay.txt");
    const auto env_tampered_bundle = path_for("outbound-env-tampered.json");
    const auto env_tampered_output = path_for("outbound-env-tampered-replay.txt");
    remove_database(database);

    std::int64_t connection_id = 0;
    {
        neta::HistoryStore store(database);
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
        process.executable_path = "/usr/bin/tls-client";
        connection_id = store.begin_connection(socket, process, "api.example.test", 10'000,
                                               neta::ConnectionDirection::Outbound);
        store.add_host_network_environment(connection_id, environment_evidence());

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
        baseline.sha256 = "outbound-baseline";
        store.save_baseline(baseline);
        const auto verdict = neta::evaluate(
            baseline, neta::aggregate_metrics({sample}), std::nullopt);
        store.save_verdict(connection_id, verdict);
        store.add_tls_session_evidence(connection_id, outbound_tls_evidence());
    }

    const auto export_command = shell_quote(binary) + " export " +
        std::to_string(connection_id) + " --db " + shell_quote(database) +
        " > " + shell_quote(bundle);
    assert(std::system(export_command.c_str()) == 0);
    const auto exported = read_file(bundle);
    assert(exported.find("\"schema_version\":6") != std::string::npos);
    assert(exported.find("\"kind\":\"TLS_SESSION\"") != std::string::npos);
    assert(exported.find("\"relation\":\"OUTBOUND_SERVER_IDENTITY\"") != std::string::npos);
    assert(exported.find("\"tls_session_count\":1") != std::string::npos);
    assert(exported.find("\"environment_present\":true") != std::string::npos);
    assert(exported.find("\"kind\":\"HOST_NETWORK_ENVIRONMENT\"") != std::string::npos);
    assert(exported.find("\"environment_interface_name\":\"eth0\"") != std::string::npos);

    const auto replay_command = shell_quote(binary) + " replay " + shell_quote(bundle) +
        " > " + shell_quote(replay_output);
    assert(std::system(replay_command.c_str()) == 0);
    const auto replay = read_file(replay_output);
    assert(replay.find("TLS application sessions:    MATCH") != std::string::npos);
    assert(replay.find("Host/network environment:    MATCH") != std::string::npos);
    assert(replay.find("Verdict:                    MATCH") != std::string::npos);

    auto env_tampered = exported;
    const auto env_key = env_tampered.find("\"environment_hostname\":\"");
    assert(env_key != std::string::npos);
    const auto env_value = env_key + std::string("\"environment_hostname\":\"").size();
    assert(env_value < env_tampered.size());
    env_tampered[env_value] = env_tampered[env_value] == 't' ? 'x' : 't';
    write_file(env_tampered_bundle, env_tampered);
    const auto env_tampered_command = shell_quote(binary) + " replay " + shell_quote(env_tampered_bundle) +
        " > " + shell_quote(env_tampered_output);
    assert(std::system(env_tampered_command.c_str()) == 0);
    const auto env_tampered_replay = read_file(env_tampered_output);
    assert(env_tampered_replay.find("Host/network environment:    MISMATCH") != std::string::npos);
    assert(env_tampered_replay.find("Verdict:                    MATCH") != std::string::npos);

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
    std::filesystem::remove(env_tampered_bundle);
    std::filesystem::remove(env_tampered_output);
}

void export_and_replay_inbound_mtls_policy(const char* binary) {
    const auto database = path_for("inbound.sqlite");
    const auto accept_output = path_for("inbound-accept.txt");
    const auto show_output = path_for("inbound-show.txt");
    const auto bundle = path_for("inbound.json");
    const auto replay_output = path_for("inbound-replay.txt");
    const auto tampered_bundle = path_for("inbound-tampered.json");
    const auto tampered_output = path_for("inbound-tampered-replay.txt");
    remove_database(database);

    std::int64_t connection_id = 0;
    {
        neta::HistoryStore store(database);
        neta::SocketObservation socket;
        socket.socket_cookie = 801;
        socket.network_namespace_inode = 88;
        socket.local_ip = "192.0.2.20";
        socket.local_port = 9443;
        socket.remote_ip = "203.0.113.31";
        socket.remote_port = 51001;
        neta::ProcessIdentity process;
        process.pid = 5252;
        process.uid = 1000;
        process.start_ticks = 901;
        process.comm = "mtls-server";
        process.executable_path = "/usr/bin/mtls-server";
        connection_id = store.begin_connection(socket, process, "", 20'000,
                                               neta::ConnectionDirection::Inbound);

        neta::TcpSnapshot sample;
        sample.observed_ns = 20'100;
        sample.state = 1;
        sample.rtt_us = 900;
        sample.rtt_variance_us = 90;
        store.add_tcp_sample(connection_id, sample);
        store.add_tls_session_evidence(connection_id, inbound_tls_evidence());
    }

    const auto accept_command = shell_quote(binary) + " baseline accept-client " +
        std::to_string(connection_id) + " --db " + shell_quote(database) +
        " > " + shell_quote(accept_output);
    assert(std::system(accept_command.c_str()) == 0);
    const auto accepted = read_file(accept_output);
    assert(accepted.find("Accepted authenticated inbound client identity") != std::string::npos);
    assert(accepted.find("Client subject: CN=client-a") != std::string::npos);

    const auto show_command = shell_quote(binary) + " baseline show-client " +
        std::to_string(connection_id) + " --db " + shell_quote(database) +
        " > " + shell_quote(show_output);
    assert(std::system(show_command.c_str()) == 0);
    const auto shown = read_file(show_output);
    assert(shown.find("Accepted client SPKI: client-spki") != std::string::npos);
    assert(shown.find("Accepted issuer: CN=test-client-ca") != std::string::npos);

    {
        neta::HistoryStore store(database);
        const auto verdict = store.verdict_for_connection(connection_id);
        assert(verdict);
        assert(verdict->trust == neta::TrustState::Stable);
        assert(verdict->rule_set_version == neta::kRuleSetVersion);
    }

    const auto export_command = shell_quote(binary) + " export " +
        std::to_string(connection_id) + " --db " + shell_quote(database) +
        " > " + shell_quote(bundle);
    assert(std::system(export_command.c_str()) == 0);
    const auto exported = read_file(bundle);
    assert(exported.find("\"schema_version\":6") != std::string::npos);
    assert(exported.find("\"direction\":\"INBOUND\"") != std::string::npos);
    assert(exported.find("\"baseline_kind\":\"INBOUND_CLIENT_IDENTITY\"") != std::string::npos);
    assert(exported.find("\"inbound_peer_authenticated\":true") != std::string::npos);
    assert(exported.find("\"inbound_client_subject\":\"CN=client-a\"") != std::string::npos);
    assert(exported.find("\"inbound_client_spki\":\"client-spki\"") != std::string::npos);

    const auto replay_command = shell_quote(binary) + " replay " + shell_quote(bundle) +
        " > " + shell_quote(replay_output);
    assert(std::system(replay_command.c_str()) == 0);
    const auto replay = read_file(replay_output);
    assert(replay.find("Evidence input hash:        MATCH") != std::string::npos);
    assert(replay.find("Host/network environment:    MATCH") != std::string::npos);
    assert(replay.find("Rule set:                   MATCH") != std::string::npos);
    assert(replay.find("Verdict:                    MATCH") != std::string::npos);

    auto tampered = exported;
    const auto key = tampered.find("\"inbound_client_spki\":\"");
    assert(key != std::string::npos);
    const auto value = key + std::string("\"inbound_client_spki\":\"").size();
    assert(value < tampered.size());
    tampered[value] = tampered[value] == 'c' ? 'x' : 'c';
    write_file(tampered_bundle, tampered);
    const auto tampered_command = shell_quote(binary) + " replay " + shell_quote(tampered_bundle) +
        " > " + shell_quote(tampered_output);
    assert(std::system(tampered_command.c_str()) == 0);
    const auto tampered_replay = read_file(tampered_output);
    assert(tampered_replay.find("Evidence input hash:        MISMATCH") != std::string::npos);
    assert(tampered_replay.find("Verdict:                    MISMATCH") != std::string::npos);

    remove_database(database);
    std::filesystem::remove(accept_output);
    std::filesystem::remove(show_output);
    std::filesystem::remove(bundle);
    std::filesystem::remove(replay_output);
    std::filesystem::remove(tampered_bundle);
    std::filesystem::remove(tampered_output);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    export_and_replay_outbound_tls_session(argv[1]);
    export_and_replay_inbound_mtls_policy(argv[1]);
    std::cout << "TLS-session/MS3.3/MS3.4 export/replay tests passed\n";
}
