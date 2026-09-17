#include "neta/history_store.hpp"
#include "neta/rm2_reporting.hpp"
#include "neta/rules/rule_set_loader.hpp"
#include "neta/transfer_assurance.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace {

void remove_artifacts(const std::filesystem::path& database) {
    std::error_code ignored;
    for (const auto& suffix : {"", "-wal", "-shm", ".findings.jsonl",
                               ".rm2-rules.state"}) {
        std::filesystem::remove(database.string() + suffix, ignored);
    }
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

}  // namespace

int main() {
    const auto database = std::filesystem::temp_directory_path() /
                          "neta-large-ingress-reporting-test.sqlite";
    remove_artifacts(database);
    {
        neta::HistoryStore history(database);
        neta::TransferEvidenceStore transfers(database);
        neta::SocketObservation socket;
        socket.socket_cookie = 700;
        socket.local_ip = "192.0.2.10";
        socket.local_port = 45000;
        socket.remote_ip = "203.0.113.20";
        socket.remote_port = 18081;
        socket.endpoint_kind = neta::TcpEndpointKind::Connection;
        socket.transport.observed_ns = 10'000;
        neta::ProcessIdentity process;
        process.pid = 4242;
        process.start_ticks = 99;
        process.comm = "large-download";
        const auto connection_id = history.begin_connection(
            socket, process, "", socket.transport.observed_ns,
            neta::ConnectionDirection::Outbound);

        socket.transport.bytes_sent = 4096;
        socket.transport.bytes_received = 300ULL * 1024ULL * 1024ULL;
        socket.transport.transfer_source = "test:tcp-info";
        socket.transport.transfer_fidelity = neta::EvidenceFidelity::Exact;
        transfers.observe(connection_id, socket.transport);

        const auto rules = neta::rules::RuleSetLoader::built_in();
        neta::FleetReportingPolicy policy;
        policy.mode = neta::FleetReportingMode::Off;
        const auto result = neta::auto_report_rule_large_ingress(
            history, transfers, connection_id, policy, rules);
        assert(result.detected == 1);
        assert(result.persisted == 1);
        assert(result.suppressed_policy == 1);

        const auto finding = read_text(database.string() + ".findings.jsonl");
        assert(finding.find("\"type\":\"LARGE_INGRESS_TRANSFER\"") != std::string::npos);
        assert(finding.find("\"rule_id\":\"NET-001\"") != std::string::npos);
        assert(finding.find("\"semantic_type\":\"LARGE_INGRESS_TRANSFER\"") != std::string::npos);
        assert(finding.find("\"rule_set_version\":\"neta-rules/0.6.0\"") != std::string::npos);
        assert(finding.find("\"minimum_bytes_received\":268435456") != std::string::npos);
        assert(finding.find("\"bytes_received\":314572800") != std::string::npos);
    }
    remove_artifacts(database);
    std::cout << "Large-ingress live evidence reporting test passed\n";
}
