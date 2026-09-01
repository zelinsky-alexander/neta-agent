#include "neta/cli/fleet_command.hpp"
#include "neta/crypto.hpp"
#include "neta/fleet_client.hpp"
#include "neta/history_store.hpp"
#include "neta/tls_session.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace neta::cli {
namespace {

std::string arg_value(int argc, char** argv, const std::string& key,
                      const std::string& fallback = {}) {
    for (int i = 0; i + 1 < argc; ++i) {
        if (argv[i] == key) return argv[i + 1];
    }
    return fallback;
}

std::filesystem::path state_dir(int argc, char** argv) {
    return arg_value(argc, argv, "--state-dir", "/var/lib/neta/identity");
}

void print_identity(const FleetIdentity& identity) {
    std::cout << "Agent ID:                " << identity.agent_id << '\n'
              << "Fleet:                   " << identity.fleet_id << '\n'
              << "Coordinator:             " << identity.coordinator << '\n'
              << "Certificate fingerprint: " << identity.certificate_sha256 << '\n'
              << "Identity directory:      " << identity.state_dir << '\n';
}

std::string decode_chunked_body(const std::string& body) {
    std::size_t pos = 0;
    std::string decoded;
    bool saw_chunk = false;

    for (;;) {
        const auto line_end = body.find("\r\n", pos);
        if (line_end == std::string::npos) return body;
        std::string size_text = body.substr(pos, line_end - pos);
        const auto extension = size_text.find(';');
        if (extension != std::string::npos) size_text.resize(extension);
        if (size_text.empty() || !std::all_of(size_text.begin(), size_text.end(), [](unsigned char c) {
                return std::isxdigit(c) != 0;
            })) {
            return body;
        }

        std::size_t chunk_size = 0;
        try {
            chunk_size = static_cast<std::size_t>(std::stoull(size_text, nullptr, 16));
        } catch (...) {
            return body;
        }
        saw_chunk = true;
        pos = line_end + 2;

        if (chunk_size == 0) return saw_chunk ? decoded : body;
        if (chunk_size > body.size() - pos) return body;
        decoded.append(body, pos, chunk_size);
        pos += chunk_size;
        if (body.size() - pos < 2 || body.compare(pos, 2, "\r\n") != 0) return body;
        pos += 2;
    }
}

void print_response(const std::string& body) {
    std::cout << decode_chunked_body(body) << '\n';
}

std::string with_sha256_prefix(const std::string& hash) {
    if (hash.empty()) return {};
    return hash.starts_with("sha256:") ? hash : "sha256:" + hash;
}

std::string normalized_address(std::string address) {
    constexpr const char* mapped_v4 = "::ffff:";
    if (address.starts_with(mapped_v4)) address.erase(0, std::char_traits<char>::length(mapped_v4));
    return address;
}

FindingAnnouncementInput finding_from_connection(const std::filesystem::path& db_path,
                                                  std::int64_t connection_id) {
    HistoryStore store(db_path);
    const ExportData data = store.export_data(connection_id);

    FindingAnnouncementInput finding;
    const bool inbound = data.connection.direction == ConnectionDirection::Inbound;
    finding.host = inbound ? normalized_address(data.connection.local_ip)
                           : (!data.connection.target_host.empty()
                                  ? data.connection.target_host
                                  : normalized_address(data.connection.remote_ip));
    finding.port = inbound ? data.connection.local_port : data.connection.remote_port;
    finding.transport = "tcp";
    finding.performance_verdict = to_string(data.connection.performance);
    finding.trust_verdict = to_string(data.connection.trust);

    const auto tls_evidence = store.tls_session_evidence_for_connection(connection_id);
    const TlsSessionEvidence* preferred_tls = nullptr;
    for (const auto& evidence : tls_evidence) {
        if (evidence.correlation_fidelity != EvidenceFidelity::Exact) continue;
        if (inbound && evidence.relation == TlsSessionRelation::InboundClientIdentity) {
            preferred_tls = &evidence;
            break;
        }
        if (!inbound && evidence.relation == TlsSessionRelation::OutboundServerIdentity) {
            preferred_tls = &evidence;
            break;
        }
        if (preferred_tls == nullptr) preferred_tls = &evidence;
    }

    if (preferred_tls != nullptr) {
        finding.evidence_root = with_sha256_prefix(tls_session_evidence_hash(*preferred_tls));
    } else if (data.verdict && !data.verdict->input_hash.empty()) {
        finding.evidence_root = with_sha256_prefix(data.verdict->input_hash);
    } else {
        throw std::runtime_error("connection has no stable evidence hash to announce");
    }

    std::ostringstream semantic;
    semantic << "direction=" << to_string(data.connection.direction)
             << "|target=" << finding.host << ':' << finding.port
             << "|transport=" << finding.transport
             << "|performance=" << finding.performance_verdict
             << "|trust=" << finding.trust_verdict;
    if (data.verdict) {
        semantic << "|performance_hypothesis=" << data.verdict->performance_hypothesis
                 << "|trust_hypothesis=" << data.verdict->trust_hypothesis;
    }
    finding.finding_key = "sha256:" + sha256_hex(semantic.str());

    std::string root_suffix = finding.evidence_root;
    if (root_suffix.starts_with("sha256:")) root_suffix.erase(0, 7);
    if (root_suffix.size() > 12) root_suffix.resize(12);
    finding.finding_id = "FINDING-CONN-" + std::to_string(connection_id) + "-" + root_suffix;

    finding.changes.emplace_back("Stored connection assurance observation");
    finding.changes.emplace_back("Performance verdict: " + finding.performance_verdict);
    finding.changes.emplace_back("Trust verdict: " + finding.trust_verdict);

    if (preferred_tls != nullptr && inbound &&
        preferred_tls->relation == TlsSessionRelation::InboundClientIdentity &&
        preferred_tls->observation.peer_authenticated) {
        finding.changes.emplace_back("Authenticated inbound TLS client identity observed");
        if (data.baseline && !data.baseline->accepted_spki_sha256.empty() &&
            data.baseline->accepted_spki_sha256 == preferred_tls->observation.spki_sha256) {
            finding.changes.emplace_back("Client SPKI matches accepted inbound baseline");
        }
    }

    if (finding.host.empty() || finding.port == 0)
        throw std::runtime_error("connection does not contain a usable service endpoint");
    return finding;
}

} // namespace

void run_fleet_command(int argc, char** argv) {
    if (argc < 3)
        throw std::runtime_error("fleet requires enroll, status, hello, heartbeat, announce, or announce-connection");
    const std::string action = argv[2];

    if (action == "enroll") {
        FleetEnrollmentOptions options;
        options.coordinator = arg_value(argc, argv, "--coordinator");
        options.fleet_id = arg_value(argc, argv, "--fleet-id", "fleet-dev");
        options.fleet_ca = arg_value(argc, argv, "--fleet-ca");
        options.token = arg_value(argc, argv, "--token");
        options.display_name = arg_value(argc, argv, "--display-name");
        options.state_dir = state_dir(argc, argv);
        auto identity = FleetClient::enroll(options);
        std::cout << "Enrollment succeeded.\n";
        print_identity(identity);
        return;
    }

    if (action == "status") {
        print_identity(FleetClient::load_identity(state_dir(argc, argv)));
        return;
    }

    if (action == "hello") {
        print_response(FleetClient::send_agent_hello(state_dir(argc, argv)));
        return;
    }

    if (action == "heartbeat") {
        print_response(FleetClient::send_heartbeat(state_dir(argc, argv)));
        return;
    }

    if (action == "announce") {
        FindingAnnouncementInput finding;
        finding.finding_id = arg_value(argc, argv, "--finding-id");
        finding.finding_key = arg_value(argc, argv, "--finding-key");
        finding.host = arg_value(argc, argv, "--host");
        finding.port = static_cast<std::uint16_t>(std::stoul(arg_value(argc, argv, "--port", "0")));
        finding.transport = arg_value(argc, argv, "--transport", "tcp");
        finding.performance_verdict = arg_value(argc, argv, "--performance", "UNKNOWN");
        finding.trust_verdict = arg_value(argc, argv, "--trust", "UNVERIFIED");
        finding.evidence_root = arg_value(argc, argv, "--evidence-root");
        for (int i = 0; i + 1 < argc; ++i) {
            if (std::string(argv[i]) == "--change") finding.changes.emplace_back(argv[i + 1]);
        }
        print_response(FleetClient::send_finding(state_dir(argc, argv), finding));
        return;
    }

    if (action == "announce-connection") {
        if (argc < 4 || argv[3][0] == '-')
            throw std::runtime_error("fleet announce-connection requires a connection ID");
        const auto db_path = arg_value(argc, argv, "--db");
        if (db_path.empty()) throw std::runtime_error("--db is required");
        const auto connection_id = std::stoll(argv[3]);
        const auto finding = finding_from_connection(db_path, connection_id);
        std::cout << "Announcing " << finding.finding_id << " from CONN-" << connection_id
                  << " (" << finding.host << ':' << finding.port << ", "
                  << finding.performance_verdict << " / " << finding.trust_verdict << ")\n";
        print_response(FleetClient::send_finding(state_dir(argc, argv), finding));
        return;
    }

    throw std::runtime_error("unknown fleet action: " + action);
}

} // namespace neta::cli
