#include "neta/cli/fleet_command.hpp"
#include "neta/crypto.hpp"
#include "neta/fleet_client.hpp"
#include "neta/history_store.hpp"
#include "neta/tls_session.hpp"
#include "neta/upgrade.hpp"
#include "neta/upgrade_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
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
#ifdef _WIN32
    const char* program_data = std::getenv("ProgramData");
    const std::filesystem::path fallback = program_data == nullptr
        ? std::filesystem::path("C:/ProgramData/NETA/identity")
        : std::filesystem::path(program_data) / "NETA" / "identity";
    return arg_value(argc, argv, "--state-dir", fallback.string());
#else
    return arg_value(argc, argv, "--state-dir", "/var/lib/neta/identity");
#endif
}

void print_identity(const FleetIdentity& identity) {
    std::cout << "Agent ID:                " << identity.agent_id << '\n'
              << "Fleet:                   " << identity.fleet_id << '\n'
              << "Coordinator:             " << identity.coordinator << '\n'
              << "Certificate fingerprint: " << identity.certificate_sha256 << '\n'
              << "Identity directory:      " << identity.state_dir << '\n';
}

void print_upgrade_state(const UpgradeState& state) {
    std::cout << "Upgrade ID:      " << state.instruction.upgrade_id << '\n'
              << "State:           " << to_string(state.state) << '\n'
              << "Target:          " << state.instruction.version << " / "
              << state.instruction.build_id << '\n'
              << "Commit:          " << state.instruction.git_commit << '\n'
              << "Platform:        " << state.instruction.os << '/' << state.instruction.arch << '\n'
              << "Artifact:        " << state.instruction.artifact_name << '\n'
              << "SHA-256:         " << state.instruction.sha256 << '\n'
              << "Download path:   "
              << (state.download_path.empty() ? "-" : state.download_path.string()) << '\n'
              << "Last error:      " << (state.last_error.empty() ? "-" : state.last_error) << '\n';
}

void print_activation_state(const UpgradeActivationRecord& activation) {
    std::cout << "Activation:      " << to_string(activation.state) << '\n'
              << "Install root:    " << activation.install_root << '\n'
              << "Previous target: " << (activation.previous_target.empty() ? "-" : activation.previous_target) << '\n'
              << "Active target:   " << (activation.active_target.empty() ? "-" : activation.active_target) << '\n'
              << "Failure code:    " << (activation.failure_code.empty() ? "-" : activation.failure_code) << '\n'
              << "Failure message: " << (activation.failure_message.empty() ? "-" : activation.failure_message) << '\n';
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
        throw std::runtime_error(
            "fleet requires enroll, status, hello, heartbeat, upgrade-status, upgrade-download, upgrade-run, upgrade-report, announce, or announce-connection");
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

    if (action == "upgrade-status") {
        const auto dir = state_dir(argc, argv);
        UpgradeStateStore upgrades(dir);
        const auto pending = upgrades.load();
        if (!pending) {
            std::cout << "No staged upgrade instruction.\n";
            return;
        }
        print_upgrade_state(*pending);
        UpgradeActivationStore activation(dir);
        if (const auto active = activation.load()) print_activation_state(*active);
        return;
    }

    if (action == "upgrade-download") {
        const auto dir = state_dir(argc, argv);
        UpgradeStateStore store(dir);
        const auto pending = store.load();
        if (!pending) throw std::runtime_error("no pending upgrade instruction");
        UpgradeProgressReporter::send(dir, pending->instruction.upgrade_id, "DOWNLOADING");
        const auto state = download_pending_upgrade(dir);
        print_upgrade_state(state);
        if (state.state == UpgradeLocalState::Verified) {
            std::cout << "Artifact verified and ready for A5 activation.\n";
        }
        return;
    }

    if (action == "upgrade-run") {
        const auto dir = state_dir(argc, argv);
        UpgradeWorkerOptions options;
        options.state_dir = dir;
#ifdef _WIN32
        options.install_root = arg_value(argc, argv, "--install-root", "C:/Program Files/NETA");
        options.service_name = arg_value(argc, argv, "--service", "NETAAgent");
#else
        options.install_root = arg_value(argc, argv, "--install-root", "/opt/neta-agent");
        options.service_name = arg_value(argc, argv, "--service", "neta-agent.service");
#endif
        const auto timeout = std::stoll(arg_value(argc, argv, "--health-timeout", "45"));
        if (timeout < 5 || timeout > 300)
            throw std::runtime_error("--health-timeout must be between 5 and 300 seconds");
        options.health_timeout = std::chrono::seconds(timeout);
        run_upgrade_worker(options);
        std::cout << "Upgrade worker completed.\n";
        return;
    }

    if (action == "upgrade-report") {
        const auto dir = state_dir(argc, argv);
        const auto upgrade_id = arg_value(argc, argv, "--upgrade-id");
        const auto status = arg_value(argc, argv, "--status");
        if (upgrade_id.empty() || status.empty())
            throw std::runtime_error("upgrade-report requires --upgrade-id and --status");
        UpgradeProgressReporter::send(dir, upgrade_id, status,
            arg_value(argc, argv, "--failure-code"),
            arg_value(argc, argv, "--failure-message"));
        std::cout << "UpgradeProgress accepted by coordinator.\n";
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
