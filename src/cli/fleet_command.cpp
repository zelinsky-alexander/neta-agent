#include "neta/cli/fleet_command.hpp"
#include "neta/fleet_client.hpp"

#include <filesystem>
#include <iostream>
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

bool has_arg(int argc, char** argv, const std::string& key) {
    for (int i = 0; i < argc; ++i) if (argv[i] == key) return true;
    return false;
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

} // namespace

void run_fleet_command(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("fleet requires enroll, status, hello, heartbeat, or announce");
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
        std::cout << FleetClient::send_agent_hello(state_dir(argc, argv)) << '\n';
        return;
    }

    if (action == "heartbeat") {
        std::cout << FleetClient::send_heartbeat(state_dir(argc, argv)) << '\n';
        return;
    }

    if (action == "announce") {
        FindingAnnouncementInput finding;
        finding.finding_id = arg_value(argc, argv, "--finding-id");
        finding.host = arg_value(argc, argv, "--host");
        finding.port = static_cast<std::uint16_t>(std::stoul(arg_value(argc, argv, "--port", "0")));
        finding.transport = arg_value(argc, argv, "--transport", "tcp");
        finding.performance_verdict = arg_value(argc, argv, "--performance", "UNKNOWN");
        finding.trust_verdict = arg_value(argc, argv, "--trust", "UNVERIFIED");
        finding.evidence_root = arg_value(argc, argv, "--evidence-root");
        for (int i = 0; i + 1 < argc; ++i) {
            if (std::string(argv[i]) == "--change") finding.changes.emplace_back(argv[i + 1]);
        }
        std::cout << FleetClient::send_finding(state_dir(argc, argv), finding) << '\n';
        return;
    }

    throw std::runtime_error("unknown fleet action: " + action);
}

} // namespace neta::cli
