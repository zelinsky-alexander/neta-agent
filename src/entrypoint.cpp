#include "neta/cli/fleet_command.hpp"
#include "neta/platform.hpp"

#ifdef _WIN32
#include "neta/windows_service.hpp"
#endif

#include <iostream>
#include <string>

int neta_legacy_main(int argc, char** argv);

#ifdef _WIN32
namespace {
int windows_capabilities() {
    const auto env = neta::platform::host_environment();
    const auto capabilities = neta::platform::capabilities();
    std::cout << "Platform: " << env.os << ' ' << env.kernel_release << "\n\n"
              << "Connection discovery       " << (capabilities.connection_discovery ? "YES" : "NO") << '\n'
              << "Process attribution        " << (capabilities.process_attribution ? "YES" : "NO") << '\n'
              << "TCP RTT                    " << (capabilities.tcp_rtt ? "YES" : "NO") << '\n'
              << "TCP RTT variance           " << (capabilities.tcp_rtt_variance ? "YES" : "NO") << '\n'
              << "TCP retransmissions        " << (capabilities.tcp_retransmissions ? "YES" : "NO") << '\n'
              << "TCP cwnd                   " << (capabilities.tcp_cwnd ? "YES" : "NO") << '\n'
              << "Route observation          " << (capabilities.route_observation ? "YES" : "NO") << '\n'
              << "Lifecycle source           " << (capabilities.lifecycle_source.empty()
                    ? "UNAVAILABLE" : capabilities.lifecycle_source) << '\n'
              << "TCP connect events         " << (capabilities.lifecycle_connect_events ? "YES" : "NO") << '\n'
              << "TCP accept events          " << (capabilities.lifecycle_accept_events ? "YES" : "NO") << '\n'
              << "TCP close events           " << (capabilities.lifecycle_close_events ? "YES" : "NO") << '\n'
              << "Exact lifecycle direction  " << (capabilities.exact_lifecycle_direction ? "YES" : "NO") << '\n'
              << "Lifecycle loss counter     " << (capabilities.lifecycle_drop_counter ? "YES" : "NO") << '\n'
              << "Lifecycle dropped events   " << (capabilities.lifecycle_dropped_events
                    ? std::to_string(*capabilities.lifecycle_dropped_events) : "UNAVAILABLE") << '\n'
              << "Application resolver API   " << (capabilities.application_name_resolution_events ? "YES" : "NO") << '\n'
              << "Application TLS sessions   " << (capabilities.application_tls_session_events ? "YES" : "NO") << '\n';
    if (!capabilities.connection_lifecycle_events) {
        std::cout << "Lifecycle unavailable      " << capabilities.lifecycle_unavailable_reason << '\n';
    }
    return 0;
}
} // namespace
#endif

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "fleet") {
        try {
            neta::cli::run_fleet_command(argc, argv);
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << '\n';
            return 1;
        }
    }

#ifdef _WIN32
    if (argc >= 2 && std::string(argv[1]) == "service") {
        try {
            return neta::platform::run_windows_service(argc, argv);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << '\n';
            return 1;
        }
    }
    if (argc >= 2 && std::string(argv[1]) == "capabilities") {
        return windows_capabilities();
    }
#endif

    const int result = neta_legacy_main(argc, argv);
    if (argc < 2) {
        std::cout
            << "\nFleet / NAP/1:\n"
            << "  neta-agent fleet enroll --coordinator https://host:port --fleet-ca FILE --token TOKEN [--fleet-id ID] [--display-name NAME] [--state-dir DIR]\n"
            << "  neta-agent fleet status [--state-dir DIR]\n"
            << "  neta-agent fleet hello [--state-dir DIR]\n"
            << "  neta-agent fleet heartbeat [--state-dir DIR]\n"
            << "  neta-agent fleet announce --finding-id ID --host HOST --port PORT [--change CHANGE] [--performance VERDICT] [--trust VERDICT] [--evidence-root HASH] [--state-dir DIR]\n";
#ifdef _WIN32
        std::cout
            << "\nWindows service:\n"
            << "  neta-agent service [--all|--outbound|--inbound] [filters] [--db FILE] [--state-dir DIR] [--max-db-mb 200]\n"
            << "  The service command must be launched by the Windows Service Control Manager.\n";
#endif
    }
    return result;
}
