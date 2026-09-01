#include "neta/cli/fleet_command.hpp"

#include <iostream>
#include <string>

int neta_legacy_main(int argc, char** argv);

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

    const int result = neta_legacy_main(argc, argv);
    if (argc < 2) {
        std::cout
            << "\nFleet / NAP/1:\n"
            << "  neta-agent fleet enroll --coordinator https://host:port --fleet-ca FILE --token TOKEN [--fleet-id ID] [--display-name NAME] [--state-dir DIR]\n"
            << "  neta-agent fleet status [--state-dir DIR]\n"
            << "  neta-agent fleet hello [--state-dir DIR]\n"
            << "  neta-agent fleet heartbeat [--state-dir DIR]\n"
            << "  neta-agent fleet announce --finding-id ID --host HOST --port PORT [--change CHANGE] [--performance VERDICT] [--trust VERDICT] [--evidence-root HASH] [--state-dir DIR]\n";
    }
    return result;
}
