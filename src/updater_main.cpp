#include "neta/upgrade_runtime.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

std::string arg_value(int argc, char** argv, const std::string& key,
                      const std::string& fallback = {}) {
    for (int i = 0; i + 1 < argc; ++i) {
        if (argv[i] == key) return argv[i + 1];
    }
    return fallback;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2 || std::string(argv[1]) != "apply") {
            std::cerr << "Usage: neta-agent-updater apply --state-dir DIR --install-root DIR "
                         "[--service NAME] [--health-timeout SECONDS]\n";
            return 2;
        }

        neta::UpgradeWorkerOptions options;
        options.state_dir = arg_value(argc, argv, "--state-dir");
        options.install_root = arg_value(argc, argv, "--install-root");
#ifdef _WIN32
        options.service_name = arg_value(argc, argv, "--service", "NETAAgent");
#else
        options.service_name = arg_value(argc, argv, "--service", "neta-agent.service");
#endif
        const auto timeout = std::stoll(arg_value(argc, argv, "--health-timeout", "45"));
        if (timeout < 5 || timeout > 300)
            throw std::runtime_error("--health-timeout must be between 5 and 300 seconds");
        options.health_timeout = std::chrono::seconds(timeout);

        neta::run_upgrade_worker(options);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Upgrade failed: " << error.what() << '\n';
        return 1;
    }
}
