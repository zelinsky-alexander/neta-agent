#include "neta/upgrade_runtime.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
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

void copy_file_exact(const std::filesystem::path& from, const std::filesystem::path& to) {
    std::filesystem::create_directories(to.parent_path());
    const auto temporary = to.string() + ".tmp";
    std::filesystem::copy_file(from, temporary, std::filesystem::copy_options::overwrite_existing);
    std::error_code ec;
    std::filesystem::rename(temporary, to, ec);
#ifdef _WIN32
    if (ec) {
        std::filesystem::remove(to, ec);
        ec.clear();
        std::filesystem::rename(temporary, to, ec);
    }
#endif
    if (ec) {
        std::filesystem::remove(temporary);
        throw std::runtime_error("cannot restore installed build metadata: " + ec.message());
    }
}

void snapshot_installed_metadata(const std::filesystem::path& state_dir) {
    const auto current = state_dir / "installed-build.conf";
    const auto backup = state_dir / "upgrade" / "installed-build.previous.conf";
    const auto absent = state_dir / "upgrade" / "installed-build.previous.absent";
    std::filesystem::create_directories(backup.parent_path());
    std::filesystem::remove(backup);
    std::filesystem::remove(absent);
    if (std::filesystem::is_regular_file(current)) {
        std::filesystem::copy_file(current, backup, std::filesystem::copy_options::overwrite_existing);
    } else {
        std::ofstream marker(absent, std::ios::trunc);
        if (!marker) throw std::runtime_error("cannot snapshot absent installed-build metadata state");
    }
}

void restore_metadata_after_rollback(const std::filesystem::path& state_dir) {
    const auto current = state_dir / "installed-build.conf";
    const auto backup = state_dir / "upgrade" / "installed-build.previous.conf";
    const auto absent = state_dir / "upgrade" / "installed-build.previous.absent";
    if (std::filesystem::is_regular_file(backup)) {
        copy_file_exact(backup, current);
    } else if (std::filesystem::exists(absent)) {
        std::filesystem::remove(current);
    }
}

} // namespace

int main(int argc, char** argv) {
    std::filesystem::path state_dir;
    try {
        if (argc < 2 || std::string(argv[1]) != "apply") {
            std::cerr << "Usage: neta-agent-updater apply --state-dir DIR --install-root DIR "
                         "[--service NAME] [--health-timeout SECONDS]\n";
            return 2;
        }

        neta::UpgradeWorkerOptions options;
        options.state_dir = arg_value(argc, argv, "--state-dir");
        state_dir = options.state_dir;
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

        snapshot_installed_metadata(options.state_dir);
        neta::run_upgrade_worker(options);
        return 0;
    } catch (const std::exception& error) {
        if (!state_dir.empty()) {
            try {
                neta::UpgradeActivationStore activation(state_dir);
                const auto record = activation.load();
                if (record && record->state == neta::UpgradeActivationState::RolledBack) {
                    restore_metadata_after_rollback(state_dir);
                }
            } catch (const std::exception& restore_error) {
                std::cerr << "Rollback metadata restoration failed: " << restore_error.what() << '\n';
            }
        }
        std::cerr << "Upgrade failed: " << error.what() << '\n';
        return 1;
    }
}
