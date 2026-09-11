#include "neta/upgrade_runtime.hpp"

#include <chrono>
#include <cstdlib>
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

#ifndef _WIN32
void write_systemd_unit(const std::filesystem::path& path, const std::string& content) {
    const auto temporary = path.string() + ".neta-new";
    {
        std::ofstream output(temporary, std::ios::trunc);
        if (!output) throw std::runtime_error("cannot write systemd unit: " + temporary);
        output << content;
        if (!output) throw std::runtime_error("failed writing systemd unit: " + temporary);
    }
    std::error_code ec;
    std::filesystem::rename(temporary, path, ec);
    if (ec) {
        std::filesystem::remove(temporary);
        throw std::runtime_error("cannot activate systemd unit " + path.string() + ": " + ec.message());
    }
}

void require_command_ok(const std::string& command, const std::string& what) {
    const int rc = std::system(command.c_str());
    if (rc != 0) throw std::runtime_error(what + " failed with exit code " + std::to_string(rc));
}

void reconcile_linux_systemd_units(const std::filesystem::path& state_dir) {
    if (state_dir.empty()) throw std::runtime_error("systemd reconciliation requires state_dir");
    const std::string state = state_dir.string();
    const std::filesystem::path unit_root = "/etc/systemd/system";

    write_systemd_unit(unit_root / "neta-yarax-runtime-update.service",
        "[Unit]\n"
        "Description=NETA YARA-X runtime desired-state update\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "EnvironmentFile=/etc/neta/neta-agent.env\n"
        "ExecStart=/usr/local/bin/neta-agent fleet yarax-update --state-dir " + state + "\n");

    write_systemd_unit(unit_root / "neta-yarax-runtime-update.timer",
        "[Unit]\n"
        "Description=Poll NETA coordinator for YARA-X runtime updates\n\n"
        "[Timer]\n"
        "OnBootSec=45s\n"
        "OnUnitActiveSec=60s\n"
        "RandomizedDelaySec=15s\n"
        "Persistent=true\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n");

    write_systemd_unit(unit_root / "neta-yarax-content-update.service",
        "[Unit]\n"
        "Description=NETA centrally managed YARA content desired-state update\n"
        "After=network-online.target neta-yarax-runtime-update.service\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "EnvironmentFile=/etc/neta/neta-agent.env\n"
        "ExecStart=/usr/local/bin/neta-agent fleet yarax-content-update --state-dir " + state + "\n");

    write_systemd_unit(unit_root / "neta-yarax-content-update.timer",
        "[Unit]\n"
        "Description=Poll NETA coordinator for centrally managed YARA content\n\n"
        "[Timer]\n"
        "OnBootSec=60s\n"
        "OnUnitActiveSec=60s\n"
        "RandomizedDelaySec=15s\n"
        "Persistent=true\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n");

    require_command_ok("/usr/bin/systemctl daemon-reload", "systemd daemon-reload");
    require_command_ok("/usr/bin/systemctl enable --now neta-yarax-runtime-update.timer neta-yarax-content-update.timer",
                       "enabling NETA managed update timers");
}
#endif

} // namespace

int main(int argc, char** argv) {
    std::filesystem::path state_dir;
    try {
#ifndef _WIN32
        if (argc >= 2 && std::string(argv[1]) == "reconcile-systemd") {
            state_dir = arg_value(argc, argv, "--state-dir", "/var/lib/neta/identity");
            reconcile_linux_systemd_units(state_dir);
            std::cout << "NETA managed systemd units reconciled.\n";
            return 0;
        }
#endif
        if (argc < 2 || std::string(argv[1]) != "apply") {
            std::cerr << "Usage: neta-agent-updater apply --state-dir DIR --install-root DIR "
                         "[--service NAME] [--health-timeout SECONDS]\n";
#ifndef _WIN32
            std::cerr << "       neta-agent-updater reconcile-systemd [--state-dir DIR]\n";
#endif
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
        // Managed upgrades switch immutable binaries directly and therefore do not
        // execute deploy/linux/install-package.sh. Reconcile NETA-owned auxiliary
        // units here so new updater capabilities do not depend on a manual reinstall.
        reconcile_linux_systemd_units(options.state_dir);
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
