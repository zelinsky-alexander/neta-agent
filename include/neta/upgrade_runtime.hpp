#pragma once

#include "neta/upgrade.hpp"

#include <openssl/rand.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

namespace neta {

enum class UpgradeActivationState {
    Installing,
    LocalHealthy,
    Failed,
    RolledBack
};

std::string to_string(UpgradeActivationState state);
UpgradeActivationState upgrade_activation_state_from_string(const std::string& value);

struct UpgradeActivationRecord {
    std::string upgrade_id;
    UpgradeActivationState state{UpgradeActivationState::Installing};
    std::filesystem::path install_root;
    std::string previous_target;
    std::string active_target;
    std::string failure_code;
    std::string failure_message;
};

class UpgradeActivationStore {
public:
    explicit UpgradeActivationStore(std::filesystem::path state_dir);

    std::filesystem::path path() const;
    std::optional<UpgradeActivationRecord> load() const;
    void save(const UpgradeActivationRecord& record) const;

private:
    std::filesystem::path state_dir_;
};

struct UpgradeHealthResult {
    bool healthy{false};
    std::string failure_code;
    std::string message;
};

UpgradeHealthResult check_upgrade_health(const std::filesystem::path& state_dir,
                                         const UpgradeInstruction& expected);

class UpgradeProgressReporter {
public:
    static void send(const std::filesystem::path& state_dir,
                     const std::string& upgrade_id,
                     const std::string& status,
                     const std::string& failure_code = {},
                     const std::string& failure_message = {});
};

struct UpgradeWorkerOptions {
    std::filesystem::path state_dir;
    std::filesystem::path install_root;
    std::string service_name;
    std::chrono::seconds health_timeout{45};
};

void run_upgrade_worker(const UpgradeWorkerOptions& options);
bool launch_upgrade_worker_if_needed(const std::filesystem::path& state_dir);

} // namespace neta
