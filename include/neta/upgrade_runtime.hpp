#pragma once

#include "neta/upgrade.hpp"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>

namespace neta {

// Upgrade progress currently uses its own OpenSSL transport. Adapt the
// unqualified verification setter used by that implementation so coordinator
// IP literals are verified against iPAddress SANs, while DNS names retain the
// normal hostname-verification path. The int overload is intentionally a
// better match for the existing call's literal 0 length argument than
// OpenSSL's size_t overload.
inline int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param,
                                       const char* name,
                                       int namelen) {
    if (param == nullptr || name == nullptr) return 0;
    if (::X509_VERIFY_PARAM_set1_ip_asc(param, name) == 1) return 1;
    ERR_clear_error();
    return ::X509_VERIFY_PARAM_set1_host(
        param, name, static_cast<std::size_t>(namelen));
}

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
