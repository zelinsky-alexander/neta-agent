#pragma once

#include <openssl/core_names.h>
#include <openssl/params.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace neta {

struct FleetEnrollmentOptions {
    std::string coordinator;
    std::string fleet_id{"fleet-dev"};
    std::filesystem::path fleet_ca;
    std::string token;
    std::string display_name;
    std::filesystem::path state_dir{"/var/lib/neta/identity"};
};

struct FleetIdentity {
    std::string coordinator;
    std::string fleet_id;
    std::string agent_id;
    std::string certificate_sha256;
    std::filesystem::path state_dir;
};

struct FindingAnnouncementInput {
    std::string finding_id;
    std::string finding_key;
    std::string host;
    std::uint16_t port{0};
    std::string transport{"tcp"};
    std::string subject_type;
    std::string subject_id;
    std::optional<std::int64_t> subject_pid;
    std::optional<std::int64_t> subject_parent_pid;
    std::string subject_image;
    std::string subject_parent_image;
    std::string subject_command_line;
    std::string severity;
    std::string rule_id;
    std::string rule_set_id;
    std::string rule_set_version;
    std::string interpretation;
    std::vector<std::string> changes;
    std::string performance_verdict{"UNKNOWN"};
    std::string trust_verdict{"UNVERIFIED"};
    std::string evidence_root;
};

class FleetClient {
public:
    static FleetIdentity enroll(const FleetEnrollmentOptions& options);
    static FleetIdentity load_identity(const std::filesystem::path& state_dir);
    static std::string send_agent_hello(const std::filesystem::path& state_dir);
    static std::string send_heartbeat(const std::filesystem::path& state_dir);
    static std::string send_finding(const std::filesystem::path& state_dir,
                                    const FindingAnnouncementInput& finding);
    static std::string send_evidence_summary(const std::filesystem::path& state_dir,
                                             const std::string& summary_json);

    // RM1 central detection-policy plane. Both calls use the enrolled agent mTLS identity.
    static std::string fetch_rule_bundle(const std::filesystem::path& state_dir);
    static std::string acknowledge_rule_bundle(const std::filesystem::path& state_dir,
                                               std::uint64_t revision,
                                               const std::string& sha256,
                                               const std::string& status,
                                               const std::string& error = {});
};

} // namespace neta
