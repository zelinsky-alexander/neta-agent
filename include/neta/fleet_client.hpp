#pragma once

#include <cstdint>
#include <filesystem>
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
    std::string host;
    std::uint16_t port{0};
    std::string transport{"tcp"};
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
};

} // namespace neta
