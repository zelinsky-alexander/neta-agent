#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace neta {

struct BuildIdentity {
    std::string version;
    std::string build_id;
    std::string git_commit;
    std::string build_timestamp;
    std::string os;
    std::string arch;
    std::string artifact_sha256;
    int protocol_version{1};
    int schema_version{1};
    std::vector<std::string> features;
};

BuildIdentity current_build_identity(const std::filesystem::path& state_dir = {});
std::string build_identity_json(const BuildIdentity& build);

struct UpgradeInstruction {
    std::string upgrade_id;
    std::string version;
    std::string build_id;
    std::string git_commit;
    std::string os;
    std::string arch;
    std::string artifact_name;
    std::string download_url;
    std::string sha256;
};

enum class UpgradeLocalState {
    Received,
    Downloading,
    Verified,
    Failed
};

std::string to_string(UpgradeLocalState state);
UpgradeLocalState upgrade_local_state_from_string(const std::string& value);

struct UpgradeState {
    UpgradeInstruction instruction;
    UpgradeLocalState state{UpgradeLocalState::Received};
    std::filesystem::path download_path;
    std::string last_error;
};

std::optional<UpgradeInstruction> parse_upgrade_instruction_response(const std::string& response_body);
void validate_upgrade_instruction(const UpgradeInstruction& instruction, const BuildIdentity& local_build);

class UpgradeStateStore {
public:
    explicit UpgradeStateStore(std::filesystem::path state_dir);

    std::filesystem::path path() const;
    std::optional<UpgradeState> load() const;
    UpgradeState accept(const UpgradeInstruction& instruction, const BuildIdentity& local_build);
    void save(const UpgradeState& state) const;

private:
    std::filesystem::path state_dir_;
};

class ArtifactDownloader {
public:
    static constexpr std::size_t kDefaultMaxBytes = 256U * 1024U * 1024U;

    static std::filesystem::path download_and_verify(
        const UpgradeInstruction& instruction,
        const std::filesystem::path& destination_dir,
        std::size_t max_bytes = kDefaultMaxBytes);

    static void verify_file(const std::filesystem::path& path,
                            const std::string& expected_sha256,
                            std::size_t max_bytes = kDefaultMaxBytes);
};

std::optional<UpgradeState> accept_upgrade_from_coordinator_response(
    const std::filesystem::path& state_dir,
    const std::string& response_body);

UpgradeState download_pending_upgrade(const std::filesystem::path& state_dir,
                                      std::size_t max_bytes = ArtifactDownloader::kDefaultMaxBytes);

} // namespace neta
