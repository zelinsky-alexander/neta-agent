#pragma once

#include "neta/antimalware.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

struct sqlite3;

namespace neta {

struct StoredArtifactEvidence {
    std::string artifact_sha256;
    std::string artifact_path;
    std::uint64_t artifact_size{0};
    std::string provider_name;
    std::string provider_version;
    std::string ruleset_id;
    std::string ruleset_sha256;
    std::string state;
    std::string detail;
    std::uint64_t first_observed_ns{0};
    std::uint64_t last_observed_ns{0};
    std::uint64_t observation_count{0};
    std::vector<AntimalwareMatch> matches;
};

class ArtifactEvidenceStore {
public:
    explicit ArtifactEvidenceStore(std::filesystem::path path);
    ~ArtifactEvidenceStore();

    ArtifactEvidenceStore(const ArtifactEvidenceStore&) = delete;
    ArtifactEvidenceStore& operator=(const ArtifactEvidenceStore&) = delete;

    void record(const ArtifactIdentity& artifact,
                const AntimalwareEvidence& evidence,
                std::uint64_t observed_at_ns);
    std::vector<StoredArtifactEvidence> recent(std::size_t limit) const;

private:
    void initialize_schema();
    void exec(const char* sql) const;

    std::filesystem::path path_;
    sqlite3* db_{nullptr};
};

}  // namespace neta
