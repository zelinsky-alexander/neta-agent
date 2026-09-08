#pragma once

#include "neta/process_findings.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace neta {

struct StoredProcessFinding {
    std::string finding_id;
    std::string finding_key;
    std::string rule_id;
    std::string ruleset_version;
    std::string severity;
    std::string process_key;
    std::string parent_key;
    std::int64_t pid{0};
    std::optional<std::int64_t> parent_pid;
    std::string process_image;
    std::string parent_image;
    std::string command_line;
    std::string summary;
    std::string interpretation;
    std::string evidence_root;
    std::uint64_t observed_at_ns{0};
    std::uint64_t first_seen_ns{0};
    std::uint64_t last_seen_ns{0};
    std::uint64_t occurrence_count{0};
    std::string report_state;
};

class ProcessFindingStore {
public:
    explicit ProcessFindingStore(std::filesystem::path path);
    ~ProcessFindingStore();

    ProcessFindingStore(const ProcessFindingStore&) = delete;
    ProcessFindingStore& operator=(const ProcessFindingStore&) = delete;

    void upsert_process(const ProcessNode& node);
    StoredProcessFinding upsert_finding(const ProcessFinding& finding);
    std::vector<StoredProcessFinding> recent_findings(std::size_t limit) const;
    std::vector<StoredProcessFinding> pending_for_report(std::size_t limit,
                                                         std::uint64_t now_ns,
                                                         std::uint64_t retry_after_ns) const;
    void mark_report_attempt(const std::string& finding_id, std::uint64_t now_ns);
    void mark_reported(const std::string& finding_id, std::uint64_t now_ns);

private:
    void initialize_schema();
    void exec(const char* sql) const;

    std::filesystem::path path_;
    sqlite3* db_{nullptr};
};

[[nodiscard]] std::string stable_process_key(const ProcessInstanceKey& key);

}  // namespace neta
