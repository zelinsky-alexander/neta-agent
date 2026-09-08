#pragma once

#include "neta/process_exec.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace neta {

struct ProcessInstanceKey {
    std::int64_t pid{0};
    std::optional<std::uint64_t> start_time_ns;
    std::optional<std::uint64_t> platform_key;

    [[nodiscard]] bool durable() const noexcept {
        return pid > 0 && (platform_key.has_value() || start_time_ns.has_value());
    }

    bool operator==(const ProcessInstanceKey&) const = default;
};

struct ProcessInstanceKeyHash {
    std::size_t operator()(const ProcessInstanceKey& key) const noexcept;
};

struct ProcessNode {
    ProcessInstanceKey key;
    std::optional<ProcessInstanceKey> parent;
    std::optional<std::int64_t> parent_pid;
    std::optional<std::uint32_t> uid;
    std::optional<std::uint32_t> gid;
    std::optional<std::uint32_t> session_id;
    std::string user_identity;
    std::string integrity_level;
    std::optional<bool> elevated;
    std::string comm;
    std::string executable_path;
    std::string command_line;
    std::string working_directory;
    std::uint64_t started_at_ns{0};
    std::optional<std::uint64_t> exited_at_ns;
    std::optional<std::int32_t> exit_code;
};

struct ProcessGraphHealth {
    std::uint64_t rejected_without_stable_identity{0};
    std::uint64_t ambiguous_parent_links{0};
    std::uint64_t ambiguous_exit_events{0};
    std::uint64_t evicted_nodes{0};
};

class ProcessGraph {
public:
    explicit ProcessGraph(std::size_t max_nodes = 32768);

    bool observe(const ProcessExecEvent& event);

    [[nodiscard]] std::optional<ProcessNode> find(const ProcessInstanceKey& key) const;
    [[nodiscard]] std::vector<ProcessNode> snapshot() const;
    [[nodiscard]] std::size_t active_count() const noexcept;
    [[nodiscard]] const ProcessGraphHealth& health() const noexcept { return health_; }

private:
    std::optional<ProcessInstanceKey> key_from(const ProcessExecEvent& event) const;
    std::optional<ProcessInstanceKey> unique_active_key_for_pid(std::int64_t pid) const;
    void index_active(const ProcessInstanceKey& key);
    void unindex_active(const ProcessInstanceKey& key);
    void evict_if_needed();

    std::size_t max_nodes_;
    std::unordered_map<ProcessInstanceKey, ProcessNode, ProcessInstanceKeyHash> nodes_;
    std::unordered_multimap<std::int64_t, ProcessInstanceKey> active_by_pid_;
    std::deque<ProcessInstanceKey> insertion_order_;
    ProcessGraphHealth health_;
};

}  // namespace neta
