#include "neta/process_graph.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace neta {

std::size_t ProcessInstanceKeyHash::operator()(const ProcessInstanceKey& key) const noexcept {
    std::size_t value = std::hash<std::int64_t>{}(key.pid);
    const auto mix = [&value](std::size_t next) {
        value ^= next + 0x9e3779b97f4a7c15ULL + (value << 6U) + (value >> 2U);
    };
    if (key.start_time_ns) mix(std::hash<std::uint64_t>{}(*key.start_time_ns));
    if (key.platform_key) mix(std::hash<std::uint64_t>{}(*key.platform_key));
    return value;
}

ProcessGraph::ProcessGraph(std::size_t max_nodes) : max_nodes_(max_nodes) {
    if (max_nodes_ == 0) throw std::invalid_argument("process graph capacity must be non-zero");
}

std::optional<ProcessInstanceKey> ProcessGraph::key_from(const ProcessExecEvent& event) const {
    if (!event.tgid || *event.tgid <= 0) return std::nullopt;
    ProcessInstanceKey key;
    key.pid = *event.tgid;
    key.platform_key = event.platform_process_key;
    if (!key.platform_key) key.start_time_ns = event.process_start_time_ns;
    if (!key.durable()) return std::nullopt;
    return key;
}

std::optional<ProcessInstanceKey> ProcessGraph::unique_active_key_for_pid(std::int64_t pid) const {
    const auto [begin, end] = active_by_pid_.equal_range(pid);
    if (begin == end) return std::nullopt;
    auto it = begin;
    const ProcessInstanceKey key = it->second;
    ++it;
    if (it != end) return std::nullopt;
    return key;
}

void ProcessGraph::index_active(const ProcessInstanceKey& key) {
    active_by_pid_.emplace(key.pid, key);
}

void ProcessGraph::unindex_active(const ProcessInstanceKey& key) {
    const auto [begin, end] = active_by_pid_.equal_range(key.pid);
    for (auto it = begin; it != end; ++it) {
        if (it->second == key) {
            active_by_pid_.erase(it);
            return;
        }
    }
}

void ProcessGraph::evict_if_needed() {
    while (nodes_.size() >= max_nodes_ && !insertion_order_.empty()) {
        const auto oldest = insertion_order_.front();
        insertion_order_.pop_front();
        const auto found = nodes_.find(oldest);
        if (found == nodes_.end()) continue;
        if (!found->second.exited_at_ns) unindex_active(found->first);
        nodes_.erase(found);
        ++health_.evicted_nodes;
    }
}

bool ProcessGraph::observe(const ProcessExecEvent& event) {
    auto key = key_from(event);
    if (!key && event.type == ProcessExecEventType::Exit && event.tgid && *event.tgid > 0) {
        key = unique_active_key_for_pid(*event.tgid);
        if (!key) {
            ++health_.ambiguous_exit_events;
            return false;
        }
    }
    if (!key) {
        ++health_.rejected_without_stable_identity;
        return false;
    }

    if (event.type == ProcessExecEventType::Exit) {
        const auto found = nodes_.find(*key);
        if (found == nodes_.end()) return false;
        found->second.exited_at_ns = event.timestamp_ns;
        found->second.exit_code = event.exit_code;
        unindex_active(found->first);
        return true;
    }

    const auto existing = nodes_.find(*key);
    if (existing != nodes_.end()) {
        auto& node = existing->second;
        node.uid = event.uid;
        node.gid = event.gid;
        node.session_id = event.session_id;
        node.user_identity = event.user_identity;
        node.integrity_level = event.integrity_level;
        node.elevated = event.elevated;
        node.comm = event.comm;
        node.executable_path = event.executable_path;
        node.command_line = event.command_line;
        node.working_directory = event.working_directory;
        return true;
    }

    evict_if_needed();

    ProcessNode node;
    node.key = *key;
    node.parent_pid = event.parent_tgid;
    node.uid = event.uid;
    node.gid = event.gid;
    node.session_id = event.session_id;
    node.user_identity = event.user_identity;
    node.integrity_level = event.integrity_level;
    node.elevated = event.elevated;
    node.comm = event.comm;
    node.executable_path = event.executable_path;
    node.command_line = event.command_line;
    node.working_directory = event.working_directory;
    node.started_at_ns = event.timestamp_ns;

    if (event.parent_tgid && *event.parent_tgid > 0) {
        ProcessInstanceKey parent_key;
        parent_key.pid = *event.parent_tgid;
        parent_key.platform_key = event.parent_platform_process_key;
        if (!parent_key.platform_key) {
            parent_key.start_time_ns = event.parent_process_start_time_ns;
        }
        if (parent_key.durable()) {
            node.parent = parent_key;
        } else {
            node.parent = unique_active_key_for_pid(*event.parent_tgid);
            if (!node.parent) {
                const auto [begin, end] = active_by_pid_.equal_range(*event.parent_tgid);
                if (begin != end) ++health_.ambiguous_parent_links;
            }
        }
    }

    const auto [inserted, ok] = nodes_.emplace(node.key, std::move(node));
    if (!ok) return false;
    insertion_order_.push_back(inserted->first);
    index_active(inserted->first);
    return true;
}

std::optional<ProcessNode> ProcessGraph::find(const ProcessInstanceKey& key) const {
    const auto found = nodes_.find(key);
    if (found == nodes_.end()) return std::nullopt;
    return found->second;
}

std::vector<ProcessNode> ProcessGraph::snapshot() const {
    std::vector<ProcessNode> result;
    result.reserve(nodes_.size());
    for (const auto& [key, node] : nodes_) {
        static_cast<void>(key);
        result.push_back(node);
    }
    std::sort(result.begin(), result.end(), [](const ProcessNode& left, const ProcessNode& right) {
        if (left.started_at_ns != right.started_at_ns) return left.started_at_ns < right.started_at_ns;
        return left.key.pid < right.key.pid;
    });
    return result;
}

std::size_t ProcessGraph::active_count() const noexcept {
    std::size_t count = 0;
    for (const auto& [key, node] : nodes_) {
        static_cast<void>(key);
        if (!node.exited_at_ns) ++count;
    }
    return count;
}

}  // namespace neta
