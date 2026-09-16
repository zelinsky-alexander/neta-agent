#include "sensor_broker_process_registry.hpp"

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <limits>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace neta::windows_sensor_broker {
namespace {

struct Ownership {
    std::string slot;
    std::optional<std::uint64_t> process_key;
    bool root{false};
};

std::unordered_map<std::uint32_t, std::uint32_t> process_parents() {
    std::unordered_map<std::uint32_t, std::uint32_t> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry) != FALSE) {
        do {
            result[entry.th32ProcessID] = entry.th32ParentProcessID;
        } while (Process32NextW(snapshot, &entry) != FALSE);
    }
    CloseHandle(snapshot);
    return result;
}

}  // namespace

class EndpointProcessRegistry::Impl {
public:
    void register_endpoint(std::string slot, std::uint32_t root_pid) {
        if (slot.empty() || root_pid == 0) {
            throw std::runtime_error("Windows broker mapping requires non-empty slot and non-zero root PID");
        }
        std::lock_guard lock(mutex_);
        if (const auto existing = roots_.find(root_pid); existing != roots_.end() && existing->second != slot) {
            throw std::runtime_error("Windows broker root PID is already assigned to another endpoint");
        }
        roots_[root_pid] = slot;
        owners_[root_pid] = Ownership{std::move(slot), std::nullopt, true};
    }

    std::optional<std::string> resolve_pid(std::uint32_t pid) {
        if (pid == 0) return std::nullopt;
        {
            std::lock_guard lock(mutex_);
            const auto known = owners_.find(pid);
            if (known != owners_.end()) return known->second.slot;
        }

        const auto parents = process_parents();
        std::vector<std::uint32_t> path;
        std::unordered_set<std::uint32_t> visited;
        std::uint32_t current = pid;
        std::optional<std::string> slot;
        for (std::size_t depth = 0; current != 0 && depth < 128; ++depth) {
            if (!visited.insert(current).second) break;
            path.push_back(current);
            {
                std::lock_guard lock(mutex_);
                if (const auto known = owners_.find(current); known != owners_.end()) {
                    slot = known->second.slot;
                    break;
                }
                if (const auto root = roots_.find(current); root != roots_.end()) {
                    slot = root->second;
                    break;
                }
            }
            const auto parent = parents.find(current);
            if (parent == parents.end() || parent->second == current) break;
            current = parent->second;
        }
        if (!slot) return std::nullopt;

        std::lock_guard lock(mutex_);
        for (const auto member : path) {
            if (!roots_.contains(member)) owners_[member] = Ownership{*slot, std::nullopt, false};
        }
        return slot;
    }

    std::optional<std::string> observe(const ProcessExecEvent& event) {
        if (!event.pid || *event.pid <= 0 ||
            static_cast<std::uint64_t>(*event.pid) > static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())) {
            return std::nullopt;
        }
        const auto pid = static_cast<std::uint32_t>(*event.pid);

        if (event.type == ProcessExecEventType::Start) {
            std::optional<std::string> slot;
            if (event.parent_pid && *event.parent_pid > 0 &&
                static_cast<std::uint64_t>(*event.parent_pid) <= static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())) {
                slot = resolve_pid(static_cast<std::uint32_t>(*event.parent_pid));
            }
            if (!slot) slot = resolve_pid(pid);
            if (!slot) return std::nullopt;
            std::lock_guard lock(mutex_);
            owners_[pid] = Ownership{*slot, event.platform_process_key, roots_.contains(pid)};
            return slot;
        }

        std::optional<std::string> slot;
        {
            std::lock_guard lock(mutex_);
            const auto known = owners_.find(pid);
            if (known != owners_.end()) slot = known->second.slot;
        }
        if (!slot) slot = resolve_pid(pid);
        if (!slot) return std::nullopt;

        std::lock_guard lock(mutex_);
        const auto known = owners_.find(pid);
        if (known != owners_.end() && !known->second.root) {
            const bool same_instance = !event.platform_process_key || !known->second.process_key ||
                                       *event.platform_process_key == *known->second.process_key;
            if (same_instance) owners_.erase(known);
        }
        return slot;
    }

    bool endpoint_owns(const std::string& slot, std::uint32_t pid) {
        const auto resolved = resolve_pid(pid);
        return resolved && *resolved == slot;
    }

    std::size_t endpoint_count() const {
        std::lock_guard lock(mutex_);
        return roots_.size();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::uint32_t, std::string> roots_;
    std::unordered_map<std::uint32_t, Ownership> owners_;
};

EndpointProcessRegistry::EndpointProcessRegistry() : impl_(std::make_unique<Impl>()) {}
EndpointProcessRegistry::~EndpointProcessRegistry() = default;
EndpointProcessRegistry::EndpointProcessRegistry(EndpointProcessRegistry&&) noexcept = default;
EndpointProcessRegistry& EndpointProcessRegistry::operator=(EndpointProcessRegistry&&) noexcept = default;

void EndpointProcessRegistry::register_endpoint(std::string slot, std::uint32_t root_pid) {
    impl_->register_endpoint(std::move(slot), root_pid);
}

std::optional<std::string> EndpointProcessRegistry::resolve_pid(std::uint32_t pid) {
    return impl_->resolve_pid(pid);
}

std::optional<std::string> EndpointProcessRegistry::observe(const ProcessExecEvent& event) {
    return impl_->observe(event);
}

bool EndpointProcessRegistry::endpoint_owns(const std::string& slot, std::uint32_t pid) {
    return impl_->endpoint_owns(slot, pid);
}

std::size_t EndpointProcessRegistry::endpoint_count() const {
    return impl_->endpoint_count();
}

}  // namespace neta::windows_sensor_broker

#endif
