#pragma once

#include "neta/model.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neta::rules {

struct RuleExclusion {
    std::vector<std::string> process_names;
    std::vector<std::string> executable_paths;
    std::vector<std::string> process_path_prefixes;
    std::vector<std::string> parent_process_names;
    std::vector<std::string> users;
    std::vector<std::string> remote_hosts;
    std::vector<std::string> remote_ips;
    std::vector<std::string> remote_ports;
    std::vector<std::string> local_ports;
    std::vector<std::string> domains;
    std::vector<std::string> directions;

    [[nodiscard]] bool empty() const noexcept {
        return process_names.empty() && executable_paths.empty() && process_path_prefixes.empty() &&
               parent_process_names.empty() && users.empty() && remote_hosts.empty() &&
               remote_ips.empty() && remote_ports.empty() && local_ports.empty() &&
               domains.empty() && directions.empty();
    }
};

inline std::string exclusion_normalized(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        if (c == '\\') return '/';
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

inline bool exclusion_contains(const std::vector<std::string>& values, const std::string& candidate) {
    if (candidate.empty()) return false;
    const auto normalized = exclusion_normalized(candidate);
    return std::any_of(values.begin(), values.end(), [&](const std::string& value) {
        return exclusion_normalized(value) == normalized;
    });
}

inline bool exclusion_prefix(const std::vector<std::string>& values, const std::string& candidate) {
    if (candidate.empty()) return false;
    const auto normalized = exclusion_normalized(candidate);
    return std::any_of(values.begin(), values.end(), [&](const std::string& value) {
        const auto prefix = exclusion_normalized(value);
        return !prefix.empty() && normalized.starts_with(prefix);
    });
}

inline std::string process_basename(const ProcessIdentity& process) {
    const auto normalized = exclusion_normalized(process.executable_path);
    const auto slash = normalized.find_last_of('/');
    return slash == std::string::npos ? (!process.comm.empty() ? process.comm : normalized)
                                     : normalized.substr(slash + 1);
}

inline bool excludes_connection(const RuleExclusion& exclusion,
                                const ConnectionSummary& connection,
                                const std::vector<std::string>& correlated_domains = {},
                                const std::optional<std::string>& parent_process_name = std::nullopt) {
    if (exclusion.empty()) return false;
    if (exclusion_contains(exclusion.process_names, connection.process.comm) ||
        exclusion_contains(exclusion.process_names, process_basename(connection.process))) return true;
    if (exclusion_contains(exclusion.executable_paths, connection.process.executable_path) ||
        exclusion_prefix(exclusion.process_path_prefixes, connection.process.executable_path)) return true;
    if (exclusion_contains(exclusion.users, std::to_string(connection.process.uid))) return true;
    if (parent_process_name && exclusion_contains(exclusion.parent_process_names, *parent_process_name)) return true;
    if (exclusion_contains(exclusion.remote_hosts, connection.target_host) ||
        exclusion_contains(exclusion.remote_ips, connection.remote_ip)) return true;
    if (exclusion_contains(exclusion.remote_ports, std::to_string(connection.remote_port)) ||
        exclusion_contains(exclusion.local_ports, std::to_string(connection.local_port))) return true;
    for (const auto& domain : correlated_domains) if (exclusion_contains(exclusion.domains, domain)) return true;
    const auto direction = connection.direction == ConnectionDirection::Outbound ? "outbound" :
                           connection.direction == ConnectionDirection::Inbound ? "inbound" : "unknown";
    if (exclusion_contains(exclusion.directions, direction)) return true;
    return false;
}

} // namespace neta::rules
