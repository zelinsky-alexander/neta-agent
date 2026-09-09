#pragma once

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
    const auto normalized = exclusion_normalized(candidate);
    return std::any_of(values.begin(), values.end(), [&](const std::string& value) {
        return exclusion_normalized(value) == normalized;
    });
}

inline bool exclusion_prefix(const std::vector<std::string>& values, const std::string& candidate) {
    const auto normalized = exclusion_normalized(candidate);
    return std::any_of(values.begin(), values.end(), [&](const std::string& value) {
        const auto prefix = exclusion_normalized(value);
        return !prefix.empty() && normalized.starts_with(prefix);
    });
}

} // namespace neta::rules
