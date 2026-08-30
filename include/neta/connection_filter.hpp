#pragma once

#include "neta/lifecycle.hpp"

#include <optional>
#include <set>
#include <string>

namespace neta {

struct ConnectionFilter {
    std::optional<std::uint16_t> local_port;
    std::optional<std::uint16_t> remote_port;
    std::set<std::string> include_processes;
    std::set<std::string> exclude_processes;
};

[[nodiscard]] bool matches_filter(const ConnectionFilter& filter,
                                  std::optional<std::uint16_t> local_port,
                                  std::optional<std::uint16_t> remote_port,
                                  const std::optional<std::string>& process_name);

} // namespace neta
