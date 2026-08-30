#include "neta/connection_filter.hpp"

namespace neta {

bool matches_filter(const ConnectionFilter& filter,
                    std::optional<std::uint16_t> local_port,
                    std::optional<std::uint16_t> remote_port,
                    const std::optional<std::string>& process_name) {
    if (filter.local_port && local_port != filter.local_port) return false;
    if (filter.remote_port && remote_port != filter.remote_port) return false;
    if (!filter.include_processes.empty() &&
        (!process_name || !filter.include_processes.contains(*process_name))) {
        return false;
    }
    if (!filter.exclude_processes.empty() && !process_name) return false;
    return !process_name || !filter.exclude_processes.contains(*process_name);
}

} // namespace neta
