#pragma once

#include <filesystem>
#include <string>

namespace neta {

struct YaraXRuntimeUpdateResult {
    bool update_available{false};
    bool changed{false};
    std::string desired_version;
    std::string active_version;
    std::string state;
    std::string detail;
};

YaraXRuntimeUpdateResult update_yarax_runtime_from_coordinator(
    const std::filesystem::path& state_dir);

} // namespace neta
