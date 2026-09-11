#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace neta {

struct YaraXContentState {
    std::filesystem::path path;
    std::string bundle_id;
    std::uint64_t revision{0};
    std::string sha256;
    bool centrally_managed{false};
};

YaraXContentState update_yarax_content_from_coordinator(const std::filesystem::path& state_dir);
YaraXContentState active_yarax_content_state(const std::filesystem::path& state_dir);

} // namespace neta
