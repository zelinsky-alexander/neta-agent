#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace neta {

struct ActiveRuleBundleState {
    std::filesystem::path path;
    std::string id;
    std::uint64_t revision{0};
    std::string version;
    std::string sha256;
    std::size_t rule_count{0};
    bool centrally_managed{false};
};

ActiveRuleBundleState update_rules_from_coordinator(const std::filesystem::path& state_dir);
ActiveRuleBundleState active_rule_bundle_state(const std::filesystem::path& state_dir);

} // namespace neta
