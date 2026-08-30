#pragma once

#include "neta/connection_admission_policy.hpp"
#include "neta/observation_session.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace neta::cli {

struct ObservationOptions {
    ObservationMode mode{ObservationMode::Target};
    std::optional<ObservationTarget> target;
    ConnectionFilter filter;
    std::optional<std::chrono::seconds> duration;
    std::optional<std::chrono::milliseconds> transport_interval;
    std::chrono::seconds maintenance_interval{60};
    std::string database{"neta.db"};
    std::string ca_file;
    std::uint64_t max_database_bytes{200ULL * 1024ULL * 1024ULL};
};

ObservationOptions parse_observation_options(int argc, char** argv, bool service_mode);
ObservationTarget resolve_observation_target(const std::string& value);

} // namespace neta::cli
