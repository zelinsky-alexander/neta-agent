#pragma once

#include "neta/connection_direction.hpp"
#include "neta/connection_filter.hpp"
#include "neta/model.hpp"

#include <cstdint>
#include <set>
#include <string>

namespace neta {

enum class ObservationMode { Target, Outbound, Inbound, All };

struct AdmissionPolicyConfig {
    ObservationMode mode{ObservationMode::Target};
    ConnectionFilter filter;
    std::set<std::string> target_addresses;
    std::uint16_t target_port{0};
};

struct AdmissionDecision {
    bool admit{false};
    ConnectionDirection direction{ConnectionDirection::Unknown};
};

class ConnectionAdmissionPolicy {
public:
    explicit ConnectionAdmissionPolicy(AdmissionPolicyConfig config);

    [[nodiscard]] AdmissionDecision evaluate(
        const ConnectionLifecycleEvent& event) const;
    [[nodiscard]] AdmissionDecision evaluate_new_socket(
        const SocketObservation& socket,
        const std::optional<std::string>& process_name = std::nullopt) const;

    [[nodiscard]] ObservationMode mode() const noexcept { return config_.mode; }
    [[nodiscard]] bool has_process_filters() const noexcept;

private:
    [[nodiscard]] bool permits(ConnectionDirection direction) const noexcept;

    AdmissionPolicyConfig config_;
};

} // namespace neta
