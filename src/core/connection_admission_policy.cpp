#include "neta/connection_admission_policy.hpp"

#include <utility>

namespace neta {

ConnectionAdmissionPolicy::ConnectionAdmissionPolicy(AdmissionPolicyConfig config)
    : config_(std::move(config)) {}

bool ConnectionAdmissionPolicy::permits(ConnectionDirection direction) const noexcept {
    switch (config_.mode) {
        case ObservationMode::Target: return direction == ConnectionDirection::Outbound;
        case ObservationMode::Outbound: return direction == ConnectionDirection::Outbound;
        case ObservationMode::Inbound: return direction == ConnectionDirection::Inbound;
        case ObservationMode::All:
            return direction == ConnectionDirection::Outbound ||
                   direction == ConnectionDirection::Inbound;
    }
    return false;
}

AdmissionDecision ConnectionAdmissionPolicy::evaluate(
    const ConnectionLifecycleEvent& event) const {
    if (event.type == ConnectionLifecycleEventType::Close) {
        return {true, ConnectionDirection::Unknown};
    }
    if (!eligible_connection_seed(event.endpoint_kind) || !event.local || !event.remote) {
        return {};
    }
    const auto direction = event.type == ConnectionLifecycleEventType::Connect
        ? ConnectionDirection::Outbound
        : event.type == ConnectionLifecycleEventType::Accept
            ? ConnectionDirection::Inbound : ConnectionDirection::Unknown;
    if (!permits(direction)) return {};
    if (config_.mode == ObservationMode::Target &&
        (!event.remote->port || *event.remote->port != config_.target_port ||
         !config_.target_addresses.contains(event.remote->address))) {
        return {};
    }
    if (!matches_filter(config_.filter, event.local->port, event.remote->port,
                        event.process.comm)) return {};
    return {true, direction};
}

AdmissionDecision ConnectionAdmissionPolicy::evaluate_new_socket(
    const SocketObservation& socket,
    const std::optional<std::string>& process_name) const {
    if (!eligible_connection_seed(socket.endpoint_kind)) return {};
    // Snapshot discovery has no lifecycle direction evidence. Only target mode may use
    // it as the legacy discovery fallback, and direction remains explicitly unknown.
    if (config_.mode != ObservationMode::Target ||
        socket.remote_port != config_.target_port ||
        !config_.target_addresses.contains(socket.remote_ip) ||
        !matches_filter(config_.filter, socket.local_port, socket.remote_port, process_name)) {
        return {};
    }
    return {true, ConnectionDirection::Unknown};
}

AdmissionDecision ConnectionAdmissionPolicy::evaluate_reconciliation_socket(
    const SocketObservation& socket,
    const std::optional<std::string>& process_name) const {
    if (!eligible_connection_seed(socket.endpoint_kind)) return {};
    if (!matches_filter(config_.filter, socket.local_port, socket.remote_port, process_name)) {
        return {};
    }
    if (config_.mode == ObservationMode::Target) {
        if (socket.remote_port != config_.target_port ||
            !config_.target_addresses.contains(socket.remote_ip)) {
            return {};
        }
        return {true, ConnectionDirection::Unknown};
    }
    if (config_.mode == ObservationMode::All) {
        return {true, ConnectionDirection::Unknown};
    }
    // OUTBOUND/INBOUND modes must not convert an UNKNOWN snapshot into a directional claim.
    return {};
}

bool ConnectionAdmissionPolicy::has_process_filters() const noexcept {
    return !config_.filter.include_processes.empty() ||
           !config_.filter.exclude_processes.empty();
}

} // namespace neta
