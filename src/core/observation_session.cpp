#include "neta/observation_session.hpp"

#include "neta/connection_tracker.hpp"
#include "neta/evidence_scheduler.hpp"

#include <algorithm>
#include <chrono>
#include <set>
#include <thread>
#include <unordered_map>
#include <utility>

namespace neta {

ObservationSession::ObservationSession(HistoryStore& store,
                                       platform::ConnectionObserver& socket_observer,
                                       LifecycleObserver& lifecycle_observer,
                                       platform::ProcessResolver& process_resolver,
                                       platform::RouteObserver& route_observer,
                                       ConnectionAdmissionPolicy admission_policy,
                                       std::string target_label,
                                       StorageMaintenance* storage_maintenance)
    : store_(store),
      socket_observer_(socket_observer),
      lifecycle_observer_(lifecycle_observer),
      process_resolver_(process_resolver),
      route_observer_(route_observer),
      admission_policy_(std::move(admission_policy)),
      target_label_(std::move(target_label)),
      storage_maintenance_(storage_maintenance) {}

ObservationRunResult ObservationSession::run(
    std::optional<std::chrono::seconds> duration,
    std::chrono::milliseconds transport_poll_interval,
    const std::function<bool()>& stop_requested,
    const std::function<void()>& observation_started) {
    ConnectionTracker tracker(store_, process_resolver_, target_label_);
    EvidenceScheduler scheduler(transport_poll_interval);
    ObservationRunResult result;
    const auto& capability = lifecycle_observer_.capability();
    switch (admission_policy_.mode()) {
        case ObservationMode::Target:
        case ObservationMode::Outbound:
            result.lifecycle_events_active = capability.outbound_available();
            break;
        case ObservationMode::Inbound:
            result.lifecycle_events_active = capability.accept_events && capability.close_events;
            break;
        case ObservationMode::All:
            result.lifecycle_events_active = capability.available();
            break;
    }
    std::set<std::int64_t> connection_ids;
    struct RouteRequest {
        std::string remote_address;
        ConnectionDirection direction{ConnectionDirection::Unknown};
    };
    std::unordered_map<std::int64_t, RouteRequest> route_requests;

    const auto record_admission = [&](const ConnectionAdmission& admission,
                                      const std::string& remote_address,
                                      ConnectionDirection direction) {
        if (!admission.newly_admitted) return;
        scheduler.connection_admitted(admission.connection_id);
        ++result.admitted_connections;
        connection_ids.insert(admission.connection_id);
        route_requests.emplace(admission.connection_id,
                               RouteRequest{remote_address, direction});
    };

    const auto sample_transport = [&] {
        tracker.begin_snapshot();
        for (const auto& socket : socket_observer_.snapshot()) {
            std::optional<std::string> process_name;
            if (admission_policy_.has_process_filters()) {
                if (const auto process = process_resolver_.resolve(socket.socket_inode)) {
                    process_name = process->comm;
                }
            }
            const auto decision = admission_policy_.evaluate_new_socket(socket, process_name);
            const auto admission = tracker.observe_socket(
                socket, decision.direction, decision.admit);
            if (admission) record_admission(*admission, socket.remote_ip, decision.direction);
        }
        for (const auto connection_id :
             tracker.end_snapshot(!result.lifecycle_events_active)) {
            scheduler.connection_closed(connection_id);
            route_requests.erase(connection_id);
        }
    };

    const auto observe_scheduled_routes = [&] {
        for (const auto connection_id : scheduler.take_route_observations_due()) {
            const auto request = route_requests.find(connection_id);
            if (request == route_requests.end()) continue;
            if (auto route = route_observer_.route_to(request->second.remote_address)) {
                route->relation = request->second.direction == ConnectionDirection::Outbound
                    ? RouteRelation::OutboundSelectedRoute
                    : request->second.direction == ConnectionDirection::Inbound
                        ? RouteRelation::InboundResponseRoute : RouteRelation::Unknown;
                store_.add_route(connection_id, *route);
            }
            route_requests.erase(request);
        }
    };

    const auto deadline = duration
        ? std::optional{std::chrono::steady_clock::now() + *duration} : std::nullopt;
    if (observation_started) observation_started();
    while ((!deadline || std::chrono::steady_clock::now() < *deadline) && !stop_requested()) {
        if (result.lifecycle_events_active) {
            const auto now = std::chrono::steady_clock::now();
            const auto timeout = deadline
                ? std::min(scheduler.wait_time(now),
                           std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - now))
                : scheduler.wait_time(now);
            for (const auto& event : lifecycle_observer_.poll(timeout)) {
                const auto decision = admission_policy_.evaluate(event);
                if (!decision.admit) continue;
                const auto admission = tracker.observe_lifecycle(event, decision.direction);
                if (admission && admission->closed) {
                    scheduler.connection_closed(admission->connection_id);
                    route_requests.erase(admission->connection_id);
                }
                if (admission && admission->newly_admitted && event.remote) {
                    record_admission(*admission, event.remote->address, decision.direction);
                    // A lifecycle poll may also contain CLOSE for a short-lived socket.
                    // Sample while the admission is being handled, before a later event
                    // can retire its scheduler state.
                    sample_transport();
                    scheduler.transport_sampled(std::chrono::steady_clock::now());
                    observe_scheduled_routes();
                }
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (scheduler.transport_due(now, !result.lifecycle_events_active)) {
            sample_transport();
            scheduler.transport_sampled(std::chrono::steady_clock::now());
            observe_scheduled_routes();
        }
        if (storage_maintenance_) {
            static_cast<void>(storage_maintenance_->run_if_due(now));
        }
        if (!result.lifecycle_events_active) std::this_thread::sleep_for(transport_poll_interval);
    }

    tracker.finish_observation(!result.lifecycle_events_active);
    result.connection_ids.assign(connection_ids.begin(), connection_ids.end());
    return result;
}

} // namespace neta
