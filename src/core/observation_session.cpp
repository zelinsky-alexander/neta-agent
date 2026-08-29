#include "neta/observation_session.hpp"

#include "neta/connection_tracker.hpp"

#include <algorithm>
#include <chrono>
#include <set>
#include <thread>
#include <utility>

namespace neta {

ObservationSession::ObservationSession(HistoryStore& store,
                                       platform::ConnectionObserver& socket_observer,
                                       LifecycleObserver& lifecycle_observer,
                                       platform::ProcessResolver& process_resolver,
                                       platform::RouteObserver& route_observer,
                                       ObservationTarget target)
    : store_(store),
      socket_observer_(socket_observer),
      lifecycle_observer_(lifecycle_observer),
      process_resolver_(process_resolver),
      route_observer_(route_observer),
      target_(std::move(target)) {}

bool ObservationSession::matches_target(const SocketObservation& socket) const {
    return socket.remote_port == target_.port && target_.addresses.contains(socket.remote_ip);
}

bool ObservationSession::matches_target(const ConnectionLifecycleEvent& event) const {
    if (event.type == ConnectionLifecycleEventType::Close) return true;
    if (event.type != ConnectionLifecycleEventType::Connect || !event.remote ||
        !event.remote->port) {
        return false;
    }
    return *event.remote->port == target_.port &&
           target_.addresses.contains(event.remote->address);
}

ObservationRunResult ObservationSession::run(
    std::chrono::seconds duration,
    std::chrono::milliseconds transport_poll_interval,
    const std::function<bool()>& stop_requested) {
    ConnectionTracker tracker(store_, process_resolver_, target_.host);
    ObservationRunResult result;
    result.lifecycle_events_active = lifecycle_observer_.capability().outbound_available();
    std::set<std::int64_t> connection_ids;

    const auto admit_route = [&](const ConnectionAdmission& admission,
                                 const std::string& remote_address) {
        if (!admission.newly_admitted) return;
        ++result.admitted_connections;
        connection_ids.insert(admission.connection_id);
        if (const auto route = route_observer_.route_to(remote_address)) {
            store_.add_route(admission.connection_id, *route);
        }
    };

    const auto sample_transport = [&] {
        tracker.begin_snapshot();
        for (const auto& socket : socket_observer_.snapshot()) {
            if (!matches_target(socket)) continue;
            const auto admission = tracker.observe_socket(socket);
            if (admission) admit_route(*admission, socket.remote_ip);
        }
        tracker.end_snapshot(!result.lifecycle_events_active);
    };

    const auto deadline = std::chrono::steady_clock::now() + duration;
    auto next_transport_sample = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() < deadline && !stop_requested()) {
        bool lifecycle_admitted = false;
        if (result.lifecycle_events_active) {
            const auto now = std::chrono::steady_clock::now();
            const auto wake_at = std::min(deadline, next_transport_sample);
            const auto timeout = wake_at > now
                ? std::chrono::duration_cast<std::chrono::milliseconds>(wake_at - now)
                : std::chrono::milliseconds(0);
            for (const auto& event : lifecycle_observer_.poll(timeout)) {
                if (!matches_target(event)) continue;
                const auto admission = tracker.observe_lifecycle(event);
                if (admission && admission->newly_admitted && event.remote) {
                    admit_route(*admission, event.remote->address);
                    lifecycle_admitted = true;
                }
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (!result.lifecycle_events_active || lifecycle_admitted || now >= next_transport_sample) {
            sample_transport();
            next_transport_sample = std::chrono::steady_clock::now() + transport_poll_interval;
        }
        if (!result.lifecycle_events_active) std::this_thread::sleep_for(transport_poll_interval);
    }

    tracker.finish_observation(!result.lifecycle_events_active);
    result.connection_ids.assign(connection_ids.begin(), connection_ids.end());
    return result;
}

} // namespace neta
