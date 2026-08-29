#pragma once

#include "neta/history_store.hpp"
#include "neta/platform.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace neta {

struct ObservationTarget {
    std::string host;
    std::uint16_t port{443};
    std::set<std::string> addresses;
};

struct ObservationRunResult {
    std::vector<std::int64_t> connection_ids;
    std::size_t admitted_connections{0};
    bool lifecycle_events_active{false};
};

class ObservationSession {
public:
    ObservationSession(HistoryStore& store,
                       platform::ConnectionObserver& socket_observer,
                       LifecycleObserver& lifecycle_observer,
                       platform::ProcessResolver& process_resolver,
                       platform::RouteObserver& route_observer,
                       ObservationTarget target);

    ObservationRunResult run(std::chrono::seconds duration,
                             std::chrono::milliseconds transport_poll_interval,
                             const std::function<bool()>& stop_requested);

private:
    bool matches_target(const SocketObservation& socket) const;
    bool matches_target(const ConnectionLifecycleEvent& event) const;

    HistoryStore& store_;
    platform::ConnectionObserver& socket_observer_;
    LifecycleObserver& lifecycle_observer_;
    platform::ProcessResolver& process_resolver_;
    platform::RouteObserver& route_observer_;
    ObservationTarget target_;
};

} // namespace neta
