#pragma once

#include "neta/history_store.hpp"
#include "neta/connection_admission_policy.hpp"
#include "neta/storage_maintenance.hpp"
#include "neta/platform.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
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
    bool name_resolution_events_active{false};
    std::size_t name_resolution_events_observed{0};
    std::size_t name_resolution_evidence_attached{0};
    std::size_t ambiguous_name_resolution_matches{0};
    bool tls_session_events_active{false};
    std::size_t tls_session_events_observed{0};
    std::size_t tls_session_evidence_attached{0};
    std::size_t ambiguous_tls_session_matches{0};
};

class ObservationSession {
public:
    ObservationSession(HistoryStore& store,
                       platform::ConnectionObserver& socket_observer,
                       LifecycleObserver& lifecycle_observer,
                       platform::ProcessResolver& process_resolver,
                       platform::RouteObserver& route_observer,
                       ConnectionAdmissionPolicy admission_policy,
                       std::string target_label,
                       StorageMaintenance* storage_maintenance = nullptr,
                       NameResolutionObserver* name_resolution_observer = nullptr,
                       TlsSessionObserver* tls_session_observer = nullptr);

    ObservationRunResult run(std::optional<std::chrono::seconds> duration,
                             std::chrono::milliseconds transport_poll_interval,
                             const std::function<bool()>& stop_requested,
                             const std::function<void()>& observation_started = {});

private:
    HistoryStore& store_;
    platform::ConnectionObserver& socket_observer_;
    LifecycleObserver& lifecycle_observer_;
    platform::ProcessResolver& process_resolver_;
    platform::RouteObserver& route_observer_;
    ConnectionAdmissionPolicy admission_policy_;
    std::string target_label_;
    StorageMaintenance* storage_maintenance_;
    NameResolutionObserver* name_resolution_observer_;
    TlsSessionObserver* tls_session_observer_;
};

} // namespace neta
