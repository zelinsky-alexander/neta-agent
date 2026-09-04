#include "neta/observation_session.hpp"

#include "neta/connection_tracker.hpp"
#include "neta/evidence_scheduler.hpp"

#include <algorithm>
#include <chrono>
#include <set>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace neta {
namespace {

constexpr std::uint64_t snapshot_reconciliation_grace_ns = 250'000'000ULL;
constexpr std::uint64_t snapshot_candidate_stale_ns = 5'000'000'000ULL;
constexpr std::size_t max_snapshot_reconciliation_candidates = 4096;

std::string snapshot_tuple_key(const SocketObservation& socket,
                               const std::optional<ProcessIdentity>& process) {
    std::string key = socket.local_ip + ':' + std::to_string(socket.local_port) + "->" +
                      socket.remote_ip + ':' + std::to_string(socket.remote_port);
    if (process) {
        key += "|pid:" + std::to_string(process->pid) +
               "|start:" + std::to_string(process->start_ticks.value_or(0));
    } else if (socket.owning_pid) {
        key += "|pid:" + std::to_string(*socket.owning_pid) + "|start:0";
    }
    return key;
}

std::string lifecycle_tuple_key(const ConnectionLifecycleEvent& event, bool reverse = false) {
    if (!event.local || !event.remote) return {};
    const auto& local = reverse ? *event.remote : *event.local;
    const auto& remote = reverse ? *event.local : *event.remote;
    std::string key = local.address + ':' + std::to_string(local.port.value_or(0)) + "->" +
                      remote.address + ':' + std::to_string(remote.port.value_or(0));
    if (event.process.agent_visible.tgid) {
        key += "|pid:" + std::to_string(*event.process.agent_visible.tgid) +
               "|start:" + std::to_string(event.process.start_ticks.value_or(0));
    }
    return key;
}

} // namespace

ObservationSession::ObservationSession(HistoryStore& store,
                                       platform::ConnectionObserver& socket_observer,
                                       LifecycleObserver& lifecycle_observer,
                                       platform::ProcessResolver& process_resolver,
                                       platform::RouteObserver& route_observer,
                                       ConnectionAdmissionPolicy admission_policy,
                                       std::string target_label,
                                       StorageMaintenance* storage_maintenance,
                                       NameResolutionObserver* name_resolution_observer,
                                       TlsSessionObserver* tls_session_observer)
    : store_(store),
      socket_observer_(socket_observer),
      lifecycle_observer_(lifecycle_observer),
      process_resolver_(process_resolver),
      route_observer_(route_observer),
      admission_policy_(std::move(admission_policy)),
      target_label_(std::move(target_label)),
      storage_maintenance_(storage_maintenance),
      name_resolution_observer_(name_resolution_observer),
      tls_session_observer_(tls_session_observer) {}

ObservationRunResult ObservationSession::run(
    std::optional<std::chrono::seconds> duration,
    std::chrono::milliseconds transport_poll_interval,
    const std::function<bool()>& stop_requested,
    const std::function<void()>& observation_started) {
    ObservationRuntimeCallbacks callbacks;
    callbacks.started = observation_started;
    return run(duration, transport_poll_interval, stop_requested, callbacks);
}

ObservationRunResult ObservationSession::run(
    std::optional<std::chrono::seconds> duration,
    std::chrono::milliseconds transport_poll_interval,
    const std::function<bool()>& stop_requested,
    const ObservationRuntimeCallbacks& callbacks) {
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
    result.name_resolution_events_active = name_resolution_observer_ != nullptr &&
        name_resolution_observer_->capability().available();
    result.tls_session_events_active = tls_session_observer_ != nullptr &&
        tls_session_observer_->capability().available();

    std::set<std::int64_t> connection_ids;
    constexpr auto completion_evidence_grace = std::chrono::milliseconds(350);
    std::unordered_map<std::int64_t, std::chrono::steady_clock::time_point>
        pending_completed_connections;
    std::set<std::int64_t> dispatched_completed_connections;
    struct RouteRequest {
        std::string remote_address;
        ConnectionDirection direction{ConnectionDirection::Unknown};
    };
    std::unordered_map<std::int64_t, RouteRequest> route_requests;

    struct PendingSnapshotCandidate {
        SocketObservation socket;
        std::optional<ProcessIdentity> process;
        std::uint64_t first_seen_ns{0};
        std::uint64_t last_seen_ns{0};
        bool startup{false};
    };
    std::unordered_map<std::string, PendingSnapshotCandidate> pending_snapshot_candidates;

    constexpr std::size_t max_name_resolution_observations = 4096;
    const NameResolutionCorrelationPolicy name_resolution_policy{};
    std::vector<NameResolutionObservation> name_resolution_observations;

    constexpr std::size_t max_tls_session_observations = 4096;
    const TlsSessionCorrelationPolicy tls_session_policy{};
    std::vector<TlsSessionObservation> tls_session_observations;
    std::set<std::string> attached_tls_session_keys;

    const auto drain_name_resolution = [&] {
        if (!result.name_resolution_events_active) return;
        auto observations = name_resolution_observer_->poll(std::chrono::milliseconds(0));
        result.name_resolution_events_observed += observations.size();
        for (auto& observation : observations) {
            if (observation.completed_ns != 0) {
                name_resolution_observations.push_back(std::move(observation));
            }
        }
        if (name_resolution_observations.empty()) return;
        std::sort(name_resolution_observations.begin(), name_resolution_observations.end(),
                  [](const auto& left, const auto& right) {
                      return left.completed_ns < right.completed_ns;
                  });
        const auto newest = name_resolution_observations.back().completed_ns;
        const auto threshold = newest > name_resolution_policy.max_age_ns
            ? newest - name_resolution_policy.max_age_ns : 0;
        const auto first_current = std::lower_bound(
            name_resolution_observations.begin(), name_resolution_observations.end(), threshold,
            [](const auto& observation, std::uint64_t value) {
                return observation.completed_ns < value;
            });
        name_resolution_observations.erase(name_resolution_observations.begin(), first_current);
        if (name_resolution_observations.size() > max_name_resolution_observations) {
            const auto excess = name_resolution_observations.size() -
                                max_name_resolution_observations;
            name_resolution_observations.erase(
                name_resolution_observations.begin(),
                name_resolution_observations.begin() +
                    static_cast<std::vector<NameResolutionObservation>::difference_type>(excess));
        }
    };

    const auto attach_name_resolution = [&](std::int64_t connection_id,
                                            ConnectionDirection direction) {
        if (!result.name_resolution_events_active || direction != ConnectionDirection::Outbound) {
            return;
        }
        const auto connection = store_.connection(connection_id);
        if (!connection) return;
        const auto correlation = correlate_name_resolution(
            *connection, name_resolution_observations, name_resolution_policy);
        if (correlation.status == NameResolutionCorrelationStatus::Ambiguous) {
            ++result.ambiguous_name_resolution_matches;
            return;
        }
        if (correlation.status == NameResolutionCorrelationStatus::Matched &&
            correlation.evidence) {
            store_.add_name_resolution_evidence(connection_id, *correlation.evidence);
            ++result.name_resolution_evidence_attached;
        }
    };

    const auto correlate_tls_sessions = [&] {
        if (!result.tls_session_events_active || tls_session_observations.empty() ||
            connection_ids.empty()) {
            return;
        }
        std::vector<ConnectionSummary> connections;
        connections.reserve(connection_ids.size());
        for (const auto connection_id : connection_ids) {
            if (const auto connection = store_.connection(connection_id)) {
                connections.push_back(*connection);
            }
        }
        if (connections.empty()) return;

        std::uint64_t correlation_watermark_ns = 0;
        for (const auto& connection : connections) {
            correlation_watermark_ns = std::max(correlation_watermark_ns,
                                                connection.last_seen_ns);
        }
        for (const auto& observation : tls_session_observations) {
            correlation_watermark_ns = std::max(correlation_watermark_ns,
                                                observation.observed_ns);
        }

        std::vector<TlsSessionObservation> unresolved;
        unresolved.reserve(tls_session_observations.size());
        for (auto& observation : tls_session_observations) {
            if (correlation_watermark_ns > observation.observed_ns &&
                correlation_watermark_ns - observation.observed_ns >
                    tls_session_policy.tuple_max_age_ns) {
                continue;
            }
            const auto correlation = correlate_tls_session(
                observation, connections, tls_session_policy);
            if (correlation.status == TlsSessionCorrelationStatus::Ambiguous) {
                ++result.ambiguous_tls_session_matches;
                continue;
            }
            if (correlation.status == TlsSessionCorrelationStatus::Matched &&
                correlation.connection_id && correlation.evidence) {
                const auto key = tls_session_identity_key(correlation.evidence->observation);
                if (attached_tls_session_keys.insert(key).second) {
                    const auto connection_id = *correlation.connection_id;
                    store_.add_tls_session_evidence(connection_id, *correlation.evidence);
                    ++result.tls_session_evidence_attached;

                    const auto now = std::chrono::steady_clock::now();
                    if (const auto pending = pending_completed_connections.find(connection_id);
                        pending != pending_completed_connections.end()) {
                        pending->second = now;
                    } else if (dispatched_completed_connections.erase(connection_id) != 0) {
                        pending_completed_connections.emplace(connection_id, now);
                    }
                }
                continue;
            }
            unresolved.push_back(std::move(observation));
        }
        tls_session_observations = std::move(unresolved);
    };

    const auto drain_tls_sessions = [&] {
        if (!result.tls_session_events_active) return;
        auto observations = tls_session_observer_->poll(std::chrono::milliseconds(0));
        result.tls_session_events_observed += observations.size();
        for (auto& observation : observations) {
            if (observation.observed_ns != 0) {
                tls_session_observations.push_back(std::move(observation));
            }
        }
        if (tls_session_observations.size() > max_tls_session_observations) {
            const auto excess = tls_session_observations.size() -
                                max_tls_session_observations;
            tls_session_observations.erase(
                tls_session_observations.begin(),
                tls_session_observations.begin() +
                    static_cast<std::vector<TlsSessionObservation>::difference_type>(excess));
        }
        correlate_tls_sessions();
    };

    const auto dispatch_completed = [&](bool force = false) {
        if (!callbacks.connection_completed) {
            pending_completed_connections.clear();
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        for (auto it = pending_completed_connections.begin();
             it != pending_completed_connections.end();) {
            if (!force && it->second > now) {
                ++it;
                continue;
            }
            const auto connection_id = it->first;
            it = pending_completed_connections.erase(it);
            if (dispatched_completed_connections.insert(connection_id).second) {
                callbacks.connection_completed(connection_id);
            }
        }
    };

    const auto completion_wait_time = [&](std::chrono::steady_clock::time_point now) {
        auto wait = std::chrono::milliseconds::max();
        for (const auto& [connection_id, due] : pending_completed_connections) {
            static_cast<void>(connection_id);
            if (due <= now) return std::chrono::milliseconds(0);
            wait = std::min(wait,
                            std::chrono::duration_cast<std::chrono::milliseconds>(due - now));
        }
        return wait;
    };

    const auto queue_completed = [&](std::int64_t connection_id) {
        pending_completed_connections.insert_or_assign(
            connection_id, std::chrono::steady_clock::now() + completion_evidence_grace);
    };

    const auto record_admission = [&](const ConnectionAdmission& admission,
                                      const std::string& remote_address,
                                      ConnectionDirection direction) {
        if (!admission.newly_admitted) return;
        scheduler.connection_admitted(admission.connection_id);
        ++result.admitted_connections;
        connection_ids.insert(admission.connection_id);
        route_requests.emplace(admission.connection_id,
                               RouteRequest{remote_address, direction});
        attach_name_resolution(admission.connection_id, direction);
        correlate_tls_sessions();
    };

    const auto record_direction_promotion = [&](const ConnectionAdmission& admission,
                                                const std::string& remote_address) {
        if (!admission.direction_promoted) return;
        auto route = route_requests.find(admission.connection_id);
        if (route != route_requests.end()) {
            route->second.direction = admission.direction;
            route->second.remote_address = remote_address;
        }
        attach_name_resolution(admission.connection_id, admission.direction);
    };

    const auto erase_candidate_for_lifecycle = [&](const ConnectionLifecycleEvent& event) {
        const auto key = lifecycle_tuple_key(event);
        if (!key.empty()) pending_snapshot_candidates.erase(key);
        if (event.type == ConnectionLifecycleEventType::Close) {
            const auto reverse = lifecycle_tuple_key(event, true);
            if (!reverse.empty()) pending_snapshot_candidates.erase(reverse);
        }
    };

    const auto sample_transport = [&](bool startup_snapshot) {
        drain_name_resolution();
        tracker.begin_snapshot();
        const bool lifecycle_degraded = result.lifecycle_events_active &&
            lifecycle_observer_.health().evidence_may_be_incomplete();
        std::unordered_set<std::string> candidates_seen;

        for (const auto& socket : socket_observer_.snapshot()) {
            std::optional<ProcessIdentity> process;
            // Windows snapshots carry owning_pid and require PID/start identity for
            // safe reconciliation across PID reuse. Linux SOCK_DIAG does not carry
            // an owner PID here; resolving /proc on every lifecycle-active snapshot
            // is both expensive and best-effort, and can make the same pending socket
            // alternate between tuple-only and tuple+process keys. Only resolve Linux
            // snapshots when a process filter actually requires the process name.
            if (socket.owning_pid.has_value() || admission_policy_.has_process_filters()) {
                process = process_resolver_.resolve(socket);
            }
            const std::optional<std::string> process_name = process
                ? std::optional<std::string>{process->comm} : std::nullopt;

            if (result.lifecycle_events_active) {
                if (const auto enrichment = tracker.observe_socket(
                        socket, ConnectionDirection::Unknown, false)) {
                    pending_snapshot_candidates.erase(snapshot_tuple_key(socket, process));
                    static_cast<void>(enrichment);
                    continue;
                }

                const auto decision = admission_policy_.evaluate_reconciliation_socket(
                    socket, process_name);
                if (!decision.admit) continue;
                const auto key = snapshot_tuple_key(socket, process);
                candidates_seen.insert(key);
                auto [candidate_it, inserted] = pending_snapshot_candidates.try_emplace(
                    key, PendingSnapshotCandidate{socket, process, socket.transport.observed_ns,
                                                  socket.transport.observed_ns, startup_snapshot});
                if (!inserted) {
                    candidate_it->second.socket = socket;
                    candidate_it->second.process = process;
                    candidate_it->second.last_seen_ns = socket.transport.observed_ns;
                    candidate_it->second.startup = candidate_it->second.startup || startup_snapshot;
                }

                auto& candidate = candidate_it->second;
                const bool grace_elapsed = candidate.last_seen_ns >= candidate.first_seen_ns &&
                    candidate.last_seen_ns - candidate.first_seen_ns >=
                        snapshot_reconciliation_grace_ns;
                if (lifecycle_degraded || grace_elapsed) {
                    const auto origin = lifecycle_degraded
                        ? ConnectionObservationOrigin::SnapshotReconciledAfterLifecycleLoss
                        : ConnectionObservationOrigin::SnapshotPreexisting;
                    const auto admission = tracker.observe_socket(
                        candidate.socket, ConnectionDirection::Unknown, true, origin);
                    if (admission) {
                        record_admission(*admission, candidate.socket.remote_ip,
                                         ConnectionDirection::Unknown);
                    }
                    pending_snapshot_candidates.erase(candidate_it);
                }
                continue;
            }

            const auto decision = admission_policy_.evaluate_new_socket(socket, process_name);
            const auto admission = tracker.observe_socket(
                socket, decision.direction, decision.admit,
                ConnectionObservationOrigin::SnapshotPreexisting);
            if (admission) record_admission(*admission, socket.remote_ip, decision.direction);
        }

        if (result.lifecycle_events_active) {
            for (auto current = pending_snapshot_candidates.begin();
                 current != pending_snapshot_candidates.end();) {
                if (candidates_seen.contains(current->first)) {
                    ++current;
                    continue;
                }
                auto& candidate = current->second;
                if (lifecycle_degraded) {
                    const auto admission = tracker.observe_socket(
                        candidate.socket, ConnectionDirection::Unknown, true,
                        ConnectionObservationOrigin::SnapshotReconciledAfterLifecycleLoss);
                    if (admission) {
                        record_admission(*admission, candidate.socket.remote_ip,
                                         ConnectionDirection::Unknown);
                    }
                }
                current = pending_snapshot_candidates.erase(current);
            }

            if (pending_snapshot_candidates.size() > max_snapshot_reconciliation_candidates) {
                while (pending_snapshot_candidates.size() >
                       max_snapshot_reconciliation_candidates) {
                    pending_snapshot_candidates.erase(pending_snapshot_candidates.begin());
                }
            }
            for (auto current = pending_snapshot_candidates.begin();
                 current != pending_snapshot_candidates.end();) {
                const auto& candidate = current->second;
                if (candidate.last_seen_ns >= candidate.first_seen_ns &&
                    candidate.last_seen_ns - candidate.first_seen_ns > snapshot_candidate_stale_ns) {
                    current = pending_snapshot_candidates.erase(current);
                } else {
                    ++current;
                }
            }
        }

        for (const auto connection_id : tracker.end_snapshot(
                 !result.lifecycle_events_active, lifecycle_degraded)) {
            scheduler.connection_closed(connection_id);
            route_requests.erase(connection_id);
            queue_completed(connection_id);
        }
        drain_tls_sessions();
        dispatch_completed();
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
                if (const auto connection = store_.connection(connection_id)) {
                    const auto environment = platform::capture_host_network_environment(
                        *connection, *route);
                    store_.add_host_network_environment(connection_id, environment);
                }
            }
            route_requests.erase(request);
        }
    };

    const auto deadline = duration
        ? std::optional{std::chrono::steady_clock::now() + *duration} : std::nullopt;
    if (callbacks.started) callbacks.started();
    drain_name_resolution();
    drain_tls_sessions();

    if (result.lifecycle_events_active) {
        sample_transport(true);
        scheduler.transport_sampled(std::chrono::steady_clock::now());
        observe_scheduled_routes();
    }

    while ((!deadline || std::chrono::steady_clock::now() < *deadline) && !stop_requested()) {
        if (result.lifecycle_events_active) {
            const auto now = std::chrono::steady_clock::now();
            auto timeout = deadline
                ? std::min(scheduler.wait_time(now),
                           std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - now))
                : scheduler.wait_time(now);
            timeout = std::min(timeout, completion_wait_time(now));
            const auto lifecycle_events = lifecycle_observer_.poll(timeout);
            drain_name_resolution();
            for (const auto& event : lifecycle_events) {
                erase_candidate_for_lifecycle(event);
                const auto decision = admission_policy_.evaluate(event);
                if (!decision.admit) continue;
                const auto admission = tracker.observe_lifecycle(event, decision.direction);
                if (admission && event.remote) {
                    record_direction_promotion(*admission, event.remote->address);
                }
                if (admission && admission->closed) {
                    scheduler.connection_closed(admission->connection_id);
                    route_requests.erase(admission->connection_id);
                    queue_completed(admission->connection_id);
                }
                if (admission && admission->newly_admitted && event.remote) {
                    record_admission(*admission, event.remote->address, decision.direction);
                    sample_transport(false);
                    scheduler.transport_sampled(std::chrono::steady_clock::now());
                    observe_scheduled_routes();
                }
            }
            drain_tls_sessions();
            dispatch_completed();
        }

        const auto now = std::chrono::steady_clock::now();
        const bool reconciliation_poll_required =
            result.lifecycle_events_active && !pending_snapshot_candidates.empty();
        if (scheduler.transport_due(
                now, !result.lifecycle_events_active || reconciliation_poll_required)) {
            sample_transport(false);
            scheduler.transport_sampled(std::chrono::steady_clock::now());
            observe_scheduled_routes();
        }
        if (storage_maintenance_) {
            static_cast<void>(storage_maintenance_->run_if_due(now));
        }
        if (callbacks.periodic) callbacks.periodic();
        if (!result.lifecycle_events_active) std::this_thread::sleep_for(transport_poll_interval);
    }

    drain_name_resolution();
    drain_tls_sessions();
    dispatch_completed(true);
    correlate_tls_sessions();
    dispatch_completed(true);
    tracker.finish_observation(!result.lifecycle_events_active);
    result.connection_ids.assign(connection_ids.begin(), connection_ids.end());
    return result;
}

} // namespace neta
