#include "neta/cli/observation_command.hpp"

#include "neta/cli/observation_options.hpp"
#include "neta/fleet_reporting.hpp"
#include "neta/history_store.hpp"
#include "neta/platform.hpp"
#include "neta/storage_maintenance.hpp"
#include "neta/tls_probe.hpp"
#include "neta/verdict.hpp"

#include <csignal>
#include <future>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace neta::cli {
namespace {

volatile std::sig_atomic_t stop_requested = 0;

void handle_stop_signal(int) { stop_requested = 1; }

class SignalHandlers {
public:
    SignalHandlers()
        : previous_sigint_(std::signal(SIGINT, handle_stop_signal)),
          previous_sigterm_(std::signal(SIGTERM, handle_stop_signal)) {
        stop_requested = 0;
    }
    ~SignalHandlers() {
        std::signal(SIGINT, previous_sigint_);
        std::signal(SIGTERM, previous_sigterm_);
    }
private:
    using Handler = void (*)(int);
    Handler previous_sigint_;
    Handler previous_sigterm_;
};

bool lifecycle_supports(const LifecycleCapability& capability, ObservationMode mode) {
    switch (mode) {
        case ObservationMode::Target:
        case ObservationMode::Outbound: return capability.outbound_available();
        case ObservationMode::Inbound: return capability.accept_events && capability.close_events;
        case ObservationMode::All: return capability.available();
    }
    return false;
}

void finalize_target_connections(const std::vector<std::int64_t>& connection_ids,
                                 HistoryStore& store,
                                 const std::optional<Baseline>& baseline,
                                 const std::optional<TlsObservation>& tls,
                                 std::optional<std::int64_t> tls_id) {
    if (!baseline) return;
    for (const auto connection_id : connection_ids) {
        const auto verdict = evaluate(*baseline,
                                      aggregate_metrics(store.samples_for_connection(connection_id)),
                                      tls);
        store.save_verdict(connection_id, verdict, tls_id);
    }
}

void finalize_inbound_connections(const std::vector<std::int64_t>& connection_ids,
                                  HistoryStore& store) {
    for (const auto connection_id : connection_ids) {
        const auto connection = store.connection(connection_id);
        if (!connection || connection->direction != ConnectionDirection::Inbound) continue;

        const auto tls_sessions = store.tls_session_evidence_for_connection(connection_id);
        const auto context = inbound_trust_context(tls_sessions);
        std::optional<Baseline> accepted_identity;
        const auto baseline_key = inbound_client_baseline_key(*connection, context.subject);
        if (!baseline_key.empty()) {
            accepted_identity = store.baseline_for(baseline_key, connection->local_port);
        }

        const auto verdict = evaluate_inbound(
            accepted_identity,
            aggregate_metrics(store.samples_for_connection(connection_id)),
            context);
        store.save_verdict(connection_id, verdict);
    }
}

} // namespace

void run_observation_command(int argc, char** argv, bool service_mode) {
    const auto options = parse_observation_options(argc, argv, service_mode);
    SignalHandlers signals;
    HistoryStore store(options.database);
    StorageMaintenance maintenance(store, options.max_database_bytes,
                                   options.maintenance_interval);
    maintenance.run_now();

    auto sockets = platform::make_connection_observer();
    auto processes = platform::make_process_resolver();
    auto routes = platform::make_route_observer();
    auto lifecycle = platform::make_lifecycle_observer();
    auto name_resolution = platform::make_name_resolution_observer();
    auto tls_session = platform::make_tls_session_observer();
    const bool lifecycle_active = lifecycle_supports(lifecycle->capability(), options.mode);

    if (options.mode != ObservationMode::Target && !lifecycle_active) {
        throw std::runtime_error(
            "requested direction mode requires connect/accept/close lifecycle evidence: " +
            lifecycle->capability().unavailable_reason);
    }
    if (!lifecycle_active) {
        std::cerr << "Lifecycle eBPF unavailable; target observation uses polling with "
                     "UNKNOWN direction: " << lifecycle->capability().unavailable_reason << '\n';
    }
    if (!name_resolution->capability().available()) {
        std::cerr << "Application resolver event collection unavailable: "
                  << name_resolution->capability().unavailable_reason << '\n';
    }
    if (!tls_session->capability().available()) {
        std::cerr << "Application TLS session collection unavailable: "
                  << tls_session->capability().unavailable_reason << '\n';
    }

    std::optional<TlsObservation> tls;
    std::optional<std::int64_t> tls_id;
    std::optional<Baseline> baseline;
    std::string target_label;
    AdmissionPolicyConfig policy_config;
    policy_config.mode = options.mode;
    policy_config.filter = options.filter;
    if (options.target) {
        target_label = options.target->host;
        policy_config.target_addresses = options.target->addresses;
        policy_config.target_port = options.target->port;
        baseline = store.baseline_for(options.target->host, options.target->port);
    }

    const auto transport_interval = options.transport_interval.value_or(
        lifecycle_active ? std::chrono::milliseconds(1000) : std::chrono::milliseconds(100));
    ObservationSession session(store, *sockets, *lifecycle, *processes, *routes,
                               ConnectionAdmissionPolicy(std::move(policy_config)),
                               target_label, &maintenance, name_resolution.get(),
                               tls_session.get());
    std::future<TlsObservation> tls_probe;
    const auto result = session.run(options.duration, transport_interval,
                                    [] { return stop_requested != 0; }, [&] {
        if (!options.target) return;
        tls_probe = std::async(std::launch::async, [&] {
            return TlsProbe{}.probe(options.target->host, options.target->port,
                                    options.ca_file, std::chrono::milliseconds(100));
        });
    });
    if (tls_probe.valid()) {
        try {
            tls = tls_probe.get();
            tls_id = store.add_tls(*tls);
            for (const auto connection_id : result.connection_ids) {
                store.link_tls_observation(connection_id, *tls_id);
            }
        } catch (const std::exception& error) {
            std::cerr << "TLS supporting probe unavailable: " << error.what() << '\n';
        }
    }
    if (options.target) {
        finalize_target_connections(result.connection_ids, store, baseline, tls, tls_id);
    }
    finalize_inbound_connections(result.connection_ids, store);

    const auto reporting_policy = fleet_reporting_policy_from_environment();
    const auto reporting = auto_report_connections(store, result.connection_ids, reporting_policy);
    if (reporting.considered != 0 || reporting.announced != 0 || reporting.failed != 0) {
        std::cout << "Fleet reporting: " << reporting.announced << " announced, "
                  << reporting.suppressed_policy << " suppressed by policy, "
                  << reporting.suppressed_cooldown << " suppressed by cooldown, "
                  << reporting.failed << " failed\n";
    }

    maintenance.run_now();

    const auto lifecycle_health = lifecycle->health();
    const auto name_health = name_resolution->health();
    const auto tls_health = tls_session->health();
    std::cout << "Observed " << result.admitted_connections << " matching connection(s). History: "
              << options.database << '\n'
              << "Lifecycle dropped events: "
              << (lifecycle_health.dropped_events
                  ? std::to_string(*lifecycle_health.dropped_events) : "UNAVAILABLE") << '\n'
              << "Resolver API events: " << result.name_resolution_events_observed
              << " observed, " << result.name_resolution_evidence_attached
              << " attached, " << result.ambiguous_name_resolution_matches
              << " ambiguous\n"
              << "Resolver dropped events: "
              << (name_health.dropped_events
                  ? std::to_string(*name_health.dropped_events) : "UNAVAILABLE") << '\n'
              << "TLS application sessions: " << result.tls_session_events_observed
              << " observed, " << result.tls_session_evidence_attached
              << " attached, " << result.ambiguous_tls_session_matches
              << " ambiguous\n"
              << "TLS session dropped events: "
              << (tls_health.dropped_events
                  ? std::to_string(*tls_health.dropped_events) : "UNAVAILABLE") << '\n'
              << "TLS session rejected events: " << tls_health.rejected_events << '\n';
    if (lifecycle_health.evidence_may_be_incomplete()) {
        std::cerr << "Lifecycle evidence may be incomplete because the collector dropped events\n";
    }
    if (name_health.evidence_may_be_incomplete()) {
        std::cerr << "Name-resolution evidence may be incomplete because the collector dropped events\n";
    }
    if (tls_health.evidence_may_be_incomplete()) {
        std::cerr << "Application TLS session evidence may be incomplete because events were dropped or rejected\n";
    }
}

} // namespace neta::cli