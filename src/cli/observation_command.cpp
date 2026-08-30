#include "neta/cli/observation_command.hpp"

#include "neta/cli/observation_options.hpp"
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
                               target_label, &maintenance);
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
    maintenance.run_now();

    const auto health = lifecycle->health();
    std::cout << "Observed " << result.admitted_connections << " matching connection(s). History: "
              << options.database << '\n'
              << "Lifecycle dropped events: "
              << (health.dropped_events ? std::to_string(*health.dropped_events) : "UNAVAILABLE")
              << '\n';
    if (health.evidence_may_be_incomplete()) {
        std::cerr << "Lifecycle evidence may be incomplete because the collector dropped events\n";
    }
}

} // namespace neta::cli
