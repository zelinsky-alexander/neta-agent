#pragma once

#include "neta/history_store.hpp"
#include "neta/lifecycle.hpp"
#include "neta/platform.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace neta {

enum class ConnectionObservationOrigin {
    LifecycleExact,
    LifecyclePlusSnapshot,
    SnapshotPreexisting,
    SnapshotReconciledAfterLifecycleLoss
};

struct ConnectionAdmission {
    std::int64_t connection_id{0};
    bool newly_admitted{false};
    bool closed{false};
    bool direction_promoted{false};
    ConnectionDirection direction{ConnectionDirection::Unknown};
};

struct TrackedConnection {
    std::int64_t connection_id{0};
    TcpSnapshot last_seen;
    TcpSnapshot last_persisted;
    std::uint64_t last_persist_ns{0};
    bool has_transport_sample{false};
    bool present_in_snapshot{false};
    std::size_t consecutive_snapshot_misses{0};
    std::optional<std::int64_t> process_pid;
    std::optional<std::uint64_t> process_start_ticks;
    ConnectionObservationOrigin origin{ConnectionObservationOrigin::LifecycleExact};
};

class ConnectionTracker {
public:
    ConnectionTracker(HistoryStore& store, platform::ProcessResolver& resolver,
                      std::string target_host);

    std::optional<ConnectionAdmission> observe_lifecycle(
        const ConnectionLifecycleEvent& event, ConnectionDirection direction);
    std::optional<ConnectionAdmission> observe_socket(
        const SocketObservation& socket,
        ConnectionDirection direction = ConnectionDirection::Unknown,
        bool allow_new_connection = true,
        ConnectionObservationOrigin origin = ConnectionObservationOrigin::SnapshotPreexisting);
    void begin_snapshot();
    std::vector<std::int64_t> end_snapshot(bool polling_controls_lifecycle,
                                           bool lifecycle_evidence_incomplete = false);
    void finish_observation(bool polling_controls_lifecycle);

    [[nodiscard]] const std::unordered_map<std::string, TrackedConnection>& connections() const {
        return connections_;
    }

private:
    std::optional<ProcessIdentity> process_from(const ConnectionLifecycleEvent& event) const;
    std::optional<std::string> identity_for(const ConnectionLifecycleEvent& event) const;
    std::string identity_for(const SocketObservation& socket) const;
    std::string tuple_for(const NetworkEndpoint& local, const NetworkEndpoint& remote,
                          std::optional<std::uint64_t> network_namespace_inode) const;
    std::string tuple_for(const SocketObservation& socket) const;
    std::string correlation_key(const std::string& tuple,
                                const std::optional<ProcessIdentity>& process,
                                bool require_process_start) const;
    std::optional<std::string> unique_active_correlation_match(const std::string& key) const;
    void index_correlation(const std::string& key, const std::string& identity);
    void remove_correlation_identity(const std::string& identity);
    [[nodiscard]] bool rekey_identity(const std::string& previous,
                                      const std::string& canonical);
    [[nodiscard]] bool promote_socket_cookie_identity(const std::string& previous,
                                                      const std::string& canonical,
                                                      std::uint64_t socket_cookie);
    void persist_sample(TrackedConnection& tracked, const TcpSnapshot& sample);

    HistoryStore& store_;
    platform::ProcessResolver& resolver_;
    std::string target_host_;
    std::unordered_map<std::string, TrackedConnection> connections_;
    std::unordered_multimap<std::string, std::string> correlation_index_;
    std::unordered_map<std::string, std::string> correlation_by_identity_;
};

} // namespace neta
