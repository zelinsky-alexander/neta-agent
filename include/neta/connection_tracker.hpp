#pragma once

#include "neta/history_store.hpp"
#include "neta/lifecycle.hpp"
#include "neta/platform.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace neta {

struct ConnectionAdmission {
    std::int64_t connection_id{0};
    bool newly_admitted{false};
};

struct TrackedConnection {
    std::int64_t connection_id{0};
    TcpSnapshot last_seen;
    TcpSnapshot last_persisted;
    std::uint64_t last_persist_ns{0};
    bool has_transport_sample{false};
    bool present_in_snapshot{false};
    bool closed{false};
};

class ConnectionTracker {
public:
    ConnectionTracker(HistoryStore& store, platform::ProcessResolver& resolver,
                      std::string target_host);

    std::optional<ConnectionAdmission> observe_lifecycle(const ConnectionLifecycleEvent& event);
    std::optional<ConnectionAdmission> observe_socket(const SocketObservation& socket);
    void begin_snapshot();
    void end_snapshot(bool polling_controls_lifecycle);
    void finish_observation(bool polling_controls_lifecycle);

    [[nodiscard]] const std::unordered_map<std::string, TrackedConnection>& connections() const {
        return connections_;
    }

private:
    std::optional<ProcessIdentity> process_from(const ConnectionLifecycleEvent& event) const;
    std::optional<std::string> identity_for(const ConnectionLifecycleEvent& event) const;
    std::string identity_for(const SocketObservation& socket) const;
    std::string tuple_for(const NetworkEndpoint& local, const NetworkEndpoint& remote) const;
    std::string tuple_for(const SocketObservation& socket) const;
    std::optional<std::string> unique_active_tuple_match(const std::string& tuple) const;
    void index_tuple(const std::string& tuple, const std::string& identity);
    void persist_sample(TrackedConnection& tracked, const TcpSnapshot& sample);

    HistoryStore& store_;
    platform::ProcessResolver& resolver_;
    std::string target_host_;
    std::unordered_map<std::string, TrackedConnection> connections_;
    std::unordered_multimap<std::string, std::string> tuple_index_;
};

} // namespace neta
