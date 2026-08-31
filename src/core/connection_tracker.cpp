#include "neta/connection_tracker.hpp"

#include <cmath>
#include <limits>
#include <utility>

namespace neta {
namespace {

bool valid_cookie(std::uint64_t cookie) {
    return cookie != 0 && cookie != std::numeric_limits<std::uint64_t>::max();
}

bool meaningful_change(const TcpSnapshot& previous, const TcpSnapshot& current,
                       std::uint64_t last_persist_ns) {
    if (current.total_retrans != previous.total_retrans || current.lost != previous.lost ||
        current.state != previous.state) {
        return true;
    }
    const auto material = [](std::uint32_t a, std::uint32_t b, double ratio,
                             std::uint32_t floor) {
        const auto difference = a > b ? a - b : b - a;
        return difference >= floor &&
               (a == 0 || static_cast<double>(difference) / static_cast<double>(a) >= ratio);
    };
    return material(previous.rtt_us, current.rtt_us, 0.25, 2'000) ||
           material(previous.rtt_variance_us, current.rtt_variance_us, 0.50, 2'000) ||
           current.observed_ns - last_persist_ns >= 1'000'000'000ULL;
}

} // namespace

ConnectionTracker::ConnectionTracker(HistoryStore& store, platform::ProcessResolver& resolver,
                                     std::string target_host)
    : store_(store), resolver_(resolver), target_host_(std::move(target_host)) {}

std::string ConnectionTracker::tuple_for(const NetworkEndpoint& local,
                                         const NetworkEndpoint& remote,
                                         std::optional<std::uint64_t> network_namespace_inode) const {
    return "n:" + std::to_string(network_namespace_inode.value_or(0)) + '|' +
           local.address + ':' + std::to_string(local.port.value_or(0)) + "->" +
           remote.address + ':' + std::to_string(remote.port.value_or(0));
}

std::string ConnectionTracker::tuple_for(const SocketObservation& socket) const {
    return "n:" + std::to_string(socket.network_namespace_inode.value_or(0)) + '|' +
           socket.local_ip + ':' + std::to_string(socket.local_port) + "->" +
           socket.remote_ip + ':' + std::to_string(socket.remote_port);
}

std::optional<ProcessIdentity> ConnectionTracker::process_from(
    const ConnectionLifecycleEvent& event) const {
    if (!event.process.agent_visible.tgid || !event.process.uid) return std::nullopt;
    ProcessIdentity process;
    process.pid = *event.process.agent_visible.tgid;
    process.uid = *event.process.uid;
    if (event.process.start_ticks && *event.process.start_ticks != 0) {
        process.start_ticks = event.process.start_ticks;
    }
    process.comm = event.process.comm.value_or("");
    return process;
}

std::optional<std::string> ConnectionTracker::identity_for(
    const ConnectionLifecycleEvent& event) const {
    if (event.socket_cookie && valid_cookie(*event.socket_cookie)) {
        return "c:" + std::to_string(*event.socket_cookie);
    }
    if (!event.local || !event.remote) return std::nullopt;
    const auto process = event.process.agent_visible.tgid.value_or(-1);
    const auto netns = event.network_namespace_inode.value_or(0);
    return "f:" + std::to_string(netns) + '|' + std::to_string(process) + '|' +
           tuple_for(*event.local, *event.remote, event.network_namespace_inode) + '|' +
           std::to_string(event.timestamp_ns);
}

std::string ConnectionTracker::identity_for(const SocketObservation& socket) const {
    if (valid_cookie(socket.socket_cookie)) return "c:" + std::to_string(socket.socket_cookie);
    return "i:" + std::to_string(socket.socket_inode) + '|' + tuple_for(socket);
}

void ConnectionTracker::index_tuple(const std::string& tuple, const std::string& identity) {
    tuple_index_.emplace(tuple, identity);
    tuple_by_identity_.emplace(identity, tuple);
}

void ConnectionTracker::remove_tuple_identity(const std::string& identity) {
    const auto indexed = tuple_by_identity_.find(identity);
    if (indexed == tuple_by_identity_.end()) return;
    const auto [first, last] = tuple_index_.equal_range(indexed->second);
    for (auto current = first; current != last;) {
        if (current->second == identity) current = tuple_index_.erase(current);
        else ++current;
    }
    tuple_by_identity_.erase(indexed);
}

bool ConnectionTracker::promote_identity(const std::string& previous,
                                         const std::string& canonical,
                                         std::uint64_t socket_cookie) {
    if (previous == canonical) return true;
    if (connections_.contains(canonical)) return false;
    const auto previous_connection = connections_.find(previous);
    if (previous_connection == connections_.end()) return false;
    if (!store_.update_socket_cookie(previous_connection->second.connection_id,
                                     socket_cookie)) {
        return false;
    }
    auto node = connections_.extract(previous);
    if (node.empty()) return false;
    node.key() = canonical;
    connections_.insert(std::move(node));
    auto indexed = tuple_by_identity_.extract(previous);
    if (!indexed.empty()) {
        const auto [first, last] = tuple_index_.equal_range(indexed.mapped());
        for (auto current = first; current != last; ++current) {
            if (current->second == previous) current->second = canonical;
        }
        indexed.key() = canonical;
        tuple_by_identity_.insert(std::move(indexed));
    }
    return true;
}

std::optional<std::string> ConnectionTracker::unique_active_tuple_match(
    const std::string& tuple) const {
    const auto [first, last] = tuple_index_.equal_range(tuple);
    std::optional<std::string> match;
    for (auto it = first; it != last; ++it) {
        const auto tracked = connections_.find(it->second);
        if (tracked == connections_.end()) continue;
        if (match && *match != it->second) return std::nullopt;
        match = it->second;
    }
    return match;
}

std::optional<ConnectionAdmission> ConnectionTracker::observe_lifecycle(
    const ConnectionLifecycleEvent& event, ConnectionDirection direction) {
    if (event.protocol != TransportProtocol::Tcp) return std::nullopt;
    const auto identity = identity_for(event);
    if (!identity) return std::nullopt;

    auto existing = connections_.find(*identity);
    if (event.type == ConnectionLifecycleEventType::Close) {
        if (existing == connections_.end() && event.local && event.remote) {
            const auto tuple_match = unique_active_tuple_match(
                tuple_for(*event.local, *event.remote, event.network_namespace_inode));
            if (tuple_match) existing = connections_.find(*tuple_match);
        }
        if (existing == connections_.end()) return std::nullopt;
        if (event.socket_cookie && valid_cookie(*event.socket_cookie) &&
            existing->first != *identity) {
            const auto previous_identity = existing->first;
            if (promote_identity(previous_identity, *identity, *event.socket_cookie)) {
                existing = connections_.find(*identity);
            }
        }
        const auto connection_id = existing->second.connection_id;
        const auto tracked_identity = existing->first;
        store_.touch_connection(connection_id, event.timestamp_ns, "CLOSED");
        store_.add_lifecycle_event(connection_id, event);
        remove_tuple_identity(tracked_identity);
        connections_.erase(existing);
        return ConnectionAdmission{connection_id, false, true};
    }

    if (!eligible_connection_seed(event.endpoint_kind)) return std::nullopt;
    if (!event.local || !event.remote || !event.remote->port) return std::nullopt;
    if (existing != connections_.end()) {
        store_.add_lifecycle_event(existing->second.connection_id, event);
        return ConnectionAdmission{existing->second.connection_id, false};
    }

    const auto process = process_from(event);
    if (!process) return std::nullopt;

    SocketObservation socket;
    socket.socket_cookie = event.socket_cookie.value_or(0);
    socket.network_namespace_inode = event.network_namespace_inode;
    socket.uid = event.process.uid.value_or(0);
    socket.local_ip = event.local->address;
    socket.local_port = event.local->port.value_or(0);
    socket.remote_ip = event.remote->address;
    socket.remote_port = *event.remote->port;
    socket.transport.observed_ns = event.timestamp_ns;
    socket.transport.state = event.tcp_state.value_or(0);
    const auto id = store_.begin_connection(socket, process, target_host_, event.timestamp_ns,
                                            direction);
    store_.add_lifecycle_event(id, event);
    connections_.emplace(*identity, TrackedConnection{id, socket.transport, {}, 0,
                                                       false, false});
    index_tuple(tuple_for(*event.local, *event.remote, event.network_namespace_inode), *identity);
    return ConnectionAdmission{id, true};
}

void ConnectionTracker::persist_sample(TrackedConnection& tracked, const TcpSnapshot& sample) {
    if (!tracked.has_transport_sample || meaningful_change(tracked.last_persisted, sample,
                                                           tracked.last_persist_ns)) {
        store_.add_tcp_sample(tracked.connection_id, sample);
        tracked.has_transport_sample = true;
        tracked.last_persisted = sample;
        tracked.last_persist_ns = sample.observed_ns;
    }
    tracked.last_seen = sample;
    tracked.present_in_snapshot = true;
    store_.touch_connection(tracked.connection_id, sample.observed_ns, "ACTIVE");
}

std::optional<ConnectionAdmission> ConnectionTracker::observe_socket(
    const SocketObservation& socket, ConnectionDirection direction,
    bool allow_new_connection) {
    const auto canonical = identity_for(socket);
    auto identity = canonical;
    auto existing = connections_.find(identity);
    const auto tuple_match = unique_active_tuple_match(tuple_for(socket));
    if (existing != connections_.end() && tuple_match && *tuple_match != identity) {
        return std::nullopt;
    }
    if (existing == connections_.end()) {
        if (tuple_match) {
            identity = *tuple_match;
            if (valid_cookie(socket.socket_cookie) && identity != canonical) {
                if (!promote_identity(identity, canonical, socket.socket_cookie)) {
                    return std::nullopt;
                }
                identity = canonical;
            }
            existing = connections_.find(identity);
        }
    }

    if (existing != connections_.end()) {
        persist_sample(existing->second, socket.transport);
        return ConnectionAdmission{existing->second.connection_id, false};
    }

    if (!allow_new_connection) return std::nullopt;
    if (!eligible_connection_seed(socket.endpoint_kind)) return std::nullopt;
    const auto process = resolver_.resolve(socket.socket_inode);
    if (!process) return std::nullopt;
    const auto id = store_.begin_connection(socket, process, target_host_,
                                            socket.transport.observed_ns, direction);
    TrackedConnection tracked{id, socket.transport, socket.transport,
                              socket.transport.observed_ns, true, true};
    store_.add_tcp_sample(id, socket.transport);
    connections_.emplace(identity, tracked);
    index_tuple(tuple_for(socket), identity);
    return ConnectionAdmission{id, true};
}

void ConnectionTracker::begin_snapshot() {
    for (auto& [identity, tracked] : connections_) {
        static_cast<void>(identity);
        tracked.present_in_snapshot = false;
    }
}

std::vector<std::int64_t> ConnectionTracker::end_snapshot(bool polling_controls_lifecycle) {
    constexpr std::size_t lifecycle_reconciliation_miss_limit = 3;
    std::vector<std::int64_t> inactive;
    for (auto current = connections_.begin(); current != connections_.end();) {
        auto& tracked = current->second;
        if (tracked.present_in_snapshot) {
            tracked.consecutive_snapshot_misses = 0;
            ++current;
            continue;
        }
        ++tracked.consecutive_snapshot_misses;
        const bool reconcile_absent = polling_controls_lifecycle ||
            tracked.consecutive_snapshot_misses >= lifecycle_reconciliation_miss_limit;
        if (reconcile_absent) {
            const auto identity = current->first;
            const auto connection_id = tracked.connection_id;
            store_.touch_connection(connection_id, tracked.last_seen.observed_ns,
                                    polling_controls_lifecycle
                                        ? "DISAPPEARED" : "RECONCILED_ABSENT");
            remove_tuple_identity(identity);
            current = connections_.erase(current);
            inactive.push_back(connection_id);
        } else {
            ++current;
        }
    }
    return inactive;
}

void ConnectionTracker::finish_observation(bool polling_controls_lifecycle) {
    for (auto& [identity, tracked] : connections_) {
        static_cast<void>(identity);
        const char* state = polling_controls_lifecycle && !tracked.present_in_snapshot
            ? "DISAPPEARED" : "OBSERVATION_ENDED";
        store_.touch_connection(tracked.connection_id, tracked.last_seen.observed_ns,
                                state);
    }
}

} // namespace neta
