#include "neta/connection_tracker.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

namespace {

class NoProcessResolver final : public neta::platform::ProcessResolver {
public:
    std::optional<neta::ProcessIdentity> resolve(std::uint64_t) override {
        return std::nullopt;
    }
};

std::filesystem::path database_path(const char* name) {
    return std::filesystem::temp_directory_path() /
           (std::string("neta-ms2-tracker-") + name + ".sqlite");
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

neta::ConnectionLifecycleEvent accepted(std::uint64_t timestamp) {
    neta::ConnectionLifecycleEvent event;
    event.type = neta::ConnectionLifecycleEventType::Accept;
    event.timestamp_ns = timestamp;
    event.protocol = neta::TransportProtocol::Tcp;
    event.endpoint_kind = neta::TcpEndpointKind::Connection;
    event.local = neta::NetworkEndpoint{"127.0.0.1", 443};
    event.remote = neta::NetworkEndpoint{"127.0.0.2", 50000};
    event.process.agent_visible.pid = 7001;
    event.process.agent_visible.tgid = 7000;
    event.process.uid = 1000;
    event.process.start_ticks = 0;
    event.process.comm = "server";
    event.network_namespace_inode = 42;
    return event;
}

neta::SocketObservation accepted_socket(std::uint64_t cookie) {
    neta::SocketObservation socket;
    socket.socket_cookie = cookie;
    socket.socket_inode = 8000;
    socket.network_namespace_inode = 42;
    socket.uid = 1000;
    socket.local_ip = "127.0.0.1";
    socket.local_port = 443;
    socket.remote_ip = "127.0.0.2";
    socket.remote_port = 50000;
    socket.endpoint_kind = neta::TcpEndpointKind::Connection;
    socket.transport.observed_ns = 2'000;
    socket.transport.state = 1;
    return socket;
}

void promotion_preserves_connection() {
    const auto path = database_path("promotion");
    remove_database(path);
    std::int64_t connection_id = 0;
    {
        neta::HistoryStore store(path);
        NoProcessResolver resolver;
        neta::ConnectionTracker tracker(store, resolver, "");
        const auto admitted = tracker.observe_lifecycle(
            accepted(1'000), neta::ConnectionDirection::Inbound);
        assert(admitted && admitted->newly_admitted);
        connection_id = admitted->connection_id;
        const auto enriched = tracker.observe_socket(
            accepted_socket(9876), neta::ConnectionDirection::Unknown, false);
        assert(enriched && !enriched->newly_admitted);
        assert(enriched->connection_id == admitted->connection_id);
        const auto connection = store.connection(admitted->connection_id);
        assert(connection);
        assert(connection->socket_cookie == 9876);
        assert(connection->direction == neta::ConnectionDirection::Inbound);
        assert(connection->network_namespace_inode == 42);
        assert(!connection->process.start_ticks);
        const auto again = tracker.observe_socket(
            accepted_socket(9876), neta::ConnectionDirection::Unknown, false);
        assert(again && again->connection_id == admitted->connection_id);
        auto close = accepted(3'000);
        close.type = neta::ConnectionLifecycleEventType::Close;
        const auto closed = tracker.observe_lifecycle(
            close, neta::ConnectionDirection::Unknown);
        assert(closed && closed->closed);
        assert(tracker.connections().empty());
        assert(store.status(10'000'000).connection_count == 1);
    }
    {
        neta::HistoryStore reopened(path);
        const auto connection = reopened.connection(connection_id);
        assert(connection);
        assert(connection->socket_cookie == 9876);
        assert(connection->direction == neta::ConnectionDirection::Inbound);
    }
    remove_database(path);
}

void ambiguous_tuple_is_not_promoted() {
    const auto path = database_path("ambiguous");
    remove_database(path);
    {
        neta::HistoryStore store(path);
        NoProcessResolver resolver;
        neta::ConnectionTracker tracker(store, resolver, "");
        assert(tracker.observe_lifecycle(accepted(1'000), neta::ConnectionDirection::Inbound));
        assert(tracker.observe_lifecycle(accepted(1'001), neta::ConnectionDirection::Inbound));
        assert(!tracker.observe_socket(
            accepted_socket(9999), neta::ConnectionDirection::Unknown, false));
        const auto connections = store.recent_connections(10);
        assert(connections.size() == 2);
        assert(connections[0].socket_cookie == 0);
        assert(connections[1].socket_cookie == 0);
    }
    remove_database(path);
}

void close_cookie_promotes_fallback_identity() {
    const auto path = database_path("close-promotion");
    remove_database(path);
    {
        neta::HistoryStore store(path);
        NoProcessResolver resolver;
        neta::ConnectionTracker tracker(store, resolver, "");
        const auto admission = tracker.observe_lifecycle(
            accepted(1'000), neta::ConnectionDirection::Inbound);
        assert(admission && admission->newly_admitted);

        auto close = accepted(2'000);
        close.type = neta::ConnectionLifecycleEventType::Close;
        close.socket_cookie = 9876;
        const auto closed = tracker.observe_lifecycle(
            close, neta::ConnectionDirection::Unknown);
        assert(closed && closed->closed);
        assert(closed->connection_id == admission->connection_id);
        const auto connection = store.connection(admission->connection_id);
        assert(connection);
        assert(connection->socket_cookie == 9876);
        assert(connection->lifecycle_state == "CLOSED");
    }
    remove_database(path);
}

void different_network_namespace_is_not_correlated() {
    const auto path = database_path("netns");
    remove_database(path);
    {
        neta::HistoryStore store(path);
        NoProcessResolver resolver;
        neta::ConnectionTracker tracker(store, resolver, "");
        assert(tracker.observe_lifecycle(
            accepted(1'000), neta::ConnectionDirection::Inbound));
        auto socket = accepted_socket(9999);
        socket.network_namespace_inode = 43;
        assert(!tracker.observe_socket(
            socket, neta::ConnectionDirection::Unknown, false));
        assert(store.connection(1)->socket_cookie == 0);
    }
    remove_database(path);
}

void canonical_identity_collision_is_rejected() {
    const auto path = database_path("canonical-collision");
    remove_database(path);
    {
        neta::HistoryStore store(path);
        NoProcessResolver resolver;
        neta::ConnectionTracker tracker(store, resolver, "");
        assert(tracker.observe_lifecycle(
            accepted(1'000), neta::ConnectionDirection::Inbound));

        auto outbound = accepted(1'001);
        outbound.type = neta::ConnectionLifecycleEventType::Connect;
        outbound.socket_cookie = 9999;
        outbound.local->port = 41000;
        outbound.remote->port = 8443;
        assert(tracker.observe_lifecycle(
            outbound, neta::ConnectionDirection::Outbound));

        assert(!tracker.observe_socket(
            accepted_socket(9999), neta::ConnectionDirection::Unknown, false));
        const auto connections = store.recent_connections(10);
        assert(connections.size() == 2);
        assert(connections[0].socket_cookie == 9999);
        assert(connections[1].socket_cookie == 0);
    }
    remove_database(path);
}

void closed_connections_leave_bounded_tracker_state() {
    const auto path = database_path("churn");
    remove_database(path);
    {
        neta::HistoryStore store(path);
        NoProcessResolver resolver;
        neta::ConnectionTracker tracker(store, resolver, "");
        for (std::uint64_t index = 0; index < 500; ++index) {
            auto open = accepted(10'000 + index * 2);
            open.remote->port = static_cast<std::uint16_t>(20'000 + index);
            const auto admission = tracker.observe_lifecycle(
                open, neta::ConnectionDirection::Inbound);
            assert(admission && admission->newly_admitted);
            auto close = open;
            close.type = neta::ConnectionLifecycleEventType::Close;
            close.timestamp_ns += 1;
            const auto closed = tracker.observe_lifecycle(
                close, neta::ConnectionDirection::Unknown);
            assert(closed && closed->closed);
        }
        assert(tracker.connections().empty());
        assert(store.status(100'000'000).connection_count == 500);
    }
    remove_database(path);
}

void missing_close_is_reconciled_from_snapshots() {
    const auto path = database_path("lost-close");
    remove_database(path);
    {
        neta::HistoryStore store(path);
        NoProcessResolver resolver;
        neta::ConnectionTracker tracker(store, resolver, "");
        const auto admission = tracker.observe_lifecycle(
            accepted(1'000), neta::ConnectionDirection::Inbound);
        assert(admission);
        for (int miss = 0; miss < 2; ++miss) {
            tracker.begin_snapshot();
            assert(tracker.end_snapshot(false).empty());
            assert(tracker.connections().size() == 1);
        }
        tracker.begin_snapshot();
        const auto inactive = tracker.end_snapshot(false);
        assert(inactive.size() == 1);
        assert(inactive.front() == admission->connection_id);
        assert(tracker.connections().empty());
        assert(store.connection(admission->connection_id)->lifecycle_state ==
               "RECONCILED_ABSENT");
    }
    remove_database(path);
}

} // namespace

int main() {
    promotion_preserves_connection();
    ambiguous_tuple_is_not_promoted();
    close_cookie_promotes_fallback_identity();
    different_network_namespace_is_not_correlated();
    canonical_identity_collision_is_rejected();
    closed_connections_leave_bounded_tracker_state();
    missing_close_is_reconciled_from_snapshots();
    std::cout << "Connection tracker MS2 tests passed\n";
}
