#include "neta/connection_tracker.hpp"
#include "neta/evidence_scheduler.hpp"
#include "neta/storage_maintenance.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>

namespace {

class NoProcessResolver final : public neta::platform::ProcessResolver {
public:
    std::optional<neta::ProcessIdentity> resolve(std::uint64_t) override {
        return std::nullopt;
    }
};

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

neta::ConnectionLifecycleEvent open_event(std::uint64_t index, bool inbound) {
    neta::ConnectionLifecycleEvent event;
    event.type = inbound ? neta::ConnectionLifecycleEventType::Accept
                         : neta::ConnectionLifecycleEventType::Connect;
    event.timestamp_ns = 1'000 + index * 3;
    event.protocol = neta::TransportProtocol::Tcp;
    event.endpoint_kind = neta::TcpEndpointKind::Connection;
    event.network_namespace_inode = 42;
    event.process.agent_visible.pid = 7000;
    event.process.agent_visible.tgid = 7000;
    event.process.uid = 1000;
    event.process.start_ticks = 1234;
    event.process.comm = inbound ? "server" : "client";
    if (inbound) {
        event.local = neta::NetworkEndpoint{"127.0.0.1", 8443};
        event.remote = neta::NetworkEndpoint{
            "127.0.0.2", static_cast<std::uint16_t>(20'000 + index)};
    } else {
        event.local = neta::NetworkEndpoint{
            "127.0.0.1", static_cast<std::uint16_t>(20'000 + index)};
        event.remote = neta::NetworkEndpoint{"127.0.0.2", 8443};
        event.socket_cookie = 100'000 + index;
    }
    return event;
}

neta::SocketObservation socket_for(const neta::ConnectionLifecycleEvent& event,
                                   std::uint64_t cookie) {
    neta::SocketObservation socket;
    socket.socket_cookie = cookie;
    socket.socket_inode = cookie + 1'000'000;
    socket.network_namespace_inode = event.network_namespace_inode;
    socket.local_ip = event.local->address;
    socket.local_port = *event.local->port;
    socket.remote_ip = event.remote->address;
    socket.remote_port = *event.remote->port;
    socket.endpoint_kind = neta::TcpEndpointKind::Connection;
    socket.transport.observed_ns = event.timestamp_ns + 1;
    socket.transport.state = 1;
    socket.transport.rtt_us = 1'000;
    return socket;
}

} // namespace

int main() {
    using namespace std::chrono_literals;
    constexpr std::uint64_t max_bytes = 700ULL * 1024ULL;
    constexpr std::uint64_t connection_count = 2'000;
    const auto path = std::filesystem::temp_directory_path() /
                      "neta-ms2-resource-churn.sqlite";
    remove_database(path);
    {
        neta::HistoryStore store(path);
        NoProcessResolver resolver;
        neta::ConnectionTracker tracker(store, resolver, "");
        neta::EvidenceScheduler scheduler(1s);
        neta::StorageMaintenance maintenance(store, max_bytes, 1s);
        const auto start = neta::StorageMaintenance::Clock::time_point{};

        for (std::uint64_t index = 0; index < connection_count; ++index) {
            const bool inbound = index % 2 == 0;
            auto event = open_event(index, inbound);
            const auto direction = inbound ? neta::ConnectionDirection::Inbound
                                           : neta::ConnectionDirection::Outbound;
            const auto admission = tracker.observe_lifecycle(event, direction);
            assert(admission && admission->newly_admitted);
            scheduler.connection_admitted(admission->connection_id);

            const auto cookie = 100'000 + index;
            const auto enrichment = tracker.observe_socket(
                socket_for(event, cookie), neta::ConnectionDirection::Unknown, false);
            assert(enrichment && enrichment->connection_id == admission->connection_id);

            event.type = neta::ConnectionLifecycleEventType::Close;
            event.timestamp_ns += 2;
            event.socket_cookie = cookie;
            const auto closed = tracker.observe_lifecycle(
                event, neta::ConnectionDirection::Unknown);
            assert(closed && closed->closed);
            scheduler.connection_closed(closed->connection_id);

            if ((index + 1) % 100 == 0) {
                static_cast<void>(maintenance.run_if_due(
                    start + std::chrono::seconds((index + 1) / 100)));
            }
        }

        maintenance.run_now();
        const auto status = store.status(max_bytes);
        assert(tracker.connections().empty());
        assert(scheduler.active_connections() == 0);
        scheduler.transport_sampled(neta::EvidenceScheduler::Clock::now());
        assert(scheduler.take_route_observations_due().empty());
        assert(status.bytes <= max_bytes);
        assert(status.connection_count <= connection_count);
        assert(neta::LifecycleHealth{0}.evidence_may_be_incomplete() == false);
        assert(neta::LifecycleHealth{17}.evidence_may_be_incomplete());
        std::cout << "connections_retained=" << status.connection_count << '\n'
                  << "samples_retained=" << status.sample_count << '\n'
                  << "sqlite_bytes=" << status.bytes << '\n';
    }
    remove_database(path);
    std::cout << "Resource churn MS2 tests passed\n";
}
