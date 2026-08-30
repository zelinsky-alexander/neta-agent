#include "neta/observation_session.hpp"
#include "neta/verdict.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>
#include <utility>
#include <vector>

namespace {

class FakeSocketObserver final : public neta::platform::ConnectionObserver {
public:
    explicit FakeSocketObserver(std::vector<neta::SocketObservation> sockets)
        : sockets_(std::move(sockets)) {}

    std::vector<neta::SocketObservation> snapshot() override { return sockets_; }

private:
    std::vector<neta::SocketObservation> sockets_;
};

class ScriptedSocketObserver final : public neta::platform::ConnectionObserver {
public:
    explicit ScriptedSocketObserver(std::vector<std::vector<neta::SocketObservation>> snapshots)
        : snapshots_(std::move(snapshots)) {}

    std::vector<neta::SocketObservation> snapshot() override {
        ++snapshot_count_;
        const auto index = std::min(snapshot_count_ - 1, snapshots_.size() - 1);
        return snapshots_[index];
    }

    std::size_t snapshot_count() const noexcept { return snapshot_count_; }

private:
    std::vector<std::vector<neta::SocketObservation>> snapshots_;
    std::size_t snapshot_count_{0};
};

class FakeLifecycleObserver final : public neta::LifecycleObserver {
public:
    FakeLifecycleObserver(std::vector<neta::ConnectionLifecycleEvent> opens,
                          std::vector<neta::ConnectionLifecycleEvent> closes)
        : batches_{std::move(opens), std::move(closes)} {
        capability_.built_in = true;
        capability_.btf_core_runtime = true;
        capability_.connect_events = true;
        capability_.accept_events = true;
        capability_.close_events = true;
        capability_.drop_counter = true;
    }

    const neta::LifecycleCapability& capability() const noexcept override {
        return capability_;
    }
    neta::LifecycleHealth health() const override { return neta::LifecycleHealth{0}; }
    std::vector<neta::ConnectionLifecycleEvent> poll(std::chrono::milliseconds) override {
        if (polls_ >= batches_.size()) return {};
        return batches_[polls_++];
    }
    std::size_t polls() const noexcept { return polls_; }

private:
    neta::LifecycleCapability capability_;
    std::vector<std::vector<neta::ConnectionLifecycleEvent>> batches_;
    std::size_t polls_{0};
};

class WaitingLifecycleObserver final : public neta::LifecycleObserver {
public:
    explicit WaitingLifecycleObserver(neta::ConnectionLifecycleEvent connect)
        : connect_(std::move(connect)) {
        capability_.built_in = true;
        capability_.btf_core_runtime = true;
        capability_.connect_events = true;
        capability_.close_events = true;
    }

    const neta::LifecycleCapability& capability() const noexcept override {
        return capability_;
    }
    neta::LifecycleHealth health() const override { return neta::LifecycleHealth{0}; }
    std::vector<neta::ConnectionLifecycleEvent> poll(std::chrono::milliseconds timeout) override {
        if (!delivered_) {
            delivered_ = true;
            return {connect_};
        }
        std::this_thread::sleep_for(timeout);
        return {};
    }

private:
    neta::LifecycleCapability capability_;
    neta::ConnectionLifecycleEvent connect_;
    bool delivered_{false};
};

class NoProcessResolver final : public neta::platform::ProcessResolver {
public:
    std::optional<neta::ProcessIdentity> resolve(std::uint64_t) override {
        return std::nullopt;
    }
};

class FakeRouteObserver final : public neta::platform::RouteObserver {
public:
    std::optional<neta::RouteObservation> route_to(const std::string& destination) override {
        neta::RouteObservation route;
        route.destination = destination;
        route.source = "127.0.0.1";
        route.interface_name = "lo";
        route.interface_index = 1;
        route.observed_ns = 50;
        route.sha256 = "route-" + destination;
        return route;
    }
};

neta::ConnectionLifecycleEvent lifecycle_event(
    neta::ConnectionLifecycleEventType type, std::uint64_t timestamp,
    std::int64_t pid, const char* process, std::uint16_t local_port,
    std::uint16_t remote_port, std::optional<std::uint64_t> cookie) {
    neta::ConnectionLifecycleEvent event;
    event.type = type;
    event.timestamp_ns = timestamp;
    event.protocol = neta::TransportProtocol::Tcp;
    event.endpoint_kind = neta::TcpEndpointKind::Connection;
    event.network_namespace_inode = 42;
    event.local = neta::NetworkEndpoint{"127.0.0.1", local_port};
    event.remote = neta::NetworkEndpoint{"127.0.0.2", remote_port};
    event.process.agent_visible.pid = pid;
    event.process.agent_visible.tgid = pid;
    event.process.uid = 1000;
    event.process.start_ticks = static_cast<std::uint64_t>(pid);
    event.process.comm = process;
    event.socket_cookie = cookie;
    return event;
}

neta::SocketObservation socket(std::uint64_t cookie, std::uint16_t local_port,
                               std::uint16_t remote_port,
                               neta::TcpEndpointKind kind = neta::TcpEndpointKind::Connection) {
    neta::SocketObservation result;
    result.socket_cookie = cookie;
    result.socket_inode = cookie + 1000;
    result.network_namespace_inode = 42;
    result.local_ip = "127.0.0.1";
    result.local_port = local_port;
    result.remote_ip = kind == neta::TcpEndpointKind::Listener ? "0.0.0.0" : "127.0.0.2";
    result.remote_port = remote_port;
    result.endpoint_kind = kind;
    result.transport.observed_ns = 150;
    result.transport.state = 1;
    result.transport.rtt_us = 1000;
    return result;
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

} // namespace

int main() {
    using namespace std::chrono_literals;
    const auto path = std::filesystem::temp_directory_path() /
                      "neta-ms2-observation-session.sqlite";
    remove_database(path);
    {
        auto connect = lifecycle_event(neta::ConnectionLifecycleEventType::Connect, 100,
                                       111, "client", 40001, 50001, 101);
        auto accept = lifecycle_event(neta::ConnectionLifecycleEventType::Accept, 101,
                                      222, "server", 50002, 40002, std::nullopt);
        auto connect_close = connect;
        connect_close.type = neta::ConnectionLifecycleEventType::Close;
        connect_close.timestamp_ns = 200;
        auto accept_close = accept;
        accept_close.type = neta::ConnectionLifecycleEventType::Close;
        accept_close.timestamp_ns = 201;
        accept_close.socket_cookie = 202;

        FakeLifecycleObserver lifecycle({connect, accept}, {connect_close, accept_close});
        FakeSocketObserver sockets({socket(101, 40001, 50001),
                                    socket(202, 50002, 40002),
                                    socket(303, 50002, 0, neta::TcpEndpointKind::Listener)});
        NoProcessResolver processes;
        FakeRouteObserver routes;
        neta::HistoryStore store(path);
        neta::AdmissionPolicyConfig config;
        config.mode = neta::ObservationMode::All;
        neta::ObservationSession session(
            store, sockets, lifecycle, processes, routes,
            neta::ConnectionAdmissionPolicy(config), "");

        const auto result = session.run(std::chrono::seconds(1), 1ms, [&] {
            return lifecycle.polls() >= 2;
        });
        assert(result.lifecycle_events_active);
        assert(result.admitted_connections == 2);
        assert(result.connection_ids.size() == 2);

        const auto rows = store.recent_connections(10);
        assert(rows.size() == 2);
        for (const auto& row : rows) {
            assert(row.lifecycle_state == "CLOSED");
            assert(row.network_namespace_inode == 42);
            assert(!store.samples_for_connection(row.id).empty());
            const auto route = store.route_for_connection(row.id);
            assert(route);
            if (row.direction == neta::ConnectionDirection::Outbound) {
                assert(row.process.pid == 111);
                assert(row.socket_cookie == 101);
                assert(route->relation == neta::RouteRelation::OutboundSelectedRoute);
            } else {
                assert(row.direction == neta::ConnectionDirection::Inbound);
                assert(row.process.pid == 222);
                assert(row.socket_cookie == 202);
                assert(route->relation == neta::RouteRelation::InboundResponseRoute);
            }
        }
    }
    remove_database(path);
    {
        auto connect = lifecycle_event(neta::ConnectionLifecycleEventType::Connect, 300,
                                       333, "target-client", 41001, 443, 404);
        auto close = connect;
        close.type = neta::ConnectionLifecycleEventType::Close;
        close.timestamp_ns = 301;

        // Deliver CONNECT and CLOSE in one lifecycle batch. Immediate enrichment
        // must run when CONNECT is admitted, before CLOSE retires scheduler state.
        FakeLifecycleObserver lifecycle({connect, close}, {});
        auto syn_sent = socket(404, 41001, 443);
        syn_sent.transport.state = 2;
        syn_sent.transport.rtt_us = 0;
        FakeSocketObserver sockets({syn_sent});
        NoProcessResolver processes;
        FakeRouteObserver routes;
        neta::HistoryStore store(path);
        neta::AdmissionPolicyConfig config;
        config.mode = neta::ObservationMode::Target;
        config.target_addresses.insert("127.0.0.2");
        config.target_port = 443;
        neta::ObservationSession session(
            store, sockets, lifecycle, processes, routes,
            neta::ConnectionAdmissionPolicy(config), "example.com");

        const auto result = session.run(std::chrono::seconds(1), 1s, [&] {
            return lifecycle.polls() >= 1;
        });
        assert(result.admitted_connections == 1);
        assert(result.connection_ids.size() == 1);
        const auto connection = store.connection(result.connection_ids.front());
        assert(connection);
        assert(connection->direction == neta::ConnectionDirection::Outbound);
        assert(connection->socket_cookie == 404);
        assert(connection->target_host == "example.com");
        assert(connection->remote_ip == "127.0.0.2");
        assert(connection->remote_port == 443);
        const auto samples = store.samples_for_connection(connection->id);
        assert(samples.size() == 1);
        assert(samples.front().state == 2);
        assert(samples.front().rtt_us == 0);
        assert(neta::aggregate_metrics(samples).observed_rtt_us == 0);
        assert(store.recent_samples_for_target("example.com", 443, 200).size() == 1);
    }
    remove_database(path);
    {
        auto connect = lifecycle_event(neta::ConnectionLifecycleEventType::Connect, 400,
                                       444, "target-client", 42001, 443, 505);
        WaitingLifecycleObserver lifecycle(connect);
        auto syn_sent = socket(505, 42001, 443);
        syn_sent.transport.state = 2;
        syn_sent.transport.rtt_us = 0;
        syn_sent.transport.rtt_variance_us = 250'000;
        auto established = syn_sent;
        established.transport.observed_ns = 450;
        established.transport.state = 1;
        established.transport.rtt_us = 1'250;
        established.transport.rtt_variance_us = 300;
        ScriptedSocketObserver sockets({{syn_sent}, {established}});
        NoProcessResolver processes;
        FakeRouteObserver routes;
        neta::HistoryStore store(path);
        neta::AdmissionPolicyConfig config;
        config.mode = neta::ObservationMode::Target;
        config.target_addresses.insert("127.0.0.2");
        config.target_port = 443;
        neta::ObservationSession session(
            store, sockets, lifecycle, processes, routes,
            neta::ConnectionAdmissionPolicy(config), "example.com");

        const auto result = session.run(std::chrono::seconds(1), 1s, [&] {
            return sockets.snapshot_count() >= 2;
        });
        assert(result.connection_ids.size() == 1);
        const auto samples = store.samples_for_connection(result.connection_ids.front());
        assert(samples.size() == 2);
        assert(samples.front().state == 2);
        assert(samples.front().rtt_us == 0);
        assert(samples.back().state == 1);
        assert(samples.back().rtt_us == 1'250);

        const auto target_samples = store.recent_samples_for_target("example.com", 443, 200);
        assert(target_samples.size() == 2);
        const auto rtt_samples = std::count_if(target_samples.begin(), target_samples.end(),
                                               [](const auto& sample) {
                                                   return sample.rtt_us != 0;
                                               });
        assert(rtt_samples == 1);
        const auto metrics = neta::aggregate_metrics(target_samples);
        assert(metrics.observed_rtt_us == 1'250);
        assert(metrics.observed_rttvar_us == 300);
    }
    remove_database(path);
    std::cout << "Observation session MS2 tests passed\n";
}
