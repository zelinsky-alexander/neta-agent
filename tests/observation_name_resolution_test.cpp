#include "neta/observation_session.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

namespace {

class FakeSocketObserver final : public neta::platform::ConnectionObserver {
public:
    std::vector<neta::SocketObservation> snapshot() override {
        neta::SocketObservation socket;
        socket.socket_cookie = 101;
        socket.socket_inode = 1101;
        socket.network_namespace_inode = 77;
        socket.local_ip = "192.0.2.10";
        socket.local_port = 45000;
        socket.remote_ip = "203.0.113.20";
        socket.remote_port = 443;
        socket.endpoint_kind = neta::TcpEndpointKind::Connection;
        socket.transport.observed_ns = 10'100'000'000ULL;
        socket.transport.state = 1;
        socket.transport.rtt_us = 1'000;
        return {socket};
    }
};

class FakeLifecycleObserver final : public neta::LifecycleObserver {
public:
    FakeLifecycleObserver() {
        capability_.built_in = true;
        capability_.btf_core_runtime = true;
        capability_.connect_events = true;
        capability_.close_events = true;
        batches_.push_back({event(neta::ConnectionLifecycleEventType::Connect,
                                  10'000'000'000ULL)});
        batches_.push_back({event(neta::ConnectionLifecycleEventType::Close,
                                  10'200'000'000ULL)});
    }

    const neta::LifecycleCapability& capability() const noexcept override { return capability_; }
    neta::LifecycleHealth health() const override { return neta::LifecycleHealth{0}; }
    std::vector<neta::ConnectionLifecycleEvent> poll(std::chrono::milliseconds) override {
        if (polls_ >= batches_.size()) { ++polls_; return {}; }
        return batches_[polls_++];
    }
    std::size_t polls() const noexcept { return polls_; }

private:
    static neta::ConnectionLifecycleEvent event(neta::ConnectionLifecycleEventType type,
                                                std::uint64_t timestamp) {
        neta::ConnectionLifecycleEvent event;
        event.type = type;
        event.timestamp_ns = timestamp;
        event.protocol = neta::TransportProtocol::Tcp;
        event.endpoint_kind = neta::TcpEndpointKind::Connection;
        event.network_namespace_inode = 77;
        event.local = neta::NetworkEndpoint{"192.0.2.10", 45000};
        event.remote = neta::NetworkEndpoint{"203.0.113.20", 443};
        event.process.agent_visible.pid = 4242;
        event.process.agent_visible.tgid = 4242;
        event.process.uid = 1000;
        event.process.start_ticks = 900;
        event.process.comm = "resolver-client";
        event.socket_cookie = 101;
        return event;
    }

    neta::LifecycleCapability capability_;
    std::vector<std::vector<neta::ConnectionLifecycleEvent>> batches_;
    std::size_t polls_{0};
};

class FakeNameResolutionObserver final : public neta::NameResolutionObserver {
public:
    explicit FakeNameResolutionObserver(std::vector<neta::NameResolutionObservation> observations)
        : observations_(std::move(observations)) {
        capability_.built_in = true;
        capability_.application_resolver_api = true;
        capability_.glibc_getaddrinfo = true;
        capability_.drop_counter = true;
        capability_.source = "deterministic-resolver";
    }

    const neta::NameResolutionCapability& capability() const noexcept override {
        return capability_;
    }
    neta::NameResolutionHealth health() const override { return neta::NameResolutionHealth{0}; }
    std::vector<neta::NameResolutionObservation> poll(std::chrono::milliseconds) override {
        if (delivered_) return {};
        delivered_ = true;
        return observations_;
    }

private:
    neta::NameResolutionCapability capability_;
    std::vector<neta::NameResolutionObservation> observations_;
    bool delivered_{false};
};

class NoProcessResolver final : public neta::platform::ProcessResolver {
public:
    std::optional<neta::ProcessIdentity> resolve(std::uint64_t) override { return std::nullopt; }
};

class FakeRouteObserver final : public neta::platform::RouteObserver {
public:
    std::optional<neta::RouteObservation> route_to(const std::string& destination) override {
        neta::RouteObservation route;
        route.destination = destination;
        route.interface_name = "test0";
        route.sha256 = "route";
        return route;
    }
};

neta::NameResolutionObservation lookup(std::uint64_t completed_ns) {
    neta::NameResolutionObservation observation;
    observation.started_ns = completed_ns - 1'000'000ULL;
    observation.completed_ns = completed_ns;
    observation.query_kind = neta::NameResolutionQueryKind::Forward;
    observation.mechanism = neta::NameResolutionMechanism::ApplicationResolverApi;
    observation.process.agent_visible.pid = 4242;
    observation.process.agent_visible.tgid = 4242;
    observation.process.uid = 1000;
    observation.process.start_ticks = 900;
    observation.network_namespace_inode = 77;
    observation.query_name = "api.example.test";
    observation.addresses.push_back({neta::NetworkAddressFamily::IPv4, "203.0.113.20"});
    observation.result_code = 0;
    observation.fidelity = neta::EvidenceFidelity::Exact;
    observation.source = "glibc:getaddrinfo";
    return observation;
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

neta::ObservationRunResult run_session(const std::filesystem::path& path,
                                       std::vector<neta::NameResolutionObservation> observations) {
    FakeSocketObserver sockets;
    FakeLifecycleObserver lifecycle;
    FakeNameResolutionObserver names(std::move(observations));
    NoProcessResolver processes;
    FakeRouteObserver routes;
    neta::HistoryStore store(path);
    neta::AdmissionPolicyConfig config;
    config.mode = neta::ObservationMode::Outbound;
    neta::ObservationSession session(store, sockets, lifecycle, processes, routes,
                                     neta::ConnectionAdmissionPolicy(config), "",
                                     nullptr, &names);
    return session.run(std::chrono::seconds(1), std::chrono::milliseconds(1), [&] {
        return lifecycle.polls() >= 2;
    });
}

void unique_lookup_attaches_to_connection() {
    const auto path = std::filesystem::temp_directory_path() /
                      "neta-ms3-observation-name.sqlite";
    remove_database(path);
    const auto result = run_session(path, {lookup(9'500'000'000ULL)});
    assert(result.name_resolution_events_active);
    assert(result.name_resolution_events_observed == 1);
    assert(result.name_resolution_evidence_attached == 1);
    assert(result.ambiguous_name_resolution_matches == 0);
    assert(result.connection_ids.size() == 1);
    {
        neta::HistoryStore store(path);
        const auto evidence = store.name_resolution_evidence_for_connection(
            result.connection_ids.front());
        assert(evidence.size() == 1);
        assert(evidence.front().observation.query_name == "api.example.test");
        assert(evidence.front().observation.result_code == 0);
        assert(evidence.front().correlation_fidelity ==
               neta::EvidenceFidelity::StronglyCorrelated);
    }
    remove_database(path);
}

void ambiguous_lookup_remains_unresolved() {
    const auto path = std::filesystem::temp_directory_path() /
                      "neta-ms3-observation-name-ambiguous.sqlite";
    remove_database(path);
    const auto result = run_session(path,
        {lookup(9'400'000'000ULL), lookup(9'500'000'000ULL)});
    assert(result.name_resolution_events_observed == 2);
    assert(result.name_resolution_evidence_attached == 0);
    assert(result.ambiguous_name_resolution_matches == 1);
    {
        neta::HistoryStore store(path);
        assert(store.name_resolution_evidence_for_connection(
            result.connection_ids.front()).empty());
    }
    remove_database(path);
}

} // namespace

int main() {
    unique_lookup_attaches_to_connection();
    ambiguous_lookup_remains_unresolved();
    std::cout << "Observation name-resolution tests passed\n";
}
