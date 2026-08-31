#include "neta/observation_session.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <utility>
#include <vector>

namespace {

class FakeSocketObserver final : public neta::platform::ConnectionObserver {
public:
    std::vector<neta::SocketObservation> snapshot() override {
        neta::SocketObservation socket;
        socket.socket_cookie = 900;
        socket.socket_inode = 901;
        socket.network_namespace_inode = 77;
        socket.local_ip = "192.0.2.10";
        socket.local_port = 45000;
        socket.remote_ip = "203.0.113.20";
        socket.remote_port = 443;
        socket.endpoint_kind = neta::TcpEndpointKind::Connection;
        socket.transport.observed_ns = 2'000;
        socket.transport.state = 1;
        return {socket};
    }
};

class NoProcessResolver final : public neta::platform::ProcessResolver {
public:
    std::optional<neta::ProcessIdentity> resolve(std::uint64_t) override { return std::nullopt; }
};

class NoRouteObserver final : public neta::platform::RouteObserver {
public:
    std::optional<neta::RouteObservation> route_to(const std::string&) override {
        return std::nullopt;
    }
};

class OneConnectLifecycle final : public neta::LifecycleObserver {
public:
    OneConnectLifecycle() {
        capability_.built_in = true;
        capability_.btf_core_runtime = true;
        capability_.connect_events = true;
        capability_.close_events = true;
    }
    const neta::LifecycleCapability& capability() const noexcept override { return capability_; }
    neta::LifecycleHealth health() const override { return neta::LifecycleHealth{0}; }
    std::vector<neta::ConnectionLifecycleEvent> poll(std::chrono::milliseconds) override {
        ++polls_;
        if (polls_ != 1) return {};
        neta::ConnectionLifecycleEvent event;
        event.type = neta::ConnectionLifecycleEventType::Connect;
        event.timestamp_ns = 1'000;
        event.protocol = neta::TransportProtocol::Tcp;
        event.endpoint_kind = neta::TcpEndpointKind::Connection;
        event.process.agent_visible.pid = 42;
        event.process.agent_visible.tgid = 42;
        event.process.uid = 1000;
        event.process.start_ticks = 88;
        event.process.comm = "tls-client";
        event.network_namespace_inode = 77;
        event.socket_cookie = 900;
        event.local = neta::NetworkEndpoint{"192.0.2.10", 45000};
        event.remote = neta::NetworkEndpoint{"203.0.113.20", 443};
        return {event};
    }
    std::size_t polls() const noexcept { return polls_; }
private:
    neta::LifecycleCapability capability_;
    std::size_t polls_{0};
};

class NoNameResolution final : public neta::NameResolutionObserver {
public:
    NoNameResolution() { capability_.built_in = true; }
    const neta::NameResolutionCapability& capability() const noexcept override { return capability_; }
    neta::NameResolutionHealth health() const override { return {}; }
    std::vector<neta::NameResolutionObservation> poll(std::chrono::milliseconds) override { return {}; }
private:
    neta::NameResolutionCapability capability_;
};

class ScriptedTlsSessionObserver final : public neta::TlsSessionObserver {
public:
    ScriptedTlsSessionObserver() {
        capability_.application_instrumentation = true;
        capability_.sender_credentials_verified = true;
        capability_.source = "test";
    }
    const neta::TlsSessionCapability& capability() const noexcept override { return capability_; }
    neta::TlsSessionHealth health() const override { return {}; }
    std::vector<neta::TlsSessionObservation> poll(std::chrono::milliseconds) override {
        ++polls_;
        if (polls_ != 2) return {};
        neta::TlsSessionObservation event;
        event.observed_ns = 1'500;
        event.local_role = neta::TlsSessionRole::Client;
        event.process.pid = 42;
        event.process.uid = 1000;
        event.process.start_ticks = 88;
        event.process.comm = "tls-client";
        event.network_namespace_inode = 77;
        event.socket_cookie = 900;
        event.local = {"192.0.2.10", 45000};
        event.remote = {"203.0.113.20", 443};
        event.tls_version = "TLSv1.3";
        event.cipher = "TLS_AES_256_GCM_SHA384";
        event.peer_certificate_present = true;
        event.spki_sha256 = "spki";
        event.fidelity = neta::EvidenceFidelity::Exact;
        event.source = "openssl3:application-shim";
        return {event};
    }
    std::size_t polls() const noexcept { return polls_; }
private:
    neta::TlsSessionCapability capability_;
    std::size_t polls_{0};
};

class EmptySocketObserver final : public neta::platform::ConnectionObserver {
public:
    std::vector<neta::SocketObservation> snapshot() override { return {}; }
};

class AcceptThenCloseLifecycle final : public neta::LifecycleObserver {
public:
    explicit AcceptThenCloseLifecycle(std::uint64_t close_cookie)
        : close_cookie_(close_cookie) {
        capability_.built_in = true;
        capability_.btf_core_runtime = true;
        capability_.accept_events = true;
        capability_.close_events = true;
    }
    const neta::LifecycleCapability& capability() const noexcept override { return capability_; }
    neta::LifecycleHealth health() const override { return {}; }
    std::vector<neta::ConnectionLifecycleEvent> poll(std::chrono::milliseconds) override {
        ++polls_;
        if (polls_ > 2) return {};
        neta::ConnectionLifecycleEvent event;
        event.type = polls_ == 1 ? neta::ConnectionLifecycleEventType::Accept
                                 : neta::ConnectionLifecycleEventType::Close;
        event.timestamp_ns = polls_ == 1 ? 1'000 : 2'000;
        event.protocol = neta::TransportProtocol::Tcp;
        event.endpoint_kind = polls_ == 1 ? neta::TcpEndpointKind::Connection
                                          : neta::TcpEndpointKind::LifecycleTail;
        event.process.agent_visible.pid = 42;
        event.process.agent_visible.tgid = 42;
        event.process.uid = 1000;
        event.process.start_ticks = 88;
        event.process.comm = "openssl";
        event.network_namespace_inode = 77;
        event.local = neta::NetworkEndpoint{"::ffff:127.0.0.1", 9443};
        event.remote = neta::NetworkEndpoint{"::ffff:127.0.0.1", 55000};
        if (polls_ == 2) event.socket_cookie = close_cookie_;
        return {event};
    }
    std::size_t polls() const noexcept { return polls_; }
private:
    neta::LifecycleCapability capability_;
    std::uint64_t close_cookie_{0};
    std::size_t polls_{0};
};

class InboundTlsBeforeCloseObserver final : public neta::TlsSessionObserver {
public:
    explicit InboundTlsBeforeCloseObserver(std::uint64_t cookie) : cookie_(cookie) {
        capability_.application_instrumentation = true;
        capability_.sender_credentials_verified = true;
        capability_.source = "test";
    }
    const neta::TlsSessionCapability& capability() const noexcept override { return capability_; }
    neta::TlsSessionHealth health() const override { return {}; }
    std::vector<neta::TlsSessionObservation> poll(std::chrono::milliseconds) override {
        ++polls_;
        if (polls_ != 2) return {};
        neta::TlsSessionObservation event;
        event.observed_ns = 1'500;
        event.local_role = neta::TlsSessionRole::Server;
        event.process.pid = 42;
        event.process.uid = 1000;
        event.process.start_ticks = 88;
        event.process.comm = "openssl";
        event.network_namespace_inode = 77;
        event.socket_cookie = cookie_;
        event.local = {"::ffff:127.0.0.1", 9443};
        event.remote = {"::ffff:127.0.0.1", 55000};
        event.tls_version = "TLSv1.3";
        event.cipher = "TLS_AES_256_GCM_SHA384";
        event.fidelity = neta::EvidenceFidelity::Exact;
        event.source = "openssl3:application-shim";
        return {event};
    }
    std::size_t polls() const noexcept { return polls_; }
private:
    neta::TlsSessionCapability capability_;
    std::uint64_t cookie_{0};
    std::size_t polls_{0};
};

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void exact_tls_session_is_attached_to_admitted_connection() {
    using namespace std::chrono_literals;
    const auto path = std::filesystem::temp_directory_path() /
                      "neta-ms3-observation-tls.sqlite";
    remove_database(path);
    neta::HistoryStore store(path);
    FakeSocketObserver sockets;
    OneConnectLifecycle lifecycle;
    NoProcessResolver processes;
    NoRouteObserver routes;
    NoNameResolution names;
    ScriptedTlsSessionObserver tls;
    neta::AdmissionPolicyConfig config;
    config.mode = neta::ObservationMode::Outbound;
    neta::ObservationSession session(store, sockets, lifecycle, processes, routes,
                                     neta::ConnectionAdmissionPolicy(config), "", nullptr,
                                     &names, &tls);
    const auto result = session.run(1s, 1ms, [&] { return tls.polls() >= 3; });
    assert(result.admitted_connections == 1);
    assert(result.tls_session_events_observed == 1);
    assert(result.tls_session_evidence_attached == 1);
    assert(result.ambiguous_tls_session_matches == 0);
    assert(result.connection_ids.size() == 1);
    const auto evidence = store.tls_session_evidence_for_connection(result.connection_ids.front());
    assert(evidence.size() == 1);
    assert(evidence.front().correlation_fidelity == neta::EvidenceFidelity::Exact);
    assert(evidence.front().relation == neta::TlsSessionRelation::OutboundServerIdentity);
    remove_database(path);
}

void inbound_tls_session_retries_after_close_cookie_promotion(
    std::uint64_t tls_cookie, std::uint64_t close_cookie, bool expect_attachment) {
    using namespace std::chrono_literals;
    const auto path = std::filesystem::temp_directory_path() /
                      (expect_attachment
                           ? "neta-ms3-observation-tls-close-promotion.sqlite"
                           : "neta-ms3-observation-tls-close-mismatch.sqlite");
    remove_database(path);
    neta::HistoryStore store(path);
    EmptySocketObserver sockets;
    AcceptThenCloseLifecycle lifecycle(close_cookie);
    NoProcessResolver processes;
    NoRouteObserver routes;
    NoNameResolution names;
    InboundTlsBeforeCloseObserver tls(tls_cookie);
    neta::AdmissionPolicyConfig config;
    config.mode = neta::ObservationMode::Inbound;
    neta::ObservationSession session(store, sockets, lifecycle, processes, routes,
                                     neta::ConnectionAdmissionPolicy(config), "", nullptr,
                                     &names, &tls);
    const auto result = session.run(1s, 1ms, [&] {
        return lifecycle.polls() >= 2 && tls.polls() >= 4;
    });
    assert(result.admitted_connections == 1);
    assert(result.tls_session_events_observed == 1);
    assert(result.tls_session_evidence_attached == (expect_attachment ? 1U : 0U));
    assert(result.ambiguous_tls_session_matches == 0);
    assert(result.connection_ids.size() == 1);
    const auto connection = store.connection(result.connection_ids.front());
    assert(connection && connection->socket_cookie == close_cookie);
    const auto evidence = store.tls_session_evidence_for_connection(
        result.connection_ids.front());
    assert(evidence.size() == (expect_attachment ? 1U : 0U));
    if (expect_attachment) {
        assert(evidence.front().correlation_fidelity == neta::EvidenceFidelity::Exact);
        assert(evidence.front().relation == neta::TlsSessionRelation::InboundTlsSession);
    }
    remove_database(path);
}

} // namespace

int main() {
    exact_tls_session_is_attached_to_admitted_connection();
    inbound_tls_session_retries_after_close_cookie_promotion(176, 176, true);
    inbound_tls_session_retries_after_close_cookie_promotion(176, 177, false);
    std::cout << "ObservationSession TLS session tests passed\n";
}
