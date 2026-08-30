#include "neta/connection_tracker.hpp"
#include "neta/platform.hpp"

#include "lifecycle_decoder.hpp"
#include "lifecycle_wire.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <string>

using namespace neta;

namespace {

std::filesystem::path db_path(const std::string& name) {
    return std::filesystem::temp_directory_path() / ("neta-ms1-" + name + ".sqlite");
}

void remove_db(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

class FixedResolver final : public platform::ProcessResolver {
public:
    std::optional<ProcessIdentity> resolve(std::uint64_t inode) override {
        last_inode = inode;
        if (!available) return std::nullopt;
        return ProcessIdentity{9001, 1000, 1234, "poll-process", "/poll-process"};
    }
    bool available{true};
    std::uint64_t last_inode{0};
};

neta_lifecycle_wire_event wire_event(std::uint8_t type, std::uint64_t cookie) {
    neta_lifecycle_wire_event wire{};
    wire.version = NETA_LIFECYCLE_WIRE_VERSION;
    wire.size = static_cast<__u16>(sizeof(wire));
    wire.type = type;
    wire.family = AF_INET;
    wire.protocol = IPPROTO_TCP;
    wire.tcp_state = TCP_ESTABLISHED;
    wire.availability = NETA_HAS_KERNEL_PID | NETA_HAS_AGENT_PID |
                        NETA_HAS_AGENT_PID_NAMESPACE | NETA_HAS_UID | NETA_HAS_COOKIE |
                        NETA_HAS_NETNS | NETA_HAS_LOCAL | NETA_HAS_REMOTE |
                        NETA_HAS_START_TIME;
    wire.kernel_pid = 3101;
    wire.kernel_tgid = 3100;
    wire.agent_pid = 7101;
    wire.agent_tgid = 7100;
    wire.uid = 1000;
    wire.timestamp_ns = 9'000'000'000ULL;
    wire.socket_cookie = cookie;
    wire.network_namespace_inode = 42;
    wire.process_start_time_ns = 2'000'000'000ULL;
    wire.agent_pid_namespace_device = 13;
    wire.agent_pid_namespace_inode = 37;
    wire.local_port = 41000;
    wire.remote_port = 443;
    assert(::inet_pton(AF_INET, "127.0.0.1", wire.local_address) == 1);
    assert(::inet_pton(AF_INET, "127.0.0.2", wire.remote_address) == 1);
    std::memcpy(wire.comm, "short-client", 12);
    return wire;
}

ConnectionLifecycleEvent decode(const neta_lifecycle_wire_event& wire) {
    const auto* bytes = reinterpret_cast<const std::byte*>(&wire);
    auto decoded = platform::linux_ebpf::decode_lifecycle_event(
        std::span<const std::byte>(bytes, sizeof(wire)));
    assert(decoded.event);
    assert(decoded.error.empty());
    return *decoded.event;
}

SocketObservation matching_socket(std::uint64_t cookie) {
    SocketObservation socket;
    socket.socket_cookie = cookie;
    socket.network_namespace_inode = 42;
    socket.socket_inode = 8800;
    socket.uid = 1000;
    socket.local_ip = "127.0.0.1";
    socket.local_port = 41000;
    socket.remote_ip = "127.0.0.2";
    socket.remote_port = 443;
    socket.endpoint_kind = TcpEndpointKind::Connection;
    socket.transport.observed_ns = 9'100'000'000ULL;
    socket.transport.state = TCP_ESTABLISHED;
    socket.transport.rtt_us = 2000;
    socket.transport.snd_cwnd = 10;
    return socket;
}

void test_decoding_and_bounds() {
    const auto event = decode(wire_event(NETA_LIFECYCLE_CONNECT, 12345));
    assert(event.type == ConnectionLifecycleEventType::Connect);
    assert(event.provenance == LifecycleProvenance::EbpfCore);
    assert(event.process.agent_visible.pid == 7101);
    assert(event.process.agent_visible.tgid == 7100);
    assert(event.process.kernel.pid == 3101);
    assert(event.process.kernel.tgid == 3100);
    assert(event.process.agent_pid_namespace);
    assert(event.process.agent_pid_namespace->device == 13);
    assert(event.process.agent_pid_namespace->inode == 37);
    assert(event.process.uid == 1000);
    assert(event.process.start_ticks && *event.process.start_ticks > 0);
    assert(event.process.comm == "short-client");
    assert(event.network_namespace_inode == 42);
    assert(event.address_family == NetworkAddressFamily::IPv4);
    assert(event.protocol == TransportProtocol::Tcp);
    assert(event.local && event.local->address == "127.0.0.1");
    assert(event.local->port == 41000);
    assert(event.remote && event.remote->address == "127.0.0.2");
    assert(event.remote->port == 443);
    assert(event.socket_cookie == 12345);

    std::byte short_record[4]{};
    const auto truncated = platform::linux_ebpf::decode_lifecycle_event(short_record);
    assert(!truncated.event);
    assert(!truncated.error.empty());
}

void test_namespace_pid_failure_is_not_misattributed() {
    const auto path = db_path("pid-namespace-unavailable");
    remove_db(path);
    {
        HistoryStore store(path);
        FixedResolver resolver;
        ConnectionTracker tracker(store, resolver, "namespace.example");
        auto wire = wire_event(NETA_LIFECYCLE_CONNECT, 12346);
        wire.availability &= ~NETA_HAS_AGENT_PID;
        wire.agent_pid = 0;
        wire.agent_tgid = 0;

        const auto event = decode(wire);
        assert(event.process.kernel.pid == 3101);
        assert(event.process.kernel.tgid == 3100);
        assert(!event.process.agent_visible.pid);
        assert(!event.process.agent_visible.tgid);
        assert(event.process.agent_pid_namespace);
        assert(event.process.agent_pid_namespace->inode == 37);
        assert(!tracker.observe_lifecycle(event, ConnectionDirection::Outbound));
        assert(store.status(10'000'000).connection_count == 0);
    }
    remove_db(path);
}

void test_lifecycle_admission_correlation_and_close() {
    const auto path = db_path("tracker");
    remove_db(path);
    {
        HistoryStore store(path);
        FixedResolver resolver;
        resolver.available = false;
        ConnectionTracker tracker(store, resolver, "target.example");

        const auto connect = decode(wire_event(NETA_LIFECYCLE_CONNECT, 23456));
        const auto first = tracker.observe_lifecycle(connect, ConnectionDirection::Outbound);
        assert(first && first->newly_admitted);
        assert(store.status(10'000'000).connection_count == 1);

        const auto duplicate = tracker.observe_lifecycle(connect, ConnectionDirection::Outbound);
        assert(duplicate && !duplicate->newly_admitted);
        assert(store.status(10'000'000).connection_count == 1);

        const auto enriched = tracker.observe_socket(matching_socket(23456));
        assert(enriched && !enriched->newly_admitted);
        assert(enriched->connection_id == first->connection_id);
        assert(store.status(10'000'000).connection_count == 1);
        assert(store.samples_for_connection(first->connection_id).size() == 1);
        const auto lifecycle = store.lifecycle_events_for_connection(first->connection_id);
        assert(lifecycle.size() == 1);
        assert(lifecycle.front().process.agent_visible.tgid == 7100);
        assert(lifecycle.front().process.kernel.tgid == 3100);
        assert(lifecycle.front().process.agent_pid_namespace);
        assert(lifecycle.front().process.agent_pid_namespace->inode == 37);

        const auto persisted = store.connection(first->connection_id);
        assert(persisted);
        assert(persisted->process.pid == 7100);
        assert(persisted->process.comm == "short-client");

        const auto close = decode(wire_event(NETA_LIFECYCLE_CLOSE, 23456));
        const auto closed = tracker.observe_lifecycle(close, ConnectionDirection::Unknown);
        assert(closed && !closed->newly_admitted);
        assert(store.connection(first->connection_id)->lifecycle_state == "CLOSED");
        assert(!tracker.observe_lifecycle(close, ConnectionDirection::Unknown));
        assert(store.lifecycle_events_for_connection(first->connection_id).size() == 2);
        assert(store.status(10'000'000).connection_count == 1);
    }
    remove_db(path);
}

void test_accept_and_listen_semantics() {
    const auto path = db_path("accept");
    remove_db(path);
    {
        HistoryStore store(path);
        FixedResolver resolver;
        ConnectionTracker tracker(store, resolver, "inbound-foundation");

        auto accept_wire = wire_event(NETA_LIFECYCLE_ACCEPT, 0);
        accept_wire.availability &= ~NETA_HAS_COOKIE;
        const auto accepted = decode(accept_wire);
        assert(accepted.type == ConnectionLifecycleEventType::Accept);
        assert(!accepted.socket_cookie);
        const auto result = tracker.observe_lifecycle(accepted, ConnectionDirection::Inbound);
        assert(result && result->newly_admitted);

        const auto enrichment = tracker.observe_socket(matching_socket(34567));
        assert(enrichment && !enrichment->newly_admitted);
        assert(enrichment->connection_id == result->connection_id);
        assert(store.lifecycle_events_for_connection(result->connection_id)
                   .front().socket_cookie == std::nullopt);

        auto listen_wire = wire_event(NETA_LIFECYCLE_ACCEPT, 45678);
        listen_wire.tcp_state = TCP_LISTEN;
        assert(!tracker.observe_lifecycle(
            decode(listen_wire), ConnectionDirection::Inbound));
        assert(store.status(10'000'000).connection_count == 1);
    }
    remove_db(path);
}

void test_polling_fallback_and_attribution_guard() {
    const auto path = db_path("fallback");
    remove_db(path);
    {
        HistoryStore store(path);
        FixedResolver resolver;
        ConnectionTracker tracker(store, resolver, "fallback.example");
        auto socket = matching_socket(56789);

        resolver.available = false;
        assert(!tracker.observe_socket(socket));
        assert(store.status(10'000'000).connection_count == 0);

        resolver.available = true;
        const auto admitted = tracker.observe_socket(socket);
        assert(admitted && admitted->newly_admitted);
        assert(resolver.last_inode == socket.socket_inode);
        assert(store.status(10'000'000).connection_count == 1);

        tracker.begin_snapshot();
        tracker.end_snapshot(true);
        assert(store.connection(admitted->connection_id)->lifecycle_state == "DISAPPEARED");
    }
    remove_db(path);
}

void test_cookie_unavailable_fallback_is_one_incarnation() {
    const auto path = db_path("cookie-unavailable");
    remove_db(path);
    {
        HistoryStore store(path);
        FixedResolver resolver;
        ConnectionTracker tracker(store, resolver, "fallback-identity.example");
        auto wire = wire_event(NETA_LIFECYCLE_CONNECT, 0);
        wire.availability &= ~NETA_HAS_COOKIE;
        const auto lifecycle_admission = tracker.observe_lifecycle(
            decode(wire), ConnectionDirection::Outbound);
        assert(lifecycle_admission && lifecycle_admission->newly_admitted);

        const auto enrichment = tracker.observe_socket(matching_socket(67890));
        assert(enrichment && !enrichment->newly_admitted);
        assert(enrichment->connection_id == lifecycle_admission->connection_id);
        assert(store.status(10'000'000).connection_count == 1);
        assert(store.lifecycle_events_for_connection(enrichment->connection_id)
                   .front().socket_cookie == std::nullopt);
    }
    remove_db(path);
}

void test_capability_is_honest() {
    const auto observer = platform::make_lifecycle_observer();
    const auto& capability = observer->capability();
    if (!capability.available()) {
        assert(!capability.unavailable_reason.empty());
        assert(!(capability.connect_events && capability.accept_events &&
                 capability.close_events));
    }
}

} // namespace

int main() {
    test_decoding_and_bounds();
    test_namespace_pid_failure_is_not_misattributed();
    test_lifecycle_admission_correlation_and_close();
    test_accept_and_listen_semantics();
    test_polling_fallback_and_attribution_guard();
    test_cookie_unavailable_fallback_is_one_incarnation();
    test_capability_is_honest();
    std::cout << "All MS1 deterministic tests passed\n";
}
