#include "neta/connection_admission_policy.hpp"
#include "neta/connection_tracker.hpp"
#include "neta/history_store.hpp"
#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

namespace {

neta::ConnectionLifecycleEvent lifecycle_event(neta::ConnectionLifecycleEventType type,
                                               neta::TcpEndpointKind endpoint_kind) {
    neta::ConnectionLifecycleEvent event;
    event.type = type;
    event.provenance = neta::LifecycleProvenance::WindowsEtw;
    event.protocol = neta::TransportProtocol::Tcp;
    event.endpoint_kind = endpoint_kind;
    event.local = neta::NetworkEndpoint{"127.0.0.1", 50000};
    event.remote = neta::NetworkEndpoint{"127.0.0.1", 9443};
    return event;
}

void verify_direction_semantics() {
    neta::AdmissionPolicyConfig config;
    config.mode = neta::ObservationMode::All;
    neta::ConnectionAdmissionPolicy policy(config);

    const auto connect = policy.evaluate(
        lifecycle_event(neta::ConnectionLifecycleEventType::Connect,
                        neta::TcpEndpointKind::Connection));
    assert(connect.admit);
    assert(connect.direction == neta::ConnectionDirection::Outbound);

    const auto accept = policy.evaluate(
        lifecycle_event(neta::ConnectionLifecycleEventType::Accept,
                        neta::TcpEndpointKind::Connection));
    assert(accept.admit);
    assert(accept.direction == neta::ConnectionDirection::Inbound);

    const auto listener = policy.evaluate(
        lifecycle_event(neta::ConnectionLifecycleEventType::Accept,
                        neta::TcpEndpointKind::Listener));
    assert(!listener.admit);
    assert(listener.direction == neta::ConnectionDirection::Unknown);

    const auto close = policy.evaluate(
        lifecycle_event(neta::ConnectionLifecycleEventType::Close,
                        neta::TcpEndpointKind::LifecycleTail));
    assert(close.admit);
    assert(close.direction == neta::ConnectionDirection::Unknown);
}

struct WinsockGuard {
    bool ready{false};
    WinsockGuard() {
        WSADATA data{};
        ready = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }
    ~WinsockGuard() { if (ready) WSACleanup(); }
};

struct SocketGuard {
    SOCKET value{INVALID_SOCKET};
    ~SocketGuard() { if (value != INVALID_SOCKET) closesocket(value); }
};

std::uint16_t local_port(SOCKET socket) {
    sockaddr_in address{};
    int size = sizeof(address);
    assert(getsockname(socket, reinterpret_cast<sockaddr*>(&address), &size) == 0);
    return ntohs(address.sin_port);
}

std::filesystem::path reconciliation_db_path() {
    wchar_t temp[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    assert(length != 0 && length < MAX_PATH);
    return std::filesystem::path(temp) /
        (L"neta-w3-reconciliation-" + std::to_wstring(GetCurrentProcessId()) + L".sqlite");
}

neta::SocketObservation reconciliation_socket(std::uint64_t observed_ns) {
    neta::SocketObservation socket;
    socket.owning_pid = static_cast<std::int64_t>(GetCurrentProcessId());
    socket.local_ip = "127.0.0.1";
    socket.local_port = 51000;
    socket.remote_ip = "127.0.0.1";
    socket.remote_port = 9443;
    socket.endpoint_kind = neta::TcpEndpointKind::Connection;
    socket.transport.observed_ns = observed_ns;
    socket.transport.state = 5;
    return socket;
}

neta::ConnectionLifecycleEvent reconciliation_event(
    neta::ConnectionLifecycleEventType type, std::uint64_t connid,
    const neta::ProcessIdentity& process, std::uint64_t timestamp_ns) {
    neta::ConnectionLifecycleEvent event;
    event.type = type;
    event.timestamp_ns = timestamp_ns;
    event.provenance = neta::LifecycleProvenance::WindowsEtw;
    event.process.agent_visible.pid = process.pid;
    event.process.agent_visible.tgid = process.pid;
    event.process.kernel = event.process.agent_visible;
    event.process.uid = process.uid;
    event.process.start_ticks = process.start_ticks;
    event.process.comm = process.comm;
    event.address_family = neta::NetworkAddressFamily::IPv4;
    event.protocol = neta::TransportProtocol::Tcp;
    event.endpoint_kind = type == neta::ConnectionLifecycleEventType::Close
        ? neta::TcpEndpointKind::LifecycleTail : neta::TcpEndpointKind::Connection;
    event.local = neta::NetworkEndpoint{"127.0.0.1", 51000};
    event.remote = neta::NetworkEndpoint{"127.0.0.1", 9443};
    event.platform_connection_id = connid;
    return event;
}

void verify_reconciliation_tracker() {
    const auto path = reconciliation_db_path();
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(path.string() + "-wal", ignored);
    std::filesystem::remove(path.string() + "-shm", ignored);

    {
        neta::HistoryStore store(path);
        auto resolver = neta::platform::make_process_resolver();
        neta::ConnectionTracker tracker(store, *resolver, "loopback.test");
        auto socket = reconciliation_socket(1'000'000'000ULL);
        const auto process = resolver->resolve(socket);
        assert(process.has_value());

        // Snapshot-before-ETW: admit UNKNOWN preexisting, then promote the same object when ETW
        // arrives. There must not be a second history connection.
        const auto preexisting = tracker.observe_socket(
            socket, neta::ConnectionDirection::Unknown, true,
            neta::ConnectionObservationOrigin::SnapshotPreexisting);
        assert(preexisting && preexisting->newly_admitted);
        const auto first_id = preexisting->connection_id;
        assert(store.status(100'000'000).connection_count == 1);

        const auto connect = reconciliation_event(
            neta::ConnectionLifecycleEventType::Connect, 1001, *process, 1'010'000'000ULL);
        const auto promoted = tracker.observe_lifecycle(
            connect, neta::ConnectionDirection::Outbound);
        assert(promoted && !promoted->newly_admitted && promoted->direction_promoted);
        assert(promoted->connection_id == first_id);
        assert(store.status(100'000'000).connection_count == 1);
        assert(store.connection(first_id)->direction == neta::ConnectionDirection::Outbound);

        // Snapshot enrichment after ETW must bind to the exact same connection.
        socket.transport.observed_ns = 1'020'000'000ULL;
        const auto enriched = tracker.observe_socket(
            socket, neta::ConnectionDirection::Unknown, false);
        assert(enriched && enriched->connection_id == first_id);
        assert(store.status(100'000'000).connection_count == 1);

        // With clean ETW, snapshot absence alone never closes the connection.
        for (int i = 0; i < 5; ++i) {
            tracker.begin_snapshot();
            assert(tracker.end_snapshot(false, false).empty());
        }
        assert(tracker.connections().size() == 1);

        // The exact ETW close owns lifecycle termination.
        const auto close = reconciliation_event(
            neta::ConnectionLifecycleEventType::Close, 1001, *process, 1'030'000'000ULL);
        const auto closed = tracker.observe_lifecycle(close, neta::ConnectionDirection::Unknown);
        assert(closed && closed->closed && closed->connection_id == first_id);
        assert(tracker.connections().empty());

        // Immediate tuple reuse with a different ETW connid is a different connection.
        const auto connect_reuse = reconciliation_event(
            neta::ConnectionLifecycleEventType::Connect, 1002, *process, 1'040'000'000ULL);
        const auto reused = tracker.observe_lifecycle(
            connect_reuse, neta::ConnectionDirection::Outbound);
        assert(reused && reused->newly_admitted && reused->connection_id != first_id);
        const auto second_id = reused->connection_id;
        const auto close_reuse = reconciliation_event(
            neta::ConnectionLifecycleEventType::Close, 1002, *process, 1'050'000'000ULL);
        assert(tracker.observe_lifecycle(close_reuse, neta::ConnectionDirection::Unknown)->closed);

        // ETW-only short-lived connection: no TCP table snapshot is required at all.
        const auto connect_short = reconciliation_event(
            neta::ConnectionLifecycleEventType::Connect, 1003, *process, 1'060'000'000ULL);
        const auto short_admission = tracker.observe_lifecycle(
            connect_short, neta::ConnectionDirection::Outbound);
        assert(short_admission && short_admission->newly_admitted);
        const auto short_id = short_admission->connection_id;
        const auto close_short = reconciliation_event(
            neta::ConnectionLifecycleEventType::Close, 1003, *process, 1'061'000'000ULL);
        const auto short_close = tracker.observe_lifecycle(
            close_short, neta::ConnectionDirection::Unknown);
        assert(short_close && short_close->closed && short_close->connection_id == short_id);

        // When lifecycle health is degraded, three consecutive snapshot misses repair a missing
        // close instead of leaving the connection active forever.
        const auto connect_lost = reconciliation_event(
            neta::ConnectionLifecycleEventType::Connect, 1004, *process, 1'070'000'000ULL);
        const auto lost = tracker.observe_lifecycle(
            connect_lost, neta::ConnectionDirection::Outbound);
        assert(lost && lost->newly_admitted);
        tracker.begin_snapshot();
        assert(tracker.end_snapshot(false, true).empty());
        tracker.begin_snapshot();
        assert(tracker.end_snapshot(false, true).empty());
        tracker.begin_snapshot();
        const auto repaired = tracker.end_snapshot(false, true);
        assert(repaired.size() == 1 && repaired.front() == lost->connection_id);
        assert(store.connection(lost->connection_id)->lifecycle_state ==
               "RECONCILED_ABSENT_AFTER_LIFECYCLE_LOSS");

        assert(second_id != short_id);
    }

    std::filesystem::remove(path, ignored);
    std::filesystem::remove(path.string() + "-wal", ignored);
    std::filesystem::remove(path.string() + "-shm", ignored);
}

void verify_real_etw_lifecycle() {
    auto lifecycle = neta::platform::make_lifecycle_observer();
    if (!lifecycle->capability().available()) {
        std::cout << "ETW lifecycle runtime test skipped: "
                  << lifecycle->capability().unavailable_reason << '\n';
        return;
    }

    WinsockGuard winsock;
    assert(winsock.ready);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    SocketGuard listener{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    assert(listener.value != INVALID_SOCKET);
    sockaddr_in listen_address{};
    listen_address.sin_family = AF_INET;
    listen_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listen_address.sin_port = 0;
    assert(bind(listener.value, reinterpret_cast<sockaddr*>(&listen_address),
                sizeof(listen_address)) == 0);
    assert(listen(listener.value, 1) == 0);
    const auto server_port = local_port(listener.value);

    SocketGuard client{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    assert(client.value != INVALID_SOCKET);
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(server_port);
    assert(connect(client.value, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 0);
    const auto client_port = local_port(client.value);

    SocketGuard accepted{accept(listener.value, nullptr, nullptr)};
    assert(accepted.value != INVALID_SOCKET);

    shutdown(client.value, SD_BOTH);
    closesocket(client.value);
    client.value = INVALID_SOCKET;
    shutdown(accepted.value, SD_BOTH);
    closesocket(accepted.value);
    accepted.value = INVALID_SOCKET;

    bool saw_connect = false;
    bool saw_accept = false;
    bool saw_close = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline &&
           !(saw_connect && saw_accept && saw_close)) {
        for (const auto& event : lifecycle->poll(std::chrono::milliseconds(250))) {
            if (!event.process.agent_visible.tgid ||
                *event.process.agent_visible.tgid != static_cast<std::int64_t>(GetCurrentProcessId()) ||
                !event.local || !event.remote || !event.local->port || !event.remote->port) {
                continue;
            }
            const bool client_tuple = event.local->address == "127.0.0.1" &&
                *event.local->port == client_port && event.remote->address == "127.0.0.1" &&
                *event.remote->port == server_port;
            const bool server_tuple = event.local->address == "127.0.0.1" &&
                *event.local->port == server_port && event.remote->address == "127.0.0.1" &&
                *event.remote->port == client_port;
            if (event.type == neta::ConnectionLifecycleEventType::Connect && client_tuple) {
                saw_connect = true;
            } else if (event.type == neta::ConnectionLifecycleEventType::Accept && server_tuple) {
                saw_accept = true;
            } else if (event.type == neta::ConnectionLifecycleEventType::Close &&
                       (client_tuple || server_tuple)) {
                saw_close = true;
            }
        }
    }

    assert(saw_connect);
    assert(saw_accept);
    assert(saw_close);
    const auto health = lifecycle->health();
    assert(health.dropped_events.has_value());
    std::cout << "ETW loopback lifecycle OK; dropped=" << *health.dropped_events << '\n';
}

} // namespace

int main() {
    verify_direction_semantics();
    verify_reconciliation_tracker();

    const auto capabilities = neta::platform::capabilities();
    assert(capabilities.connection_discovery);
    assert(capabilities.process_attribution);
    assert(capabilities.route_observation);
    assert(capabilities.lifecycle_source == "windows:etw-tcpip");
    if (capabilities.connection_lifecycle_events) {
        assert(capabilities.lifecycle_connect_events);
        assert(capabilities.lifecycle_accept_events);
        assert(capabilities.lifecycle_close_events);
        assert(capabilities.exact_lifecycle_direction);
        assert(capabilities.lifecycle_drop_counter);
        assert(capabilities.lifecycle_dropped_events.has_value());
    } else {
        assert(!capabilities.lifecycle_unavailable_reason.empty());
    }
    assert(!capabilities.application_name_resolution_events);
    assert(!capabilities.application_tls_session_events);

    const auto host = neta::platform::host_environment();
    assert(host.os == "Windows");

    auto observer = neta::platform::make_connection_observer();
    const auto sockets = observer->snapshot();

    auto resolver = neta::platform::make_process_resolver();
    for (const auto& socket : sockets) {
        if (!socket.owning_pid) continue;
        const auto process = resolver->resolve(socket);
        if (process) {
            assert(process->pid == *socket.owning_pid);
            break;
        }
    }

    auto route = neta::platform::make_route_observer();
    const auto loopback = route->route_to("127.0.0.1");
    assert(loopback.has_value());
    assert(loopback->interface_index != 0);

    verify_real_etw_lifecycle();

    std::cout << "Windows platform W3 reconciliation OK; sockets=" << sockets.size()
              << ", lifecycle=" << (capabilities.connection_lifecycle_events ? "ETW" : "unavailable")
              << '\n';
    return 0;
}
