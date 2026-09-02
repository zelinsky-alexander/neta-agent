#include "neta/connection_admission_policy.hpp"
#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cassert>
#include <chrono>
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

    std::cout << "Windows platform W3 foundation OK; sockets=" << sockets.size()
              << ", lifecycle=" << (capabilities.connection_lifecycle_events ? "ETW" : "unavailable")
              << '\n';
    return 0;
}
