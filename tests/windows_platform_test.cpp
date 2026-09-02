#include "neta/connection_admission_policy.hpp"
#include "neta/platform.hpp"

#include <cassert>
#include <iostream>

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

    std::cout << "Windows platform W3 foundation OK; sockets=" << sockets.size()
              << ", lifecycle=" << (capabilities.connection_lifecycle_events ? "ETW" : "unavailable")
              << '\n';
    return 0;
}
