#include "neta/platform.hpp"

#include <cassert>
#include <iostream>

int main() {
    const auto capabilities = neta::platform::capabilities();
    assert(capabilities.connection_discovery);
    assert(capabilities.process_attribution);
    assert(capabilities.route_observation);
    assert(!capabilities.connection_lifecycle_events);
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

    std::cout << "Windows platform foundation OK; sockets=" << sockets.size() << '\n';
    return 0;
}
