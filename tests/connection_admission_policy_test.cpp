#include "neta/connection_admission_policy.hpp"

#include <cassert>
#include <iostream>

namespace {

neta::ConnectionLifecycleEvent event(neta::ConnectionLifecycleEventType type) {
    neta::ConnectionLifecycleEvent result;
    result.type = type;
    result.protocol = neta::TransportProtocol::Tcp;
    result.endpoint_kind = neta::TcpEndpointKind::Connection;
    result.local = neta::NetworkEndpoint{"127.0.0.1", 443};
    result.remote = neta::NetworkEndpoint{"127.0.0.2", 50000};
    result.process.comm = "service";
    return result;
}

} // namespace

int main() {
    using namespace neta;
    AdmissionPolicyConfig config;
    config.mode = ObservationMode::All;
    ConnectionAdmissionPolicy all(config);
    assert(all.evaluate(event(ConnectionLifecycleEventType::Connect)).direction ==
           ConnectionDirection::Outbound);
    assert(all.evaluate(event(ConnectionLifecycleEventType::Accept)).direction ==
           ConnectionDirection::Inbound);

    auto listener = event(ConnectionLifecycleEventType::Accept);
    listener.endpoint_kind = TcpEndpointKind::Listener;
    assert(!all.evaluate(listener).admit);

    config.mode = ObservationMode::Inbound;
    config.filter.local_port = 443;
    config.filter.include_processes.insert("service");
    ConnectionAdmissionPolicy inbound(config);
    assert(inbound.evaluate(event(ConnectionLifecycleEventType::Accept)).admit);
    assert(!inbound.evaluate(event(ConnectionLifecycleEventType::Connect)).admit);
    auto excluded = event(ConnectionLifecycleEventType::Accept);
    excluded.process.comm = "other";
    assert(!inbound.evaluate(excluded).admit);

    config.filter.include_processes.clear();
    config.filter.exclude_processes.insert("service");
    ConnectionAdmissionPolicy exclusion(config);
    assert(!exclusion.evaluate(event(ConnectionLifecycleEventType::Accept)).admit);

    AdmissionPolicyConfig target_config;
    target_config.mode = ObservationMode::Target;
    target_config.target_addresses.insert("127.0.0.2");
    target_config.target_port = 50000;
    ConnectionAdmissionPolicy target(target_config);
    neta::SocketObservation socket;
    socket.endpoint_kind = TcpEndpointKind::Connection;
    socket.local_port = 40000;
    socket.remote_ip = "127.0.0.2";
    socket.remote_port = 50000;
    const auto unknown = target.evaluate_new_socket(socket);
    assert(unknown.admit);
    assert(unknown.direction == ConnectionDirection::Unknown);

    target_config.filter.exclude_processes.insert("blocked");
    ConnectionAdmissionPolicy target_exclusion(target_config);
    assert(!target_exclusion.evaluate_new_socket(socket, "blocked").admit);
    assert(target_exclusion.evaluate_new_socket(socket, "allowed").admit);
    assert(!target_exclusion.evaluate_new_socket(socket).admit);

    std::cout << "Connection admission policy tests passed\n";
}
