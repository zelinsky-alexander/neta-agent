#include "neta/lifecycle.hpp"
#include "neta/process_exec.hpp"
#include "../src/platform/windows/sensor_broker_process_registry.hpp"
#include "../src/platform/windows/sensor_broker_protocol.hpp"
#include "../src/platform/windows/sensor_broker_router.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <string>

namespace {

neta::ProcessExecEvent start_event(std::int64_t pid, std::int64_t parent) {
    neta::ProcessExecEvent event;
    event.type = neta::ProcessExecEventType::Start;
    event.pid = pid;
    event.tgid = pid;
    event.parent_pid = parent;
    event.parent_tgid = parent;
    event.platform_process_key = static_cast<std::uint64_t>(pid) * 100U;
    event.executable_path = "C:\\Windows\\System32\\cmd.exe";
    event.command_line = "cmd.exe /c echo NETA";
    event.comm = "cmd.exe";
    return event;
}

void verify_process_tree_attribution() {
    neta::windows_sensor_broker::EndpointProcessRegistry registry;
    registry.register_endpoint("win-0001", 1001);
    registry.register_endpoint("win-0002", 2001);

    const auto first = registry.observe(start_event(2002, 2001));
    assert(first && *first == "win-0002");
    const auto second = registry.observe(start_event(2003, 2002));
    assert(second && *second == "win-0002");
    assert(registry.endpoint_owns("win-0002", 2003));
    assert(!registry.endpoint_owns("win-0001", 2003));

    auto exit = start_event(2003, 2002);
    exit.type = neta::ProcessExecEventType::Exit;
    const auto exited = registry.observe(exit);
    assert(exited && *exited == "win-0002");
    assert(registry.endpoint_count() == 2);
}

void verify_protocol_round_trip() {
    neta::ConnectionLifecycleEvent lifecycle;
    lifecycle.type = neta::ConnectionLifecycleEventType::Connect;
    lifecycle.provenance = neta::LifecycleProvenance::WindowsEtw;
    lifecycle.timestamp_ns = 123456;
    lifecycle.process.kernel.pid = 2002;
    lifecycle.process.kernel.tgid = 2002;
    lifecycle.process.agent_visible = lifecycle.process.kernel;
    lifecycle.process.comm = "curl.exe";
    lifecycle.address_family = neta::NetworkAddressFamily::IPv4;
    lifecycle.protocol = neta::TransportProtocol::Tcp;
    lifecycle.endpoint_kind = neta::TcpEndpointKind::Connection;
    lifecycle.local = neta::NetworkEndpoint{"10.70.0.22", 50000};
    lifecycle.remote = neta::NetworkEndpoint{"10.70.0.1", 18080};
    lifecycle.platform_connection_id = 77;

    const auto lifecycle_frame = neta::windows_sensor_broker::protocol::encode_lifecycle(lifecycle, 1);
    const auto decoded_lifecycle = neta::windows_sensor_broker::protocol::decode_lifecycle(lifecycle_frame);
    assert(decoded_lifecycle);
    assert(decoded_lifecycle->process.kernel.pid == 2002);
    assert(decoded_lifecycle->remote && decoded_lifecycle->remote->port == 18080);

    auto process = start_event(3002, 3001);
    process.user_identity = "S-1-5-18";
    process.integrity_level = "system";
    process.elevated = true;
    const auto process_frame = neta::windows_sensor_broker::protocol::encode_process_exec(process, 2);
    const auto decoded_process = neta::windows_sensor_broker::protocol::decode_process_exec(process_frame);
    assert(decoded_process);
    assert(decoded_process->pid == 3002);
    assert(decoded_process->parent_pid == 3001);
    assert(decoded_process->user_identity == "S-1-5-18");
    assert(decoded_process->elevated && *decoded_process->elevated);

    const auto registration_frame = neta::windows_sensor_broker::protocol::encode_registration({"win-0002"});
    const auto registration = neta::windows_sensor_broker::protocol::decode_registration(registration_frame);
    assert(registration && registration->endpoint_slot == "win-0002");
}

void verify_router_isolation_and_drop_accounting() {
    using namespace std::chrono_literals;
    neta::windows_sensor_broker::BrokerEventRouter router(1);
    router.register_endpoint("win-0001");
    router.register_endpoint("win-0002");

    auto first = start_event(4001, 4000);
    auto second = start_event(4002, 4000);
    assert(router.route_process_exec("win-0002", first, 1));
    assert(router.route_process_exec("win-0002", second, 2));
    assert(router.dropped("win-0002") == 1);
    assert(!router.take("win-0001", 0ms));

    const auto frame = router.take("win-0002", 0ms);
    assert(frame);
    const auto decoded = neta::windows_sensor_broker::protocol::decode_process_exec(*frame);
    assert(decoded && decoded->pid == 4002);

    router.note_unroutable();
    assert(router.unroutable() == 1);
}

}  // namespace

int main() {
    verify_process_tree_attribution();
    verify_protocol_round_trip();
    verify_router_isolation_and_drop_accounting();
    std::cout << "Windows sensor-broker deterministic tests passed\n";
    return 0;
}
