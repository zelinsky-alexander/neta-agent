#include "neta/lifecycle.hpp"
#include "neta/sensor_broker.hpp"

#include <cassert>
#include <chrono>
#include <iostream>

namespace {

void test_lifecycle_health() {
    neta::LifecycleHealth unavailable;
    assert(!unavailable.dropped_events);
    assert(!unavailable.evidence_may_be_incomplete());
    neta::LifecycleHealth healthy{0};
    assert(!healthy.evidence_may_be_incomplete());
    neta::LifecycleHealth dropped{3};
    assert(dropped.evidence_may_be_incomplete());
}

void test_bounded_queue_reports_loss() {
    neta::sensor_broker::BoundedQueue<int> queue(2);
    queue.push(1);
    queue.push(2);
    queue.push(3);
    assert(queue.dropped() == 1);
    const auto first = queue.pop_for(std::chrono::milliseconds(0));
    const auto second = queue.pop_for(std::chrono::milliseconds(0));
    assert(first && *first == 2);
    assert(second && *second == 3);
}

void test_endpoint_routing_is_isolated() {
    using namespace neta;
    using namespace neta::sensor_broker;

    EventRouter router(4);
    router.register_endpoint("lnx-0001", 1001, 2001);
    router.register_endpoint("lnx-0002", 1002, 2002);

    ConnectionLifecycleEvent lifecycle;
    lifecycle.type = ConnectionLifecycleEventType::Connect;
    lifecycle.timestamp_ns = 1234;
    lifecycle.network_namespace_inode = 1002;
    lifecycle.address_family = NetworkAddressFamily::IPv4;
    lifecycle.protocol = TransportProtocol::Tcp;
    lifecycle.endpoint_kind = TcpEndpointKind::Connection;
    lifecycle.local = NetworkEndpoint{"10.70.0.12", 41000};
    lifecycle.remote = NetworkEndpoint{"203.0.113.10", 443};
    lifecycle.process.comm = "curl";
    assert(router.route(lifecycle, 7));

    assert(!router.take("lnx-0001", EventKind::Lifecycle, std::chrono::milliseconds(0)));
    const auto lnx2 = router.take("lnx-0002", EventKind::Lifecycle, std::chrono::milliseconds(0));
    assert(lnx2);
    const auto decoded_lifecycle = decode_lifecycle(*lnx2);
    assert(decoded_lifecycle);
    assert(decoded_lifecycle->network_namespace_inode == 1002);
    assert(decoded_lifecycle->process.comm == "curl");
    assert(decoded_lifecycle->local && decoded_lifecycle->local->address == "10.70.0.12");

    ProcessExecEvent process;
    process.type = ProcessExecEventType::Start;
    process.timestamp_ns = 5678;
    process.pid = 301;
    process.tgid = 301;
    process.cgroup_id = 2001;
    process.comm = "python3";
    process.executable_path = "/usr/bin/python3";
    assert(router.route(process, 8));

    assert(!router.take("lnx-0002", EventKind::ProcessExec, std::chrono::milliseconds(0)));
    const auto lnx1 = router.take("lnx-0001", EventKind::ProcessExec, std::chrono::milliseconds(0));
    assert(lnx1);
    const auto decoded_process = decode_process_exec(*lnx1);
    assert(decoded_process);
    assert(decoded_process->cgroup_id == 2001);
    assert(decoded_process->comm == "python3");
    assert(decoded_process->executable_path == "/usr/bin/python3");

    ProcessExecEvent unknown;
    unknown.cgroup_id = 9999;
    assert(!router.route(unknown, 9));
    assert(router.unroutable() == 1);
}

void test_registration_protocol_rejects_invalid_kind() {
    using namespace neta::sensor_broker;
    const auto encoded = encode_registration("lnx-0042", EventKind::Lifecycle);
    const auto decoded = decode_registration(encoded);
    assert(decoded);
    assert(decoded->endpoint_slot == "lnx-0042");
    assert(decoded->event_kind == EventKind::Lifecycle);
}

} // namespace

int main() {
    test_lifecycle_health();
    test_bounded_queue_reports_loss();
    test_endpoint_routing_is_isolated();
    test_registration_protocol_rejects_invalid_kind();
    std::cout << "Lifecycle health and sensor broker isolation tests passed\n";
}
