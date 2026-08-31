#include "name_resolution_decoder.hpp"
#include "name_resolution_wire.h"

#include <arpa/inet.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <span>

namespace {

std::span<const std::byte> bytes_of(const neta_name_resolution_wire_event& wire) {
    return {reinterpret_cast<const std::byte*>(&wire), sizeof(wire)};
}

neta_name_resolution_wire_event event() {
    neta_name_resolution_wire_event wire{};
    wire.version = NETA_NAME_RESOLUTION_WIRE_VERSION;
    wire.size = sizeof(wire);
    wire.availability = NETA_NAME_HAS_KERNEL_PID | NETA_NAME_HAS_AGENT_PID |
                        NETA_NAME_HAS_UID | NETA_NAME_HAS_START_TIME |
                        NETA_NAME_HAS_NETNS | NETA_NAME_HAS_CANONICAL_NAME;
    wire.result_code = 0;
    wire.address_count = 2;
    wire.kernel_pid = 42;
    wire.kernel_tgid = 42;
    wire.agent_pid = 42;
    wire.agent_tgid = 42;
    wire.uid = 1000;
    wire.started_ns = 1'000;
    wire.completed_ns = 2'000;
    wire.process_start_time_ns = 3'000'000'000ULL;
    wire.network_namespace_inode = 77;
    std::strncpy(wire.query_name, "api.example.test", sizeof(wire.query_name) - 1);
    std::strncpy(wire.canonical_name, "edge.example.test", sizeof(wire.canonical_name) - 1);
    std::strncpy(wire.comm, "resolver-test", sizeof(wire.comm) - 1);
    wire.addresses[0].family = AF_INET;
    wire.addresses[1].family = AF_INET6;
    assert(::inet_pton(AF_INET, "203.0.113.20", wire.addresses[0].address) == 1);
    assert(::inet_pton(AF_INET6, "2001:db8::20", wire.addresses[1].address) == 1);
    return wire;
}

void complete_event_decodes_exactly() {
    const auto wire = event();
    const auto decoded = neta::platform::linux_ebpf::decode_name_resolution_event(bytes_of(wire));
    assert(decoded.observation);
    const auto& observation = *decoded.observation;
    assert(observation.started_ns == 1'000);
    assert(observation.completed_ns == 2'000);
    assert(observation.query_kind == neta::NameResolutionQueryKind::Forward);
    assert(observation.mechanism == neta::NameResolutionMechanism::ApplicationResolverApi);
    assert(observation.query_name == "api.example.test");
    assert(observation.canonical_name == "edge.example.test");
    assert(observation.result_code == 0);
    assert(observation.process.agent_visible.tgid == 42);
    assert(observation.network_namespace_inode == 77);
    assert(observation.addresses.size() == 2);
    assert(observation.addresses[0].address == "203.0.113.20");
    assert(observation.addresses[1].address == "2001:db8::20");
    assert(observation.fidelity == neta::EvidenceFidelity::Exact);
    assert(observation.source == "glibc:getaddrinfo");
}

void partial_event_is_not_exact() {
    auto wire = event();
    wire.availability |= NETA_NAME_PARTIAL;
    const auto decoded = neta::platform::linux_ebpf::decode_name_resolution_event(bytes_of(wire));
    assert(decoded.observation);
    assert(decoded.observation->fidelity == neta::EvidenceFidelity::Supporting);
}

void malformed_event_is_rejected() {
    auto wire = event();
    wire.version = 99;
    auto decoded = neta::platform::linux_ebpf::decode_name_resolution_event(bytes_of(wire));
    assert(!decoded.observation);

    wire = event();
    const auto truncated = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(&wire), sizeof(wire) - 1);
    decoded = neta::platform::linux_ebpf::decode_name_resolution_event(truncated);
    assert(!decoded.observation);
}

} // namespace

int main() {
    complete_event_decodes_exactly();
    partial_event_is_not_exact();
    malformed_event_is_rejected();
    std::cout << "Name-resolution decoder tests passed\n";
}
