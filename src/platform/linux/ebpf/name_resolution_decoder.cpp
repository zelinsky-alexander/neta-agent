#include "name_resolution_decoder.hpp"

#include "name_resolution_wire.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace neta::platform::linux_ebpf {
namespace {

std::optional<std::uint64_t> start_ticks_from_ns(std::uint64_t nanoseconds) {
    const long ticks_per_second = ::sysconf(_SC_CLK_TCK);
    if (ticks_per_second <= 0) return std::nullopt;
    constexpr std::uint64_t billion = 1'000'000'000ULL;
    const auto ticks = static_cast<std::uint64_t>(ticks_per_second);
    return (nanoseconds / billion) * ticks +
           ((nanoseconds % billion) * ticks) / billion;
}

std::optional<std::string> decode_address(const neta_name_resolution_wire_address& wire) {
    std::array<char, INET6_ADDRSTRLEN> output{};
    const int family = wire.family == AF_INET ? AF_INET :
                       wire.family == AF_INET6 ? AF_INET6 : 0;
    if (family == 0 || !::inet_ntop(family, wire.address, output.data(), output.size())) {
        return std::nullopt;
    }
    return std::string(output.data());
}

} // namespace

NameResolutionDecodeResult decode_name_resolution_event(std::span<const std::byte> bytes) {
    if (bytes.size() < sizeof(neta_name_resolution_wire_event)) {
        return {std::nullopt, "truncated name-resolution event"};
    }

    neta_name_resolution_wire_event wire{};
    std::memcpy(&wire, bytes.data(), sizeof(wire));
    if (wire.version != NETA_NAME_RESOLUTION_WIRE_VERSION || wire.size != sizeof(wire)) {
        return {std::nullopt, "unsupported name-resolution event version or size"};
    }

    const auto query_length = ::strnlen(wire.query_name, sizeof(wire.query_name));
    if (query_length == 0) return {std::nullopt, "name-resolution event has no query name"};

    NameResolutionObservation observation;
    observation.started_ns = wire.started_ns;
    observation.completed_ns = wire.completed_ns;
    observation.query_kind = NameResolutionQueryKind::Forward;
    observation.mechanism = NameResolutionMechanism::ApplicationResolverApi;
    observation.query_name = std::string(wire.query_name, query_length);
    observation.result_code = wire.result_code;
    observation.source = "glibc:getaddrinfo";
    observation.fidelity = (wire.availability & NETA_NAME_PARTIAL) != 0U
        ? EvidenceFidelity::Supporting : EvidenceFidelity::Exact;

    if ((wire.availability & NETA_NAME_HAS_CANONICAL_NAME) != 0U) {
        const auto canonical_length = ::strnlen(wire.canonical_name, sizeof(wire.canonical_name));
        if (canonical_length != 0) {
            observation.canonical_name = std::string(wire.canonical_name, canonical_length);
        }
    }
    if ((wire.availability & NETA_NAME_HAS_KERNEL_PID) != 0U) {
        observation.process.kernel.pid = static_cast<std::int64_t>(wire.kernel_pid);
        observation.process.kernel.tgid = static_cast<std::int64_t>(wire.kernel_tgid);
    }
    if ((wire.availability & NETA_NAME_HAS_AGENT_PID) != 0U) {
        observation.process.agent_visible.pid = static_cast<std::int64_t>(wire.agent_pid);
        observation.process.agent_visible.tgid = static_cast<std::int64_t>(wire.agent_tgid);
    }
    if ((wire.availability & NETA_NAME_HAS_AGENT_PID_NAMESPACE) != 0U) {
        observation.process.agent_pid_namespace = ProcessNamespaceIdentity{
            wire.agent_pid_namespace_device, wire.agent_pid_namespace_inode};
    }
    if ((wire.availability & (NETA_NAME_HAS_KERNEL_PID | NETA_NAME_HAS_AGENT_PID)) != 0U) {
        const auto comm_length = ::strnlen(wire.comm, sizeof(wire.comm));
        observation.process.comm = std::string(wire.comm, comm_length);
    }
    if ((wire.availability & NETA_NAME_HAS_UID) != 0U) observation.process.uid = wire.uid;
    if ((wire.availability & NETA_NAME_HAS_START_TIME) != 0U) {
        observation.process.start_ticks = start_ticks_from_ns(wire.process_start_time_ns);
    }
    if ((wire.availability & NETA_NAME_HAS_NETNS) != 0U) {
        observation.network_namespace_inode = wire.network_namespace_inode;
    }

    const auto address_count = std::min<std::size_t>(wire.address_count,
        NETA_NAME_RESOLUTION_MAX_ADDRESSES);
    for (std::size_t index = 0; index < address_count; ++index) {
        const auto address = decode_address(wire.addresses[index]);
        if (!address) continue;
        observation.addresses.push_back({
            wire.addresses[index].family == AF_INET ? NetworkAddressFamily::IPv4 :
            wire.addresses[index].family == AF_INET6 ? NetworkAddressFamily::IPv6 :
                                                       NetworkAddressFamily::Unknown,
            *address});
    }
    return {observation, {}};
}

} // namespace neta::platform::linux_ebpf
