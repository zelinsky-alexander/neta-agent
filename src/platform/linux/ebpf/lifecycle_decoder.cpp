#include "lifecycle_decoder.hpp"

#include "lifecycle_wire.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <limits>

namespace neta::platform::linux_ebpf {
namespace {

std::optional<std::string> decode_address(std::uint8_t family, const __u8* bytes) {
    std::array<char, INET6_ADDRSTRLEN> output{};
    const int native_family = family == AF_INET ? AF_INET : family == AF_INET6 ? AF_INET6 : 0;
    if (native_family == 0 || !::inet_ntop(native_family, bytes, output.data(), output.size())) {
        return std::nullopt;
    }
    return std::string(output.data());
}

std::optional<std::uint64_t> start_ticks_from_ns(std::uint64_t nanoseconds) {
    const long ticks_per_second = ::sysconf(_SC_CLK_TCK);
    if (ticks_per_second <= 0) return std::nullopt;
    constexpr std::uint64_t billion = 1'000'000'000ULL;
    const auto ticks = static_cast<std::uint64_t>(ticks_per_second);
    return (nanoseconds / billion) * ticks +
           ((nanoseconds % billion) * ticks) / billion;
}

} // namespace

DecodeResult decode_lifecycle_event(std::span<const std::byte> bytes) {
    if (bytes.size() < sizeof(neta_lifecycle_wire_event)) {
        return {std::nullopt, "truncated lifecycle event"};
    }
    neta_lifecycle_wire_event wire{};
    std::memcpy(&wire, bytes.data(), sizeof(wire));
    if (wire.version != NETA_LIFECYCLE_WIRE_VERSION || wire.size != sizeof(wire)) {
        return {std::nullopt, "unsupported lifecycle event version or size"};
    }

    ConnectionLifecycleEvent event;
    switch (wire.type) {
        case NETA_LIFECYCLE_CONNECT: event.type = ConnectionLifecycleEventType::Connect; break;
        case NETA_LIFECYCLE_ACCEPT: event.type = ConnectionLifecycleEventType::Accept; break;
        case NETA_LIFECYCLE_CLOSE: event.type = ConnectionLifecycleEventType::Close; break;
        default: return {std::nullopt, "unknown lifecycle event type"};
    }
    event.timestamp_ns = wire.timestamp_ns;
    event.provenance = LifecycleProvenance::EbpfCore;
    event.address_family = wire.family == AF_INET ? NetworkAddressFamily::IPv4 :
                           wire.family == AF_INET6 ? NetworkAddressFamily::IPv6 :
                                                   NetworkAddressFamily::Unknown;
    event.protocol = wire.protocol == IPPROTO_TCP ? TransportProtocol::Tcp :
                                                   TransportProtocol::Unknown;
    event.tcp_state = wire.tcp_state;

    if ((wire.availability & NETA_HAS_KERNEL_PID) != 0U) {
        event.process.kernel.pid = static_cast<std::int64_t>(wire.kernel_pid);
        event.process.kernel.tgid = static_cast<std::int64_t>(wire.kernel_tgid);
    }
    if ((wire.availability & NETA_HAS_AGENT_PID) != 0U) {
        event.process.agent_visible.pid = static_cast<std::int64_t>(wire.agent_pid);
        event.process.agent_visible.tgid = static_cast<std::int64_t>(wire.agent_tgid);
    }
    if ((wire.availability & NETA_HAS_AGENT_PID_NAMESPACE) != 0U) {
        event.process.agent_pid_namespace = ProcessNamespaceIdentity{
            wire.agent_pid_namespace_device, wire.agent_pid_namespace_inode};
    }
    if ((wire.availability & (NETA_HAS_KERNEL_PID | NETA_HAS_AGENT_PID)) != 0U) {
        const auto length = ::strnlen(wire.comm, sizeof(wire.comm));
        event.process.comm = std::string(wire.comm, length);
    }
    if ((wire.availability & NETA_HAS_UID) != 0U) event.process.uid = wire.uid;
    if ((wire.availability & NETA_HAS_COOKIE) != 0U && wire.socket_cookie != 0) {
        event.socket_cookie = wire.socket_cookie;
    }
    if ((wire.availability & NETA_HAS_NETNS) != 0U) {
        event.network_namespace_inode = wire.network_namespace_inode;
    }
    if ((wire.availability & NETA_HAS_START_TIME) != 0U) {
        event.process.start_ticks = start_ticks_from_ns(wire.process_start_time_ns);
    }

    const auto local_address = decode_address(wire.family, wire.local_address);
    if ((wire.availability & NETA_HAS_LOCAL) != 0U && local_address) {
        event.local = NetworkEndpoint{*local_address,
                                      wire.local_port == 0 ? std::nullopt :
                                      std::optional<std::uint16_t>{wire.local_port}};
    }
    const auto remote_address = decode_address(wire.family, wire.remote_address);
    if ((wire.availability & NETA_HAS_REMOTE) != 0U && remote_address) {
        event.remote = NetworkEndpoint{*remote_address,
                                       wire.remote_port == 0 ? std::nullopt :
                                       std::optional<std::uint16_t>{wire.remote_port}};
    }
    return {event, {}};
}

} // namespace neta::platform::linux_ebpf
