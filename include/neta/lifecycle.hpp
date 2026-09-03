#pragma once

#include "neta/model.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neta {

enum class ConnectionLifecycleEventType { Connect, Accept, Close };
enum class NetworkAddressFamily { Unknown, IPv4, IPv6 };
enum class TransportProtocol { Unknown, Tcp };
enum class LifecycleProvenance { EbpfCore, WindowsEtw, DeterministicTest };

struct NetworkEndpoint {
    std::string address;
    std::optional<std::uint16_t> port;
};

struct LifecycleProcessIds {
    std::optional<std::int64_t> pid;
    std::optional<std::int64_t> tgid;
};

struct ProcessNamespaceIdentity {
    std::uint64_t device{0};
    std::uint64_t inode{0};
};

struct LifecycleProcessContext {
    // Only this identity is suitable for process lookup by the observing agent.
    LifecycleProcessIds agent_visible;
    // Kernel-provider process identity. On Linux this may be in a different PID namespace;
    // on Windows ETW and agent-visible PIDs are the same host PID namespace.
    LifecycleProcessIds kernel;
    std::optional<ProcessNamespaceIdentity> agent_pid_namespace;
    std::optional<std::uint32_t> uid;
    std::optional<std::uint64_t> start_ticks;
    std::optional<std::string> comm;
};

struct ConnectionLifecycleEvent {
    ConnectionLifecycleEventType type{ConnectionLifecycleEventType::Connect};
    std::uint64_t timestamp_ns{0};
    LifecycleProvenance provenance{LifecycleProvenance::EbpfCore};
    LifecycleProcessContext process;
    std::optional<std::uint64_t> network_namespace_inode;
    NetworkAddressFamily address_family{NetworkAddressFamily::Unknown};
    TransportProtocol protocol{TransportProtocol::Unknown};
    TcpEndpointKind endpoint_kind{TcpEndpointKind::Unknown};
    std::optional<NetworkEndpoint> local;
    std::optional<NetworkEndpoint> remote;
    std::optional<std::uint64_t> socket_cookie;
    // Platform-native connection identity when the collector exposes one. This is not a
    // Linux socket cookie and must not be persisted or described as one.
    std::optional<std::uint64_t> platform_connection_id;
    std::optional<std::uint8_t> tcp_state;
};

struct LifecycleCapability {
    bool built_in{false};
    bool btf_core_runtime{false};
    bool connect_events{false};
    bool accept_events{false};
    bool close_events{false};
    bool drop_counter{false};
    std::string source;
    std::string unavailable_reason;

    [[nodiscard]] bool available() const noexcept {
        return connect_events && accept_events && close_events;
    }
    [[nodiscard]] bool outbound_available() const noexcept {
        return connect_events && close_events;
    }
};

struct LifecycleHealth {
    std::optional<std::uint64_t> dropped_events;

    [[nodiscard]] bool evidence_may_be_incomplete() const noexcept {
        return dropped_events && *dropped_events != 0;
    }
};

class LifecycleObserver {
public:
    virtual ~LifecycleObserver() = default;
    [[nodiscard]] virtual const LifecycleCapability& capability() const noexcept = 0;
    [[nodiscard]] virtual LifecycleHealth health() const = 0;
    virtual std::vector<ConnectionLifecycleEvent> poll(std::chrono::milliseconds timeout) = 0;
};

std::string to_string(ConnectionLifecycleEventType value);
std::string to_string(LifecycleProvenance value);

} // namespace neta
