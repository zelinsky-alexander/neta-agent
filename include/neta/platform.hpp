#pragma once

#include "neta/lifecycle.hpp"
#include "neta/model.hpp"
#include "neta/name_resolution.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace neta::platform {

struct PlatformCapabilities {
    bool connection_discovery{false};
    bool process_attribution{false};
    bool tcp_rtt{false};
    bool tcp_rtt_variance{false};
    bool tcp_retransmissions{false};
    bool tcp_cwnd{false};
    bool route_observation{false};
    bool connection_lifecycle_events{false};
    bool ebpf_connect_events{false};
    bool ebpf_accept_events{false};
    bool ebpf_close_events{false};
    bool exact_lifecycle_direction{false};
    bool lifecycle_drop_counter{false};
    std::optional<std::uint64_t> lifecycle_dropped_events;
    bool btf_core_runtime{false};
    bool ebpf_built_in{false};
    std::string lifecycle_unavailable_reason;
    bool application_name_resolution_events{false};
    bool name_resolution_drop_counter{false};
    std::optional<std::uint64_t> name_resolution_dropped_events;
    std::string name_resolution_source;
    std::string name_resolution_unavailable_reason;
    bool exact_dns_observation{false};
    bool exact_tls_observation{false};
};

class ConnectionObserver {
public:
    virtual ~ConnectionObserver() = default;
    virtual std::vector<SocketObservation> snapshot() = 0;
};

class ProcessResolver {
public:
    virtual ~ProcessResolver() = default;
    virtual std::optional<ProcessIdentity> resolve(std::uint64_t socket_inode) = 0;
};

class RouteObserver {
public:
    virtual ~RouteObserver() = default;
    virtual std::optional<RouteObservation> route_to(const std::string& destination) = 0;
};

HostEnvironment host_environment();
PlatformCapabilities capabilities();

std::unique_ptr<ConnectionObserver> make_connection_observer();
std::unique_ptr<LifecycleObserver> make_lifecycle_observer();
std::unique_ptr<NameResolutionObserver> make_name_resolution_observer();
std::unique_ptr<ProcessResolver> make_process_resolver();
std::unique_ptr<RouteObserver> make_route_observer();

} // namespace neta::platform
