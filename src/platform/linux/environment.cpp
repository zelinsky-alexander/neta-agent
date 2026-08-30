#include "neta/platform.hpp"

#include <sys/stat.h>
#include <sys/utsname.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <string>

namespace neta::platform {
namespace {
std::string read_first_line(const char* path) {
    std::ifstream in(path);
    std::string line;
    std::getline(in, line);
    return line;
}
}

HostEnvironment host_environment() {
    HostEnvironment result;
    result.boot_id = read_first_line("/proc/sys/kernel/random/boot_id");
    utsname info{};
    if (uname(&info) == 0) result.kernel_release = info.release;

    auto version = read_first_line("/proc/version");
    std::transform(version.begin(), version.end(), version.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    result.is_wsl = version.find("microsoft") != std::string::npos ||
                    version.find("wsl") != std::string::npos;

    struct stat st{};
    if (stat("/proc/self/ns/net", &st) == 0) result.network_namespace_inode = st.st_ino;
    return result;
}

PlatformCapabilities capabilities() {
    PlatformCapabilities c;
    c.connection_discovery = true;
    c.process_attribution = true;
    c.tcp_rtt = true;
    c.tcp_rtt_variance = true;
    c.tcp_retransmissions = true;
    c.tcp_cwnd = true;
    c.route_observation = true;

    const auto lifecycle = make_lifecycle_observer();
    const auto& lifecycle_capability = lifecycle->capability();
    c.connection_lifecycle_events = lifecycle_capability.available();
    c.ebpf_connect_events = lifecycle_capability.connect_events;
    c.ebpf_accept_events = lifecycle_capability.accept_events;
    c.ebpf_close_events = lifecycle_capability.close_events;
    c.exact_lifecycle_direction = lifecycle_capability.connect_events &&
                                  lifecycle_capability.accept_events;
    c.lifecycle_drop_counter = lifecycle_capability.drop_counter;
    c.lifecycle_dropped_events = lifecycle->health().dropped_events;
    c.btf_core_runtime = lifecycle_capability.btf_core_runtime;
    c.ebpf_built_in = lifecycle_capability.built_in;
    c.lifecycle_unavailable_reason = lifecycle_capability.unavailable_reason;

    const auto name_resolution = make_name_resolution_observer();
    const auto& name_capability = name_resolution->capability();
    c.application_name_resolution_events = name_capability.available();
    c.name_resolution_drop_counter = name_capability.drop_counter;
    c.name_resolution_dropped_events = name_resolution->health().dropped_events;
    c.name_resolution_source = name_capability.source;
    c.name_resolution_unavailable_reason = name_capability.unavailable_reason;

    // The glibc collector observes an exact application resolver API event. It does not prove
    // that a network DNS transaction occurred because NSS/cache/hosts may satisfy getaddrinfo().
    c.exact_dns_observation = false;
    c.exact_tls_observation = false;
    return c;
}

} // namespace neta::platform
