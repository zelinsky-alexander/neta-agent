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
    c.connection_lifecycle_events = false;
    c.exact_dns_observation = false;
    c.exact_tls_observation = false;
    return c;
}

} // namespace neta::platform
