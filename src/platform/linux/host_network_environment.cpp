#include "neta/platform.hpp"

#include "neta/crypto.hpp"

#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>

namespace neta::platform {
namespace {

std::string read_first_line(const std::string& path) {
    std::ifstream in(path);
    std::string line;
    std::getline(in, line);
    return line;
}

std::optional<std::uint32_t> read_u32(const std::string& path) {
    std::ifstream in(path);
    std::uint64_t value = 0;
    if (!(in >> value) || value > 0xffffffffULL) return std::nullopt;
    return static_cast<std::uint32_t>(value);
}

std::uint64_t wall_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string detect_environment_class() {
    auto version = read_first_line("/proc/version");
    std::transform(version.begin(), version.end(), version.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (version.find("microsoft") != std::string::npos ||
        version.find("wsl") != std::string::npos) {
        return "WSL";
    }
    if (!read_first_line("/sys/hypervisor/uuid").empty()) return "VIRTUALIZED";
    return "LINUX_HOST";
}

std::string host_id() {
    const auto machine_id = read_first_line("/etc/machine-id");
    if (machine_id.empty()) return {};
    return sha256_hex("neta-host-id-v1|" + machine_id);
}

} // namespace

HostNetworkEnvironmentEvidence capture_host_network_environment(
    const ConnectionSummary& connection, const RouteObservation& route) {
    HostNetworkEnvironmentEvidence evidence;
    evidence.captured_at_ns = wall_now_ns();
    evidence.fidelity = EvidenceFidelity::StronglyCorrelated;
    evidence.host_id = host_id();
    evidence.boot_id = read_first_line("/proc/sys/kernel/random/boot_id");
    evidence.environment_class = detect_environment_class();
    evidence.network_namespace_inode = connection.network_namespace_inode;
    evidence.interface_index = route.interface_index == 0
        ? std::nullopt : std::optional<std::uint32_t>{route.interface_index};
    evidence.interface_name = route.interface_name;
    evidence.local_address = connection.local_ip;
    evidence.gateway = route.gateway;
    evidence.preferred_source = route.source;
    evidence.route_table = route.table;
    evidence.route_metric = route.metric;

    char hostname[256]{};
    if (::gethostname(hostname, sizeof(hostname) - 1) == 0) evidence.hostname = hostname;

    utsname info{};
    if (::uname(&info) == 0) {
        evidence.kernel_release = info.release;
        evidence.architecture = info.machine;
    }

    if (!evidence.interface_name.empty()) {
        const auto base = std::string("/sys/class/net/") + evidence.interface_name + "/";
        evidence.interface_mac = read_first_line(base + "address");
        evidence.interface_mtu = read_u32(base + "mtu");
    }

    std::ostringstream canonical;
    canonical << "neta-env-v1|" << evidence.host_id << '|' << evidence.boot_id << '|';
    if (evidence.network_namespace_inode) canonical << *evidence.network_namespace_inode;
    canonical << '|';
    if (evidence.interface_index) canonical << *evidence.interface_index;
    canonical << '|' << evidence.interface_name << '|' << evidence.local_address << '|'
              << evidence.gateway << '|' << evidence.preferred_source << '|';
    if (evidence.route_table) canonical << *evidence.route_table;
    canonical << '|';
    if (evidence.route_metric) canonical << *evidence.route_metric;
    evidence.environment_fingerprint = sha256_hex(canonical.str());
    return evidence;
}

} // namespace neta::platform
