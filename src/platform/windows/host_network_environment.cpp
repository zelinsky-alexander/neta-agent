#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <chrono>
#include <cstdint>
#include <string>

namespace neta::platform {
namespace {

std::uint64_t wall_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                            out.data(), needed, nullptr, nullptr) <= 0) return {};
    return out;
}

std::string hostname() {
    wchar_t buffer[256]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (GetComputerNameW(buffer, &size) == FALSE) return {};
    return utf8(std::wstring(buffer, size));
}

std::string architecture() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: return "x86_64";
        case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
        case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
        default: return "unknown";
    }
}

} // namespace

HostNetworkEnvironmentEvidence capture_host_network_environment(
    const ConnectionSummary& connection, const RouteObservation& route) {
    HostNetworkEnvironmentEvidence evidence;
    evidence.captured_at_ns = wall_now_ns();
    evidence.fidelity = EvidenceFidelity::StronglyCorrelated;
    evidence.source = "windows:host-network-environment";

    const auto host = host_environment();
    evidence.hostname = hostname();
    evidence.boot_id = host.boot_id;
    evidence.os = "Windows";
    evidence.kernel_release = host.kernel_release;
    evidence.architecture = architecture();
    evidence.environment_class = "native-windows";

    if (route.interface_index != 0) evidence.interface_index = route.interface_index;
    evidence.interface_name = route.interface_name;
    evidence.local_address = connection.local_ip;
    evidence.gateway = route.gateway;
    evidence.preferred_source = route.source;
    evidence.route_table = route.table;
    evidence.route_metric = route.metric;
    evidence.environment_fingerprint = host_network_environment_fingerprint(evidence);
    return evidence;
}

} // namespace neta::platform
