#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "ole32.lib")
#endif

#include <chrono>
#include <memory>
#include <string>

namespace neta::platform {
namespace {

class UnavailableTlsSessionObserver final : public TlsSessionObserver {
public:
    UnavailableTlsSessionObserver() {
        capability_.source = "windows:tls";
        capability_.unavailable_reason = "Windows application TLS collector is not implemented yet";
    }

    const TlsSessionCapability& capability() const noexcept override { return capability_; }
    TlsSessionHealth health() const override { return {}; }
    std::vector<TlsSessionObservation> poll(std::chrono::milliseconds) override { return {}; }

private:
    TlsSessionCapability capability_;
};

std::string native_windows_version() {
    using RtlGetVersionFn = LONG (WINAPI*)(OSVERSIONINFOW*);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) return {};
    const auto rtl_get_version = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    if (rtl_get_version == nullptr) return {};

    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (rtl_get_version(&version) < 0) return {};
    return std::to_string(version.dwMajorVersion) + "." +
           std::to_string(version.dwMinorVersion) + "." +
           std::to_string(version.dwBuildNumber);
}

} // namespace

HostEnvironment host_environment() {
    HostEnvironment result;
    result.os = "Windows";
    result.boot_id.clear();
    result.is_wsl = false;
    result.network_namespace_inode = 0;
    result.kernel_release = native_windows_version();
    return result;
}

PlatformCapabilities capabilities() {
    PlatformCapabilities c;
    c.connection_discovery = true;
    c.process_attribution = true;
    c.route_observation = true;

    const auto lifecycle = make_lifecycle_observer();
    const auto& lifecycle_capability = lifecycle->capability();
    c.connection_lifecycle_events = lifecycle_capability.available();
    c.lifecycle_connect_events = lifecycle_capability.connect_events;
    c.lifecycle_accept_events = lifecycle_capability.accept_events;
    c.lifecycle_close_events = lifecycle_capability.close_events;
    c.lifecycle_source = lifecycle_capability.source;
    c.exact_lifecycle_direction = lifecycle_capability.connect_events &&
                                  lifecycle_capability.accept_events;
    c.lifecycle_drop_counter = lifecycle_capability.drop_counter;
    c.lifecycle_dropped_events = lifecycle->health().dropped_events;
    c.lifecycle_unavailable_reason = lifecycle_capability.unavailable_reason;

    const auto name_resolution = make_name_resolution_observer();
    const auto& name_capability = name_resolution->capability();
    const auto name_health = name_resolution->health();
    c.application_name_resolution_events = name_capability.available();
    c.name_resolution_drop_counter = name_capability.drop_counter;
    c.name_resolution_dropped_events = name_health.dropped_events;
    c.name_resolution_source = name_capability.source;
    c.name_resolution_unavailable_reason = name_capability.unavailable_reason;
    c.exact_dns_observation = false;

    c.tls_session_source = "windows:tls";
    c.tls_session_unavailable_reason = "Windows application TLS collector is not implemented yet";
    return c;
}

std::unique_ptr<TlsSessionObserver> make_tls_session_observer() {
    return std::make_unique<UnavailableTlsSessionObserver>();
}

} // namespace neta::platform

// Keep the manifest-provider implementation isolated while compiling it through the
// existing Windows platform translation unit. This avoids touching non-Windows builds.
#include "dns_etw_observer.cpp"
