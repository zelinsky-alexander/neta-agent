#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <chrono>
#include <memory>
#include <string>

namespace neta::platform {
namespace {

class UnavailableNameResolutionObserver final : public NameResolutionObserver {
public:
    UnavailableNameResolutionObserver() {
        capability_.source = "windows:dns";
        capability_.unavailable_reason = "Windows DNS ETW collector is not implemented yet";
    }

    const NameResolutionCapability& capability() const noexcept override { return capability_; }
    NameResolutionHealth health() const override { return {}; }
    std::vector<NameResolutionObservation> poll(std::chrono::milliseconds) override { return {}; }

private:
    NameResolutionCapability capability_;
};

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
    // GetVersionExW is subject to application-manifest version lying and reported
    // 6.2.9200 on a real Windows 10 22H2 acceptance host. RtlGetVersion returns the
    // native kernel version and is dynamically resolved so this platform seam stays
    // independent of SDK-private headers/import libraries.
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

    c.name_resolution_source = "windows:dns";
    c.name_resolution_unavailable_reason = "Windows DNS ETW collector is not implemented yet";
    c.tls_session_source = "windows:tls";
    c.tls_session_unavailable_reason = "Windows application TLS collector is not implemented yet";
    return c;
}

std::unique_ptr<NameResolutionObserver> make_name_resolution_observer() {
    return std::make_unique<UnavailableNameResolutionObserver>();
}

std::unique_ptr<TlsSessionObserver> make_tls_session_observer() {
    return std::make_unique<UnavailableTlsSessionObserver>();
}

} // namespace neta::platform
