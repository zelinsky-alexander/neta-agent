#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <objbase.h>

#ifdef _MSC_VER
#pragma comment(lib, "ole32.lib")
#endif

#include <chrono>
#include <memory>
#include <string>

namespace neta::platform {

std::unique_ptr<TlsSessionObserver> make_windows_tls_session_observer();

namespace {

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
    // Windows TCP Extended Statistics provide the shared performance inputs.
    // Collection is enabled per connection by the elevated NETA service/CLI.
    c.tcp_rtt = true;
    c.tcp_rtt_variance = true;
    c.tcp_retransmissions = true;
    c.tcp_cwnd = true;
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

    const auto tls = make_windows_tls_session_observer();
    const auto& tls_capability = tls->capability();
    const auto tls_health = tls->health();
    c.application_tls_session_events = tls_capability.available();
    c.tls_session_sender_credentials_verified = tls_capability.sender_credentials_verified;
    c.tls_session_drop_counter = tls_capability.receive_drop_counter;
    c.tls_session_dropped_events = tls_health.dropped_events;
    c.tls_session_rejected_events = tls_health.rejected_events;
    c.tls_session_source = tls_capability.source;
    c.tls_session_endpoint = tls_capability.endpoint;
    c.tls_session_unavailable_reason = tls_capability.unavailable_reason;
    // Schannel ETW identifies the process, but the current implementation attaches
    // a TCP tuple only when it can do so unambiguously at observation time. That is
    // strong correlation, not Linux socket-cookie-level exactness.
    c.exact_tls_observation = false;
    return c;
}

std::unique_ptr<TlsSessionObserver> make_tls_session_observer() {
    return make_windows_tls_session_observer();
}

} // namespace neta::platform

// Keep the Schannel manifest-provider implementation isolated from the DNS ETW
// translation unit (compiled via service.cpp) because both use generic ETW helpers.
#include "tls_schannel_etw_observer.cpp"
