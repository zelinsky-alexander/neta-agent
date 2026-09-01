#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <chrono>
#include <memory>

namespace neta::platform {
namespace {

class UnavailableLifecycleObserver final : public LifecycleObserver {
public:
    UnavailableLifecycleObserver() {
        capability_.unavailable_reason = "Windows ETW lifecycle collector is not implemented yet";
    }

    const LifecycleCapability& capability() const noexcept override { return capability_; }
    LifecycleHealth health() const override { return {}; }
    std::vector<ConnectionLifecycleEvent> poll(std::chrono::milliseconds) override { return {}; }

private:
    LifecycleCapability capability_;
};

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

} // namespace

HostEnvironment host_environment() {
    HostEnvironment result;
    result.os = "Windows";
    result.boot_id.clear();
    result.is_wsl = false;
    result.network_namespace_inode = 0;

    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
#pragma warning(push)
#pragma warning(disable:4996)
    if (GetVersionExW(&version) != FALSE) {
        result.kernel_release = std::to_string(version.dwMajorVersion) + "." +
                                std::to_string(version.dwMinorVersion) + "." +
                                std::to_string(version.dwBuildNumber);
    }
#pragma warning(pop)
    return result;
}

PlatformCapabilities capabilities() {
    PlatformCapabilities c;
    c.connection_discovery = true;
    c.process_attribution = true;
    c.route_observation = true;
    c.lifecycle_unavailable_reason = "Windows ETW lifecycle collector is not implemented yet";
    c.name_resolution_source = "windows:dns";
    c.name_resolution_unavailable_reason = "Windows DNS ETW collector is not implemented yet";
    c.tls_session_source = "windows:tls";
    c.tls_session_unavailable_reason = "Windows application TLS collector is not implemented yet";
    return c;
}

std::unique_ptr<LifecycleObserver> make_lifecycle_observer() {
    return std::make_unique<UnavailableLifecycleObserver>();
}

std::unique_ptr<NameResolutionObserver> make_name_resolution_observer() {
    return std::make_unique<UnavailableNameResolutionObserver>();
}

std::unique_ptr<TlsSessionObserver> make_tls_session_observer() {
    return std::make_unique<UnavailableTlsSessionObserver>();
}

} // namespace neta::platform
