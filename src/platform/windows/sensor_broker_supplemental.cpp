#include "neta/windows_sensor_broker.hpp"

#ifdef _WIN32

#include <memory>

namespace neta::windows_sensor_broker {
namespace {

class BrokerNameResolutionUnavailable final : public NameResolutionObserver {
public:
    BrokerNameResolutionUnavailable() {
        capability_.source = "broker:windows-phase3";
        capability_.unavailable_reason =
            "Windows DNS ETW multiplexing is not part of large-scale simulator Phase 3";
    }
    const NameResolutionCapability& capability() const noexcept override { return capability_; }
    NameResolutionHealth health() const override { return {}; }
    std::vector<NameResolutionObservation> poll(std::chrono::milliseconds) override { return {}; }

private:
    NameResolutionCapability capability_;
};

class BrokerTlsUnavailable final : public TlsSessionObserver {
public:
    BrokerTlsUnavailable() {
        capability_.source = "broker:windows-phase3";
        capability_.unavailable_reason =
            "Windows Schannel ETW multiplexing is not part of large-scale simulator Phase 3";
    }
    const TlsSessionCapability& capability() const noexcept override { return capability_; }
    TlsSessionHealth health() const override { return {}; }
    std::vector<TlsSessionObservation> poll(std::chrono::milliseconds) override { return {}; }

private:
    TlsSessionCapability capability_;
};

}  // namespace

std::unique_ptr<NameResolutionObserver> make_broker_name_resolution_observer() {
    return std::make_unique<BrokerNameResolutionUnavailable>();
}

std::unique_ptr<TlsSessionObserver> make_broker_tls_session_observer() {
    return std::make_unique<BrokerTlsUnavailable>();
}

}  // namespace neta::windows_sensor_broker

#endif
