#include "neta/platform.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

class UnavailableNameResolutionObserver final : public NameResolutionObserver {
public:
    UnavailableNameResolutionObserver() {
        capability_.unavailable_reason =
            "application resolver eBPF support is not built (NETA_EBPF=OFF or libbpf/clang unavailable)";
    }

    const NameResolutionCapability& capability() const noexcept override { return capability_; }
    NameResolutionHealth health() const override { return {}; }
    std::vector<NameResolutionObservation> poll(std::chrono::milliseconds) override { return {}; }

private:
    NameResolutionCapability capability_;
};

} // namespace

std::unique_ptr<NameResolutionObserver> make_name_resolution_observer() {
    return std::make_unique<UnavailableNameResolutionObserver>();
}

} // namespace neta::platform
