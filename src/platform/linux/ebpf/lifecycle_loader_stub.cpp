#include "neta/platform.hpp"

#include <filesystem>
#include <memory>

namespace neta::platform {
namespace {

class UnavailableLifecycleObserver final : public LifecycleObserver {
public:
    UnavailableLifecycleObserver() {
        capability_.built_in = false;
        capability_.btf_core_runtime = std::filesystem::exists("/sys/kernel/btf/vmlinux");
        capability_.unavailable_reason =
            "binary was built without libbpf lifecycle support (polling fallback active)";
    }
    const LifecycleCapability& capability() const noexcept override { return capability_; }
    std::vector<ConnectionLifecycleEvent> poll(std::chrono::milliseconds) override { return {}; }
private:
    LifecycleCapability capability_;
};

} // namespace

std::unique_ptr<LifecycleObserver> make_lifecycle_observer() {
    return std::make_unique<UnavailableLifecycleObserver>();
}

} // namespace neta::platform
