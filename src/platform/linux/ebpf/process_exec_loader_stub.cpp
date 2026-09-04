#include "neta/platform.hpp"

#include <chrono>
#include <memory>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

class UnavailableProcessExecObserver final : public ProcessExecObserver {
public:
    UnavailableProcessExecObserver() {
        capability_.built_in = false;
        capability_.unavailable_reason = "neta-agent was built without eBPF support";
    }
    const ProcessExecCapability& capability() const noexcept override { return capability_; }
    ProcessExecHealth health() const override { return {}; }
    std::vector<ProcessExecEvent> poll(std::chrono::milliseconds) override { return {}; }
private:
    ProcessExecCapability capability_;
};

}  // namespace

std::unique_ptr<ProcessExecObserver> make_process_exec_observer() {
    return std::make_unique<UnavailableProcessExecObserver>();
}

}  // namespace neta::platform
