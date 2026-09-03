#include "neta/platform.hpp"

#include "process_exec_bpf_bytes.inc"
#include "process_exec_decoder.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

std::string exec_libbpf_error(const std::string& operation, long error) {
    const int code = error > 0 ? -static_cast<int>(error) : static_cast<int>(error);
    std::array<char, 256> message{};
    if (libbpf_strerror(code, message.data(), message.size()) != 0) {
        return operation + ": libbpf error " + std::to_string(code);
    }
    return operation + ": " + std::string(message.data());
}

class LinuxProcessExecObserver final : public ProcessExecObserver {
public:
    LinuxProcessExecObserver() {
        try {
            initialize();
        } catch (...) {
            cleanup();
            throw;
        }
    }

    ~LinuxProcessExecObserver() override { cleanup(); }

    const ProcessExecCapability& capability() const noexcept override { return capability_; }

    ProcessExecHealth health() const override {
        if (drop_map_fd_ < 0) return {};
        const std::uint32_t key = 0;
        std::uint64_t dropped = 0;
        if (bpf_map_lookup_elem(drop_map_fd_, &key, &dropped) != 0) return {};
        return ProcessExecHealth{dropped};
    }

    std::vector<ProcessExecEvent> poll(std::chrono::milliseconds timeout) override {
        pending_.clear();
        const auto bounded = std::min<std::int64_t>(
            timeout.count(), static_cast<std::int64_t>(std::numeric_limits<int>::max()));
        const int result = ring_buffer__poll(ring_, static_cast<int>(bounded));
        if (result < 0 && result != -EINTR) {
            throw std::runtime_error(exec_libbpf_error("polling process-exec ring buffer failed", result));
        }
        return std::move(pending_);
    }

private:
    void initialize() {
        capability_.built_in = true;
        capability_.btf_core_runtime = std::filesystem::exists("/sys/kernel/btf/vmlinux");
        if (!capability_.btf_core_runtime) {
            throw std::runtime_error("kernel BTF is unavailable at /sys/kernel/btf/vmlinux");
        }

        object_ = bpf_object__open_mem(linux_ebpf::kProcessExecBpfObject,
                                       linux_ebpf::kProcessExecBpfObjectSize, nullptr);
        const auto open_error = libbpf_get_error(object_);
        if (open_error != 0) {
            object_ = nullptr;
            throw std::runtime_error(exec_libbpf_error("opening embedded process-exec BPF object failed",
                                                       open_error));
        }
        const int load_result = bpf_object__load(object_);
        if (load_result != 0) {
            throw std::runtime_error(exec_libbpf_error("loading process-exec BPF program failed",
                                                       load_result));
        }

        bpf_program* program = bpf_object__find_program_by_name(object_, "neta_sched_process_exec");
        if (!program) throw std::runtime_error("embedded process-exec BPF program is missing");
        link_ = bpf_program__attach(program);
        const auto attach_error = libbpf_get_error(link_);
        if (attach_error != 0) {
            link_ = nullptr;
            throw std::runtime_error(exec_libbpf_error("attaching sched_process_exec failed",
                                                       attach_error));
        }
        capability_.exec_events = true;

        drop_map_fd_ = bpf_object__find_map_fd_by_name(object_, "process_exec_drops");
        if (drop_map_fd_ < 0) throw std::runtime_error("process-exec drop counter map is missing");
        capability_.drop_counter = true;

        const int map_fd = bpf_object__find_map_fd_by_name(object_, "process_exec_events");
        if (map_fd < 0) throw std::runtime_error("process-exec ring buffer map is missing");
        ring_ = ring_buffer__new(map_fd, &LinuxProcessExecObserver::on_sample, this, nullptr);
        const auto ring_error = libbpf_get_error(ring_);
        if (ring_error != 0) {
            ring_ = nullptr;
            throw std::runtime_error(exec_libbpf_error("creating process-exec ring buffer failed",
                                                       ring_error));
        }
    }

    void cleanup() noexcept {
        if (ring_) ring_buffer__free(ring_);
        ring_ = nullptr;
        if (link_) bpf_link__destroy(link_);
        link_ = nullptr;
        if (object_) bpf_object__close(object_);
        object_ = nullptr;
    }

    static int on_sample(void* context, void* data, std::size_t size) {
        auto& self = *static_cast<LinuxProcessExecObserver*>(context);
        const auto* first = static_cast<const std::byte*>(data);
        auto decoded = linux_ebpf::decode_process_exec_event({first, size});
        if (decoded.event) self.pending_.push_back(std::move(*decoded.event));
        return 0;
    }

    ProcessExecCapability capability_;
    bpf_object* object_{nullptr};
    bpf_link* link_{nullptr};
    ring_buffer* ring_{nullptr};
    int drop_map_fd_{-1};
    std::vector<ProcessExecEvent> pending_;
};

class UnavailableProcessExecObserver final : public ProcessExecObserver {
public:
    explicit UnavailableProcessExecObserver(std::string reason) {
        capability_.built_in = true;
        capability_.btf_core_runtime = std::filesystem::exists("/sys/kernel/btf/vmlinux");
        capability_.unavailable_reason = std::move(reason);
    }
    const ProcessExecCapability& capability() const noexcept override { return capability_; }
    ProcessExecHealth health() const override { return {}; }
    std::vector<ProcessExecEvent> poll(std::chrono::milliseconds) override { return {}; }
private:
    ProcessExecCapability capability_;
};

}  // namespace

std::unique_ptr<ProcessExecObserver> make_process_exec_observer() {
    try {
        return std::make_unique<LinuxProcessExecObserver>();
    } catch (const std::exception& error) {
        return std::make_unique<UnavailableProcessExecObserver>(error.what());
    }
}

}  // namespace neta::platform
