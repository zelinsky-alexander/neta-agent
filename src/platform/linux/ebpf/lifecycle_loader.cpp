#include "neta/platform.hpp"

#include "lifecycle_bpf_bytes.inc"
#include "lifecycle_decoder.hpp"
#include "lifecycle_wire.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/stat.h>

#include <array>
#include <cerrno>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

std::string libbpf_error(const std::string& operation, long error) {
    const int code = error > 0 ? -static_cast<int>(error) : static_cast<int>(error);
    std::array<char, 256> message{};
    if (libbpf_strerror(code, message.data(), message.size()) != 0) {
        return operation + ": libbpf error " + std::to_string(code);
    }
    return operation + ": " + std::string(message.data());
}

neta_lifecycle_config agent_pid_namespace() {
    struct stat namespace_stat {};
    if (::stat("/proc/self/ns/pid", &namespace_stat) != 0) {
        throw std::runtime_error("stat(/proc/self/ns/pid) failed: " +
                                 std::string(std::strerror(errno)));
    }
    return {static_cast<std::uint64_t>(namespace_stat.st_dev),
            static_cast<std::uint64_t>(namespace_stat.st_ino)};
}

class LinuxLifecycleObserver final : public LifecycleObserver {
public:
    LinuxLifecycleObserver() {
        try {
            initialize();
        } catch (...) {
            cleanup();
            throw;
        }
    }

    ~LinuxLifecycleObserver() override { cleanup(); }

    LinuxLifecycleObserver(const LinuxLifecycleObserver&) = delete;
    LinuxLifecycleObserver& operator=(const LinuxLifecycleObserver&) = delete;

    const LifecycleCapability& capability() const noexcept override { return capability_; }

    LifecycleHealth health() const override {
        if (drop_map_fd_ < 0) return {};
        const std::uint32_t key = 0;
        std::uint64_t dropped = 0;
        if (bpf_map_lookup_elem(drop_map_fd_, &key, &dropped) != 0) return {};
        return LifecycleHealth{dropped};
    }

    std::vector<ConnectionLifecycleEvent> poll(std::chrono::milliseconds timeout) override {
        pending_.clear();
        const auto bounded = std::min<std::int64_t>(
            timeout.count(), static_cast<std::int64_t>(std::numeric_limits<int>::max()));
        const int result = ring_buffer__poll(ring_, static_cast<int>(bounded));
        if (result < 0 && result != -EINTR) {
            throw std::runtime_error(libbpf_error("polling lifecycle ring buffer failed", result));
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
        const auto pid_namespace = agent_pid_namespace();

        object_ = bpf_object__open_mem(linux_ebpf::kLifecycleBpfObject,
                                       linux_ebpf::kLifecycleBpfObjectSize, nullptr);
        const auto open_error = libbpf_get_error(object_);
        if (open_error != 0) {
            object_ = nullptr;
            throw std::runtime_error(libbpf_error("opening embedded BPF object failed", open_error));
        }
        const int load_result = bpf_object__load(object_);
        if (load_result != 0) {
            throw std::runtime_error(libbpf_error("loading lifecycle BPF programs failed",
                                                  load_result));
        }

        const int config_fd = bpf_object__find_map_fd_by_name(object_, "lifecycle_config");
        if (config_fd < 0) {
            throw std::runtime_error("embedded lifecycle PID namespace config map is missing");
        }
        const std::uint32_t config_key = 0;
        if (bpf_map_update_elem(config_fd, &config_key, &pid_namespace, BPF_ANY) != 0) {
            throw std::runtime_error("configuring lifecycle PID namespace failed: " +
                                     std::string(std::strerror(errno)));
        }
        drop_map_fd_ = bpf_object__find_map_fd_by_name(object_, "lifecycle_drops");
        if (drop_map_fd_ < 0) {
            throw std::runtime_error("embedded lifecycle drop counter map is missing");
        }
        capability_.drop_counter = true;

        bool ipv4_connect_attached = false;
        bool ipv6_connect_attached = false;
        bool accept_attached = false;
        bool close_attached = false;
        std::string attach_errors;
        bpf_program* program = nullptr;
        bpf_object__for_each_program(program, object_) {
            bpf_link* link = bpf_program__attach(program);
            const auto attach_error = libbpf_get_error(link);
            if (attach_error != 0) {
                if (!attach_errors.empty()) attach_errors += "; ";
                attach_errors += libbpf_error(
                    "attaching " + std::string(bpf_program__name(program)) + " failed",
                    attach_error);
                continue;
            }
            links_.push_back(link);
            const std::string name = bpf_program__name(program);
            if (name == "neta_tcp_v4_connect") ipv4_connect_attached = true;
            else if (name == "neta_tcp_v6_connect") ipv6_connect_attached = true;
            else if (name == "neta_inet_csk_accept") accept_attached = true;
            else if (name == "neta_tcp_close") close_attached = true;
        }
        capability_.connect_events = ipv4_connect_attached && ipv6_connect_attached;
        capability_.accept_events = accept_attached;
        capability_.close_events = close_attached;
        capability_.unavailable_reason = std::move(attach_errors);
        if (links_.empty()) {
            throw std::runtime_error("no lifecycle eBPF hook could be attached: " +
                                     capability_.unavailable_reason);
        }

        const int map_fd = bpf_object__find_map_fd_by_name(object_, "lifecycle_events");
        if (map_fd < 0) throw std::runtime_error("embedded lifecycle ring buffer map is missing");
        ring_ = ring_buffer__new(map_fd, &LinuxLifecycleObserver::on_sample, this, nullptr);
        const auto ring_error = libbpf_get_error(ring_);
        if (ring_error != 0) {
            ring_ = nullptr;
            throw std::runtime_error(libbpf_error("creating lifecycle ring buffer failed", ring_error));
        }

    }

    void cleanup() noexcept {
        if (ring_) {
            ring_buffer__free(ring_);
            ring_ = nullptr;
        }
        for (auto* link : links_) bpf_link__destroy(link);
        links_.clear();
        if (object_) {
            bpf_object__close(object_);
            object_ = nullptr;
        }
    }
    static int on_sample(void* context, void* data, std::size_t size) {
        auto& self = *static_cast<LinuxLifecycleObserver*>(context);
        const auto* first = static_cast<const std::byte*>(data);
        auto decoded = linux_ebpf::decode_lifecycle_event({first, size});
        if (decoded.event) self.pending_.push_back(std::move(*decoded.event));
        return 0;
    }

    LifecycleCapability capability_;
    bpf_object* object_{nullptr};
    std::vector<bpf_link*> links_;
    ring_buffer* ring_{nullptr};
    int drop_map_fd_{-1};
    std::vector<ConnectionLifecycleEvent> pending_;
};

class UnavailableLifecycleObserver final : public LifecycleObserver {
public:
    explicit UnavailableLifecycleObserver(std::string reason) {
        capability_.built_in = true;
        capability_.btf_core_runtime = std::filesystem::exists("/sys/kernel/btf/vmlinux");
        capability_.unavailable_reason = std::move(reason);
    }
    const LifecycleCapability& capability() const noexcept override { return capability_; }
    LifecycleHealth health() const override { return {}; }
    std::vector<ConnectionLifecycleEvent> poll(std::chrono::milliseconds) override { return {}; }
private:
    LifecycleCapability capability_;
};

} // namespace

std::unique_ptr<LifecycleObserver> make_lifecycle_observer() {
    try {
        return std::make_unique<LinuxLifecycleObserver>();
    } catch (const std::exception& error) {
        return std::make_unique<UnavailableLifecycleObserver>(error.what());
    }
}

} // namespace neta::platform
