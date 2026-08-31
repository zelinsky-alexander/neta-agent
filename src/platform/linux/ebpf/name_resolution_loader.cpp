#include "neta/platform.hpp"

#include "name_resolution_bpf_bytes.inc"
#include "name_resolution_decoder.hpp"
#include "name_resolution_wire.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <dlfcn.h>
#include <sys/stat.h>

#include <algorithm>
#include <array>
#include <cerrno>
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

neta_name_resolution_config agent_pid_namespace() {
    struct stat namespace_stat {};
    if (::stat("/proc/self/ns/pid", &namespace_stat) != 0) {
        throw std::runtime_error("stat(/proc/self/ns/pid) failed: " +
                                 std::string(std::strerror(errno)));
    }
    return {static_cast<std::uint64_t>(namespace_stat.st_dev),
            static_cast<std::uint64_t>(namespace_stat.st_ino)};
}

std::string glibc_path() {
    void* handle = ::dlopen("libc.so.6", RTLD_LAZY | RTLD_LOCAL);
    if (!handle) {
        throw std::runtime_error("glibc libc.so.6 is unavailable");
    }
    void* symbol = ::dlsym(handle, "getaddrinfo");
    Dl_info info{};
    const bool resolved = symbol != nullptr && ::dladdr(symbol, &info) != 0 && info.dli_fname;
    const std::string path = resolved ? info.dli_fname : std::string{};
    ::dlclose(handle);
    if (!resolved) throw std::runtime_error("unable to resolve glibc getaddrinfo symbol path");
    if (std::filesystem::path(path).filename() != "libc.so.6") {
        throw std::runtime_error("resolved getaddrinfo is not from supported glibc libc.so.6: " + path);
    }
    return path;
}

bpf_link* attach_getaddrinfo(bpf_program* program, const std::string& libc_path,
                             bool return_probe) {
    bpf_uprobe_opts options{};
    options.sz = sizeof(options);
    options.retprobe = return_probe;
    options.func_name = "getaddrinfo";
    bpf_link* link = bpf_program__attach_uprobe_opts(program, -1, libc_path.c_str(), 0, &options);
    const auto error = libbpf_get_error(link);
    if (error != 0) {
        throw std::runtime_error(libbpf_error(
            std::string("attaching glibc getaddrinfo ") + (return_probe ? "uretprobe" : "uprobe") +
                " failed", error));
    }
    return link;
}

class LinuxNameResolutionObserver final : public NameResolutionObserver {
public:
    LinuxNameResolutionObserver() {
        try {
            initialize();
        } catch (...) {
            cleanup();
            throw;
        }
    }

    ~LinuxNameResolutionObserver() override { cleanup(); }

    LinuxNameResolutionObserver(const LinuxNameResolutionObserver&) = delete;
    LinuxNameResolutionObserver& operator=(const LinuxNameResolutionObserver&) = delete;

    const NameResolutionCapability& capability() const noexcept override { return capability_; }

    NameResolutionHealth health() const override {
        if (drop_map_fd_ < 0) return {};
        const std::uint32_t key = 0;
        std::uint64_t dropped = 0;
        if (bpf_map_lookup_elem(drop_map_fd_, &key, &dropped) != 0) return {};
        return NameResolutionHealth{dropped};
    }

    std::vector<NameResolutionObservation> poll(std::chrono::milliseconds timeout) override {
        pending_.clear();
        const auto bounded = std::min<std::int64_t>(
            timeout.count(), static_cast<std::int64_t>(std::numeric_limits<int>::max()));
        const int result = ring_buffer__poll(ring_, static_cast<int>(bounded));
        if (result < 0 && result != -EINTR) {
            throw std::runtime_error(libbpf_error(
                "polling name-resolution ring buffer failed", result));
        }
        return std::move(pending_);
    }

private:
    void initialize() {
        capability_.built_in = true;
        capability_.source = "glibc:getaddrinfo uprobe";
        if (!std::filesystem::exists("/sys/kernel/btf/vmlinux")) {
            throw std::runtime_error("kernel BTF is unavailable at /sys/kernel/btf/vmlinux");
        }
        const auto libc = glibc_path();
        const auto pid_namespace = agent_pid_namespace();

        object_ = bpf_object__open_mem(linux_ebpf::kNameResolutionBpfObject,
                                       linux_ebpf::kNameResolutionBpfObjectSize, nullptr);
        const auto open_error = libbpf_get_error(object_);
        if (open_error != 0) {
            object_ = nullptr;
            throw std::runtime_error(libbpf_error(
                "opening embedded name-resolution BPF object failed", open_error));
        }
        const int load_result = bpf_object__load(object_);
        if (load_result != 0) {
            throw std::runtime_error(libbpf_error(
                "loading name-resolution BPF programs failed", load_result));
        }

        const int config_fd = bpf_object__find_map_fd_by_name(object_, "name_resolution_config");
        if (config_fd < 0) {
            throw std::runtime_error("embedded name-resolution PID namespace config map is missing");
        }
        const std::uint32_t config_key = 0;
        if (bpf_map_update_elem(config_fd, &config_key, &pid_namespace, BPF_ANY) != 0) {
            throw std::runtime_error("configuring name-resolution PID namespace failed: " +
                                     std::string(std::strerror(errno)));
        }

        drop_map_fd_ = bpf_object__find_map_fd_by_name(object_, "name_resolution_drops");
        if (drop_map_fd_ < 0) {
            throw std::runtime_error("embedded name-resolution drop counter map is missing");
        }
        capability_.drop_counter = true;

        auto* enter = bpf_object__find_program_by_name(object_, "neta_getaddrinfo_enter");
        auto* exit = bpf_object__find_program_by_name(object_, "neta_getaddrinfo_exit");
        if (!enter || !exit) {
            throw std::runtime_error("embedded getaddrinfo uprobe programs are missing");
        }
        links_.push_back(attach_getaddrinfo(enter, libc, false));
        links_.push_back(attach_getaddrinfo(exit, libc, true));

        const int event_fd = bpf_object__find_map_fd_by_name(object_, "name_resolution_events");
        if (event_fd < 0) {
            throw std::runtime_error("embedded name-resolution ring buffer map is missing");
        }
        ring_ = ring_buffer__new(event_fd, &LinuxNameResolutionObserver::on_sample, this, nullptr);
        const auto ring_error = libbpf_get_error(ring_);
        if (ring_error != 0) {
            ring_ = nullptr;
            throw std::runtime_error(libbpf_error(
                "creating name-resolution ring buffer failed", ring_error));
        }

        capability_.application_resolver_api = true;
        capability_.glibc_getaddrinfo = true;
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
        drop_map_fd_ = -1;
    }

    static int on_sample(void* context, void* data, std::size_t size) {
        auto& self = *static_cast<LinuxNameResolutionObserver*>(context);
        const auto* first = static_cast<const std::byte*>(data);
        auto decoded = linux_ebpf::decode_name_resolution_event({first, size});
        if (decoded.observation) self.pending_.push_back(std::move(*decoded.observation));
        return 0;
    }

    NameResolutionCapability capability_;
    bpf_object* object_{nullptr};
    std::vector<bpf_link*> links_;
    ring_buffer* ring_{nullptr};
    int drop_map_fd_{-1};
    std::vector<NameResolutionObservation> pending_;
};

class UnavailableNameResolutionObserver final : public NameResolutionObserver {
public:
    explicit UnavailableNameResolutionObserver(std::string reason) {
        capability_.built_in = true;
        capability_.source = "glibc:getaddrinfo uprobe";
        capability_.unavailable_reason = std::move(reason);
    }

    const NameResolutionCapability& capability() const noexcept override { return capability_; }
    NameResolutionHealth health() const override { return {}; }
    std::vector<NameResolutionObservation> poll(std::chrono::milliseconds) override { return {}; }

private:
    NameResolutionCapability capability_;
};

} // namespace

std::unique_ptr<NameResolutionObserver> make_name_resolution_observer() {
    try {
        return std::make_unique<LinuxNameResolutionObserver>();
    } catch (const std::exception& error) {
        return std::make_unique<UnavailableNameResolutionObserver>(error.what());
    }
}

} // namespace neta::platform
