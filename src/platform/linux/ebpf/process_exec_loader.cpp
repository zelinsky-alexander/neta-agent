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
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
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

std::string read_cmdline(std::int64_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (!input) return {};
    std::string value((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    for (char& c : value) {
        if (c == '\0') c = ' ';
    }
    while (!value.empty() && value.back() == ' ') value.pop_back();
    return value;
}

std::string read_working_directory(std::int64_t pid) {
    std::error_code error;
    const auto target = std::filesystem::read_symlink(
        "/proc/" + std::to_string(pid) + "/cwd", error);
    if (error) return {};
    return target.string();
}

std::optional<std::uint32_t> read_session_id(std::int64_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!input || !std::getline(input, line)) return std::nullopt;
    const auto closing = line.rfind(')');
    if (closing == std::string::npos || closing + 2U >= line.size()) return std::nullopt;
    std::istringstream fields(line.substr(closing + 2U));
    char state{};
    std::int64_t ppid{};
    std::int64_t pgrp{};
    std::int64_t session{};
    if (!(fields >> state >> ppid >> pgrp >> session) || session < 0 ||
        session > static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max())) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(session);
}

void enrich_process_start(ProcessExecEvent& event) {
    if (event.type != ProcessExecEventType::Start || !event.tgid || *event.tgid <= 0) return;
    event.command_line = read_cmdline(*event.tgid);
    event.working_directory = read_working_directory(*event.tgid);
    event.session_id = read_session_id(*event.tgid);
    if (event.uid) {
        event.user_identity = "uid:" + std::to_string(*event.uid);
        event.elevated = *event.uid == 0;
        event.integrity_level = *event.uid == 0 ? "root" : "user";
    }
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
        capability_.source = "linux:ebpf-sched-process";
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

        bpf_program* start_program = bpf_object__find_program_by_name(object_, "neta_sched_process_exec");
        if (!start_program) throw std::runtime_error("embedded sched_process_exec program is missing");
        start_link_ = bpf_program__attach(start_program);
        const auto start_error = libbpf_get_error(start_link_);
        if (start_error != 0) {
            start_link_ = nullptr;
            throw std::runtime_error(exec_libbpf_error("attaching sched_process_exec failed",
                                                       start_error));
        }
        capability_.exec_events = true;

        bpf_program* exit_program = bpf_object__find_program_by_name(object_, "neta_sched_process_exit");
        if (!exit_program) throw std::runtime_error("embedded sched_process_exit program is missing");
        exit_link_ = bpf_program__attach(exit_program);
        const auto exit_error = libbpf_get_error(exit_link_);
        if (exit_error != 0) {
            exit_link_ = nullptr;
            throw std::runtime_error(exec_libbpf_error("attaching sched_process_exit failed",
                                                       exit_error));
        }
        capability_.exit_events = true;
        capability_.parent_identity = true;
        capability_.command_line = true;
        capability_.working_directory = true;
        capability_.security_identity = true;
        capability_.session_identity = true;

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
        if (exit_link_) bpf_link__destroy(exit_link_);
        exit_link_ = nullptr;
        if (start_link_) bpf_link__destroy(start_link_);
        start_link_ = nullptr;
        if (object_) bpf_object__close(object_);
        object_ = nullptr;
    }

    static int on_sample(void* context, void* data, std::size_t size) {
        auto& self = *static_cast<LinuxProcessExecObserver*>(context);
        const auto* first = static_cast<const std::byte*>(data);
        auto decoded = linux_ebpf::decode_process_exec_event({first, size});
        if (decoded.event) {
            enrich_process_start(*decoded.event);
            self.pending_.push_back(std::move(*decoded.event));
        }
        return 0;
    }

    ProcessExecCapability capability_;
    bpf_object* object_{nullptr};
    bpf_link* start_link_{nullptr};
    bpf_link* exit_link_{nullptr};
    ring_buffer* ring_{nullptr};
    int drop_map_fd_{-1};
    std::vector<ProcessExecEvent> pending_;
};

class UnavailableProcessExecObserver final : public ProcessExecObserver {
public:
    explicit UnavailableProcessExecObserver(std::string reason) {
        capability_.built_in = true;
        capability_.source = "linux:ebpf-sched-process";
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
