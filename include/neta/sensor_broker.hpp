#pragma once

#ifndef _WIN32

#include "neta/platform.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace neta::sensor_broker {

enum class SensorMode { Native, Broker };
enum class EventKind : std::uint16_t { Lifecycle = 1, ProcessExec = 2 };

enum class MessageType : std::uint16_t {
    Register = 1,
    Lifecycle = 2,
    ProcessExec = 3,
};

inline SensorMode sensor_mode_from_environment() {
    const char* raw = std::getenv("NETA_SENSOR_MODE");
    if (raw == nullptr || *raw == '\0' || std::string_view(raw) == "native") {
        return SensorMode::Native;
    }
    if (std::string_view(raw) == "broker") return SensorMode::Broker;
    throw std::runtime_error("NETA_SENSOR_MODE must be 'native' or 'broker'");
}

inline std::string configured_socket_path() {
    const char* raw = std::getenv("NETA_SENSOR_BROKER");
    return raw != nullptr && *raw != '\0' ? std::string(raw) : "/run/neta/sensor-broker.sock";
}

inline std::string configured_endpoint_slot() {
    const char* raw = std::getenv("NETA_ENDPOINT_SLOT");
    if (raw == nullptr || *raw == '\0') {
        throw std::runtime_error("NETA_ENDPOINT_SLOT is required when NETA_SENSOR_MODE=broker");
    }
    return raw;
}

constexpr std::uint32_t kMagic = 0x4e534231U; // NSB1
constexpr std::uint16_t kProtocolVersion = 1;
constexpr std::size_t kSlotLength = 64;
constexpr std::size_t kAddressLength = 64;
constexpr std::size_t kCommLength = 64;
constexpr std::size_t kPathLength = 512;
constexpr std::size_t kCommandLineLength = 1024;
constexpr std::size_t kWorkingDirectoryLength = 512;
constexpr std::size_t kIdentityLength = 128;
constexpr std::size_t kIntegrityLength = 64;
constexpr std::size_t kMaxFrameSize = 8192;

#pragma pack(push, 1)
struct FrameHeader {
    std::uint32_t magic{kMagic};
    std::uint16_t version{kProtocolVersion};
    std::uint16_t type{0};
    std::uint64_t sequence{0};
    std::uint32_t payload_size{0};
    std::uint32_t reserved{0};
};

struct RegistrationPayload {
    std::uint16_t event_kind{0};
    std::uint16_t reserved{0};
    char endpoint_slot[kSlotLength]{};
};

enum LifecycleFlags : std::uint32_t {
    LifecycleAgentPid = 1U << 0,
    LifecycleKernelPid = 1U << 1,
    LifecyclePidNamespace = 1U << 2,
    LifecycleUid = 1U << 3,
    LifecycleStartTicks = 1U << 4,
    LifecycleNetns = 1U << 5,
    LifecycleSocketCookie = 1U << 6,
    LifecyclePlatformConnectionId = 1U << 7,
    LifecycleTcpState = 1U << 8,
    LifecycleLocal = 1U << 9,
    LifecycleLocalPort = 1U << 10,
    LifecycleRemote = 1U << 11,
    LifecycleRemotePort = 1U << 12,
};

struct LifecyclePayload {
    std::uint32_t flags{0};
    std::uint8_t event_type{0};
    std::uint8_t provenance{0};
    std::uint8_t address_family{0};
    std::uint8_t protocol{0};
    std::uint8_t endpoint_kind{0};
    std::uint8_t tcp_state{0};
    std::uint16_t reserved{0};
    std::uint64_t timestamp_ns{0};
    std::int64_t agent_pid{0};
    std::int64_t agent_tgid{0};
    std::int64_t kernel_pid{0};
    std::int64_t kernel_tgid{0};
    std::uint64_t pid_namespace_device{0};
    std::uint64_t pid_namespace_inode{0};
    std::uint32_t uid{0};
    std::uint32_t reserved2{0};
    std::uint64_t start_ticks{0};
    std::uint64_t network_namespace_inode{0};
    std::uint64_t socket_cookie{0};
    std::uint64_t platform_connection_id{0};
    std::uint16_t local_port{0};
    std::uint16_t remote_port{0};
    char comm[kCommLength]{};
    char local_address[kAddressLength]{};
    char remote_address[kAddressLength]{};
};

enum ProcessExecFlags : std::uint32_t {
    ProcessPid = 1U << 0,
    ProcessParent = 1U << 1,
    ProcessUid = 1U << 2,
    ProcessGid = 1U << 3,
    ProcessStart = 1U << 4,
    ProcessPlatformKey = 1U << 5,
    ProcessParentStart = 1U << 6,
    ProcessParentPlatformKey = 1U << 7,
    ProcessSession = 1U << 8,
    ProcessElevated = 1U << 9,
    ProcessExitCode = 1U << 10,
    ProcessCgroup = 1U << 11,
};

struct ProcessExecPayload {
    std::uint32_t flags{0};
    std::uint8_t event_type{0};
    std::uint8_t elevated{0};
    std::uint16_t reserved{0};
    std::uint64_t timestamp_ns{0};
    std::int64_t pid{0};
    std::int64_t tgid{0};
    std::int64_t parent_pid{0};
    std::int64_t parent_tgid{0};
    std::uint32_t uid{0};
    std::uint32_t gid{0};
    std::uint64_t process_start_time_ns{0};
    std::uint64_t platform_process_key{0};
    std::uint64_t parent_process_start_time_ns{0};
    std::uint64_t parent_platform_process_key{0};
    std::uint32_t session_id{0};
    std::int32_t exit_code{0};
    std::uint64_t cgroup_id{0};
    char comm[kCommLength]{};
    char executable_path[kPathLength]{};
    char command_line[kCommandLineLength]{};
    char working_directory[kWorkingDirectoryLength]{};
    char user_identity[kIdentityLength]{};
    char integrity_level[kIntegrityLength]{};
};
#pragma pack(pop)

static_assert(sizeof(FrameHeader) == 24);

template <std::size_t N>
inline void copy_text(char (&target)[N], std::string_view value) {
    static_assert(N > 0);
    std::memset(target, 0, N);
    const auto count = std::min(value.size(), N - 1U);
    if (count != 0) std::memcpy(target, value.data(), count);
}

template <std::size_t N>
inline std::string read_text(const char (&value)[N]) {
    return std::string(value, ::strnlen(value, N));
}

template <typename Payload>
inline std::vector<std::byte> make_frame(MessageType type, std::uint64_t sequence,
                                         const Payload& payload) {
    FrameHeader header;
    header.type = static_cast<std::uint16_t>(type);
    header.sequence = sequence;
    header.payload_size = static_cast<std::uint32_t>(sizeof(Payload));
    std::vector<std::byte> bytes(sizeof(FrameHeader) + sizeof(Payload));
    std::memcpy(bytes.data(), &header, sizeof(header));
    std::memcpy(bytes.data() + sizeof(header), &payload, sizeof(payload));
    return bytes;
}

inline std::optional<FrameHeader> frame_header(std::span<const std::byte> bytes) {
    if (bytes.size() < sizeof(FrameHeader)) return std::nullopt;
    FrameHeader header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.magic != kMagic || header.version != kProtocolVersion) return std::nullopt;
    const auto payload = static_cast<std::size_t>(header.payload_size);
    if (payload > kMaxFrameSize || bytes.size() != sizeof(FrameHeader) + payload) return std::nullopt;
    return header;
}

template <typename Payload>
inline std::optional<Payload> frame_payload(std::span<const std::byte> bytes, MessageType type) {
    const auto header = frame_header(bytes);
    if (!header || header->type != static_cast<std::uint16_t>(type) ||
        header->payload_size != sizeof(Payload)) {
        return std::nullopt;
    }
    Payload payload{};
    std::memcpy(&payload, bytes.data() + sizeof(FrameHeader), sizeof(payload));
    return payload;
}

inline MessageType message_type(EventKind kind) {
    return kind == EventKind::Lifecycle ? MessageType::Lifecycle : MessageType::ProcessExec;
}

inline std::vector<std::byte> encode_registration(std::string_view slot, EventKind kind) {
    if (slot.empty() || slot.size() >= kSlotLength) {
        throw std::runtime_error("broker endpoint slot must contain 1-63 bytes");
    }
    RegistrationPayload payload;
    payload.event_kind = static_cast<std::uint16_t>(kind);
    copy_text(payload.endpoint_slot, slot);
    return make_frame(MessageType::Register, 0, payload);
}

struct Registration {
    std::string endpoint_slot;
    EventKind event_kind{EventKind::Lifecycle};
};

inline std::optional<Registration> decode_registration(std::span<const std::byte> bytes) {
    const auto payload = frame_payload<RegistrationPayload>(bytes, MessageType::Register);
    if (!payload) return std::nullopt;
    EventKind kind{};
    if (payload->event_kind == static_cast<std::uint16_t>(EventKind::Lifecycle)) {
        kind = EventKind::Lifecycle;
    } else if (payload->event_kind == static_cast<std::uint16_t>(EventKind::ProcessExec)) {
        kind = EventKind::ProcessExec;
    } else {
        return std::nullopt;
    }
    const auto slot = read_text(payload->endpoint_slot);
    if (slot.empty()) return std::nullopt;
    return Registration{slot, kind};
}

inline std::vector<std::byte> encode_lifecycle(std::uint64_t sequence,
                                               const ConnectionLifecycleEvent& event) {
    LifecyclePayload payload;
    payload.event_type = static_cast<std::uint8_t>(event.type);
    payload.provenance = static_cast<std::uint8_t>(event.provenance);
    payload.address_family = static_cast<std::uint8_t>(event.address_family);
    payload.protocol = static_cast<std::uint8_t>(event.protocol);
    payload.endpoint_kind = static_cast<std::uint8_t>(event.endpoint_kind);
    payload.timestamp_ns = event.timestamp_ns;
    copy_text(payload.comm, event.process.comm.value_or(""));
    if (event.process.agent_visible.pid && event.process.agent_visible.tgid) {
        payload.flags |= LifecycleAgentPid;
        payload.agent_pid = *event.process.agent_visible.pid;
        payload.agent_tgid = *event.process.agent_visible.tgid;
    }
    if (event.process.kernel.pid && event.process.kernel.tgid) {
        payload.flags |= LifecycleKernelPid;
        payload.kernel_pid = *event.process.kernel.pid;
        payload.kernel_tgid = *event.process.kernel.tgid;
    }
    if (event.process.agent_pid_namespace) {
        payload.flags |= LifecyclePidNamespace;
        payload.pid_namespace_device = event.process.agent_pid_namespace->device;
        payload.pid_namespace_inode = event.process.agent_pid_namespace->inode;
    }
    if (event.process.uid) {
        payload.flags |= LifecycleUid;
        payload.uid = *event.process.uid;
    }
    if (event.process.start_ticks) {
        payload.flags |= LifecycleStartTicks;
        payload.start_ticks = *event.process.start_ticks;
    }
    if (event.network_namespace_inode) {
        payload.flags |= LifecycleNetns;
        payload.network_namespace_inode = *event.network_namespace_inode;
    }
    if (event.socket_cookie) {
        payload.flags |= LifecycleSocketCookie;
        payload.socket_cookie = *event.socket_cookie;
    }
    if (event.platform_connection_id) {
        payload.flags |= LifecyclePlatformConnectionId;
        payload.platform_connection_id = *event.platform_connection_id;
    }
    if (event.tcp_state) {
        payload.flags |= LifecycleTcpState;
        payload.tcp_state = *event.tcp_state;
    }
    if (event.local) {
        payload.flags |= LifecycleLocal;
        copy_text(payload.local_address, event.local->address);
        if (event.local->port) {
            payload.flags |= LifecycleLocalPort;
            payload.local_port = *event.local->port;
        }
    }
    if (event.remote) {
        payload.flags |= LifecycleRemote;
        copy_text(payload.remote_address, event.remote->address);
        if (event.remote->port) {
            payload.flags |= LifecycleRemotePort;
            payload.remote_port = *event.remote->port;
        }
    }
    return make_frame(MessageType::Lifecycle, sequence, payload);
}

inline std::optional<ConnectionLifecycleEvent> decode_lifecycle(std::span<const std::byte> bytes) {
    const auto payload = frame_payload<LifecyclePayload>(bytes, MessageType::Lifecycle);
    if (!payload) return std::nullopt;
    ConnectionLifecycleEvent event;
    event.type = static_cast<ConnectionLifecycleEventType>(payload->event_type);
    event.provenance = static_cast<LifecycleProvenance>(payload->provenance);
    event.address_family = static_cast<NetworkAddressFamily>(payload->address_family);
    event.protocol = static_cast<TransportProtocol>(payload->protocol);
    event.endpoint_kind = static_cast<TcpEndpointKind>(payload->endpoint_kind);
    event.timestamp_ns = payload->timestamp_ns;
    const auto comm = read_text(payload->comm);
    if (!comm.empty()) event.process.comm = comm;
    if ((payload->flags & LifecycleAgentPid) != 0U) {
        event.process.agent_visible.pid = payload->agent_pid;
        event.process.agent_visible.tgid = payload->agent_tgid;
    }
    if ((payload->flags & LifecycleKernelPid) != 0U) {
        event.process.kernel.pid = payload->kernel_pid;
        event.process.kernel.tgid = payload->kernel_tgid;
    }
    if ((payload->flags & LifecyclePidNamespace) != 0U) {
        event.process.agent_pid_namespace = ProcessNamespaceIdentity{
            payload->pid_namespace_device, payload->pid_namespace_inode};
    }
    if ((payload->flags & LifecycleUid) != 0U) event.process.uid = payload->uid;
    if ((payload->flags & LifecycleStartTicks) != 0U) event.process.start_ticks = payload->start_ticks;
    if ((payload->flags & LifecycleNetns) != 0U) {
        event.network_namespace_inode = payload->network_namespace_inode;
    }
    if ((payload->flags & LifecycleSocketCookie) != 0U) event.socket_cookie = payload->socket_cookie;
    if ((payload->flags & LifecyclePlatformConnectionId) != 0U) {
        event.platform_connection_id = payload->platform_connection_id;
    }
    if ((payload->flags & LifecycleTcpState) != 0U) event.tcp_state = payload->tcp_state;
    if ((payload->flags & LifecycleLocal) != 0U) {
        event.local = NetworkEndpoint{read_text(payload->local_address), std::nullopt};
        if ((payload->flags & LifecycleLocalPort) != 0U) event.local->port = payload->local_port;
    }
    if ((payload->flags & LifecycleRemote) != 0U) {
        event.remote = NetworkEndpoint{read_text(payload->remote_address), std::nullopt};
        if ((payload->flags & LifecycleRemotePort) != 0U) event.remote->port = payload->remote_port;
    }
    return event;
}

inline std::vector<std::byte> encode_process_exec(std::uint64_t sequence,
                                                  const ProcessExecEvent& event) {
    ProcessExecPayload payload;
    payload.event_type = static_cast<std::uint8_t>(event.type);
    payload.timestamp_ns = event.timestamp_ns;
    if (event.pid && event.tgid) {
        payload.flags |= ProcessPid;
        payload.pid = *event.pid;
        payload.tgid = *event.tgid;
    }
    if (event.parent_pid && event.parent_tgid) {
        payload.flags |= ProcessParent;
        payload.parent_pid = *event.parent_pid;
        payload.parent_tgid = *event.parent_tgid;
    }
    if (event.uid) { payload.flags |= ProcessUid; payload.uid = *event.uid; }
    if (event.gid) { payload.flags |= ProcessGid; payload.gid = *event.gid; }
    if (event.process_start_time_ns) {
        payload.flags |= ProcessStart;
        payload.process_start_time_ns = *event.process_start_time_ns;
    }
    if (event.platform_process_key) {
        payload.flags |= ProcessPlatformKey;
        payload.platform_process_key = *event.platform_process_key;
    }
    if (event.parent_process_start_time_ns) {
        payload.flags |= ProcessParentStart;
        payload.parent_process_start_time_ns = *event.parent_process_start_time_ns;
    }
    if (event.parent_platform_process_key) {
        payload.flags |= ProcessParentPlatformKey;
        payload.parent_platform_process_key = *event.parent_platform_process_key;
    }
    if (event.session_id) { payload.flags |= ProcessSession; payload.session_id = *event.session_id; }
    if (event.elevated) {
        payload.flags |= ProcessElevated;
        payload.elevated = *event.elevated ? 1U : 0U;
    }
    if (event.exit_code) { payload.flags |= ProcessExitCode; payload.exit_code = *event.exit_code; }
    if (event.cgroup_id) { payload.flags |= ProcessCgroup; payload.cgroup_id = *event.cgroup_id; }
    copy_text(payload.comm, event.comm);
    copy_text(payload.executable_path, event.executable_path);
    copy_text(payload.command_line, event.command_line);
    copy_text(payload.working_directory, event.working_directory);
    copy_text(payload.user_identity, event.user_identity);
    copy_text(payload.integrity_level, event.integrity_level);
    return make_frame(MessageType::ProcessExec, sequence, payload);
}

inline std::optional<ProcessExecEvent> decode_process_exec(std::span<const std::byte> bytes) {
    const auto payload = frame_payload<ProcessExecPayload>(bytes, MessageType::ProcessExec);
    if (!payload) return std::nullopt;
    ProcessExecEvent event;
    event.type = static_cast<ProcessExecEventType>(payload->event_type);
    event.timestamp_ns = payload->timestamp_ns;
    if ((payload->flags & ProcessPid) != 0U) { event.pid = payload->pid; event.tgid = payload->tgid; }
    if ((payload->flags & ProcessParent) != 0U) {
        event.parent_pid = payload->parent_pid;
        event.parent_tgid = payload->parent_tgid;
    }
    if ((payload->flags & ProcessUid) != 0U) event.uid = payload->uid;
    if ((payload->flags & ProcessGid) != 0U) event.gid = payload->gid;
    if ((payload->flags & ProcessStart) != 0U) event.process_start_time_ns = payload->process_start_time_ns;
    if ((payload->flags & ProcessPlatformKey) != 0U) event.platform_process_key = payload->platform_process_key;
    if ((payload->flags & ProcessParentStart) != 0U) {
        event.parent_process_start_time_ns = payload->parent_process_start_time_ns;
    }
    if ((payload->flags & ProcessParentPlatformKey) != 0U) {
        event.parent_platform_process_key = payload->parent_platform_process_key;
    }
    if ((payload->flags & ProcessSession) != 0U) event.session_id = payload->session_id;
    if ((payload->flags & ProcessElevated) != 0U) event.elevated = payload->elevated != 0U;
    if ((payload->flags & ProcessExitCode) != 0U) event.exit_code = payload->exit_code;
    if ((payload->flags & ProcessCgroup) != 0U) event.cgroup_id = payload->cgroup_id;
    event.comm = read_text(payload->comm);
    event.executable_path = read_text(payload->executable_path);
    event.command_line = read_text(payload->command_line);
    event.working_directory = read_text(payload->working_directory);
    event.user_identity = read_text(payload->user_identity);
    event.integrity_level = read_text(payload->integrity_level);
    return event;
}

template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity) : capacity_(std::max<std::size_t>(1, capacity)) {}

    void push(T value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= capacity_) {
            queue_.pop_front();
            ++dropped_;
        }
        queue_.push_back(std::move(value));
        cv_.notify_one();
    }

    std::optional<T> pop_for(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!cv_.wait_for(lock, timeout, [this] { return !queue_.empty(); })) return std::nullopt;
        T value = std::move(queue_.front());
        queue_.pop_front();
        return value;
    }

    [[nodiscard]] std::uint64_t dropped() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return dropped_;
    }

private:
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<T> queue_;
    std::uint64_t dropped_{0};
};

class EventRouter {
public:
    explicit EventRouter(std::size_t queue_capacity = 1024) : queue_capacity_(queue_capacity) {}

    void register_endpoint(std::string slot, std::uint64_t netns_inode, std::uint64_t cgroup_id) {
        if (slot.empty()) throw std::runtime_error("broker endpoint slot cannot be empty");
        std::lock_guard<std::mutex> lock(mutex_);
        if (queues_.contains(slot)) throw std::runtime_error("duplicate broker endpoint slot: " + slot);
        if (netns_inode != 0 && netns_to_slot_.contains(netns_inode)) {
            throw std::runtime_error("duplicate broker network namespace mapping");
        }
        if (cgroup_id != 0 && cgroup_to_slot_.contains(cgroup_id)) {
            throw std::runtime_error("duplicate broker cgroup mapping");
        }
        auto queues = std::make_shared<EndpointQueues>(queue_capacity_);
        queues_.emplace(slot, std::move(queues));
        if (netns_inode != 0) netns_to_slot_.emplace(netns_inode, slot);
        if (cgroup_id != 0) cgroup_to_slot_.emplace(cgroup_id, slot);
    }

    [[nodiscard]] bool has_endpoint(const std::string& slot) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queues_.contains(slot);
    }

    bool route(const ConnectionLifecycleEvent& event, std::uint64_t sequence) {
        if (!event.network_namespace_inode) { ++unroutable_; return false; }
        const auto slot = slot_for_netns(*event.network_namespace_inode);
        if (!slot) { ++unroutable_; return false; }
        queue_for(*slot, EventKind::Lifecycle)->push(encode_lifecycle(sequence, event));
        return true;
    }

    bool route(const ProcessExecEvent& event, std::uint64_t sequence) {
        if (!event.cgroup_id) { ++unroutable_; return false; }
        const auto slot = slot_for_cgroup(*event.cgroup_id);
        if (!slot) { ++unroutable_; return false; }
        queue_for(*slot, EventKind::ProcessExec)->push(encode_process_exec(sequence, event));
        return true;
    }

    std::optional<std::vector<std::byte>> take(const std::string& slot, EventKind kind,
                                               std::chrono::milliseconds timeout) {
        const auto queue = queue_for(slot, kind);
        return queue ? queue->pop_for(timeout) : std::nullopt;
    }

    [[nodiscard]] std::uint64_t dropped(const std::string& slot, EventKind kind) const {
        const auto queue = queue_for_const(slot, kind);
        return queue ? queue->dropped() : 0;
    }

    [[nodiscard]] std::uint64_t unroutable() const noexcept { return unroutable_.load(); }

private:
    struct EndpointQueues {
        explicit EndpointQueues(std::size_t capacity) : lifecycle(capacity), process_exec(capacity) {}
        BoundedQueue<std::vector<std::byte>> lifecycle;
        BoundedQueue<std::vector<std::byte>> process_exec;
    };

    std::optional<std::string> slot_for_netns(std::uint64_t value) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = netns_to_slot_.find(value);
        return it == netns_to_slot_.end() ? std::nullopt : std::optional<std::string>(it->second);
    }

    std::optional<std::string> slot_for_cgroup(std::uint64_t value) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = cgroup_to_slot_.find(value);
        return it == cgroup_to_slot_.end() ? std::nullopt : std::optional<std::string>(it->second);
    }

    std::shared_ptr<BoundedQueue<std::vector<std::byte>>> queue_for(const std::string& slot,
                                                                    EventKind kind) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = queues_.find(slot);
        if (it == queues_.end()) return {};
        return kind == EventKind::Lifecycle
            ? std::shared_ptr<BoundedQueue<std::vector<std::byte>>>(it->second, &it->second->lifecycle)
            : std::shared_ptr<BoundedQueue<std::vector<std::byte>>>(it->second, &it->second->process_exec);
    }

    std::shared_ptr<const BoundedQueue<std::vector<std::byte>>> queue_for_const(
        const std::string& slot, EventKind kind) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = queues_.find(slot);
        if (it == queues_.end()) return {};
        return kind == EventKind::Lifecycle
            ? std::shared_ptr<const BoundedQueue<std::vector<std::byte>>>(it->second, &it->second->lifecycle)
            : std::shared_ptr<const BoundedQueue<std::vector<std::byte>>>(it->second, &it->second->process_exec);
    }

    std::size_t queue_capacity_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<EndpointQueues>> queues_;
    std::unordered_map<std::uint64_t, std::string> netns_to_slot_;
    std::unordered_map<std::uint64_t, std::string> cgroup_to_slot_;
    std::atomic<std::uint64_t> unroutable_{0};
};

class BrokerClient {
public:
    BrokerClient(std::string path, std::string slot, EventKind kind) {
        fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (fd_ < 0) throw std::runtime_error("creating sensor-broker socket failed: " + std::string(std::strerror(errno)));
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        if (path.size() >= sizeof(address.sun_path)) {
            close_fd();
            throw std::runtime_error("sensor-broker socket path is too long");
        }
        std::memcpy(address.sun_path, path.c_str(), path.size() + 1U);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            const auto error = std::string(std::strerror(errno));
            close_fd();
            throw std::runtime_error("connecting to sensor broker failed: " + error);
        }
        const auto registration = encode_registration(slot, kind);
        const auto sent = ::send(fd_, registration.data(), registration.size(), MSG_NOSIGNAL);
        if (sent < 0 || static_cast<std::size_t>(sent) != registration.size()) {
            close_fd();
            throw std::runtime_error("registering with sensor broker failed");
        }
    }

    ~BrokerClient() { close_fd(); }
    BrokerClient(const BrokerClient&) = delete;
    BrokerClient& operator=(const BrokerClient&) = delete;

    std::optional<std::vector<std::byte>> receive(std::chrono::milliseconds timeout) {
        pollfd descriptor{fd_, POLLIN, 0};
        const auto bounded = std::clamp<std::int64_t>(timeout.count(), 0,
            static_cast<std::int64_t>(std::numeric_limits<int>::max()));
        const int result = ::poll(&descriptor, 1, static_cast<int>(bounded));
        if (result == 0) return std::nullopt;
        if (result < 0) {
            if (errno == EINTR) return std::nullopt;
            throw std::runtime_error("polling sensor broker failed: " + std::string(std::strerror(errno)));
        }
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            throw std::runtime_error("sensor-broker connection closed");
        }
        std::array<std::byte, kMaxFrameSize + sizeof(FrameHeader)> buffer{};
        const auto received = ::recv(fd_, buffer.data(), buffer.size(), 0);
        if (received <= 0) throw std::runtime_error("sensor-broker connection closed");
        return std::vector<std::byte>(buffer.begin(), buffer.begin() + received);
    }

private:
    void close_fd() noexcept { if (fd_ >= 0) ::close(std::exchange(fd_, -1)); }
    int fd_{-1};
};

class BrokerLifecycleObserver final : public LifecycleObserver {
public:
    BrokerLifecycleObserver() {
        capability_.built_in = true;
        capability_.source = "broker:linux-ebpf-lifecycle";
        try {
            client_ = std::make_unique<BrokerClient>(configured_socket_path(), configured_endpoint_slot(),
                                                     EventKind::Lifecycle);
            capability_.connect_events = true;
            capability_.accept_events = true;
            capability_.close_events = true;
        } catch (const std::exception& error) {
            capability_.unavailable_reason = error.what();
        }
    }
    const LifecycleCapability& capability() const noexcept override { return capability_; }
    LifecycleHealth health() const override { return {}; }
    std::vector<ConnectionLifecycleEvent> poll(std::chrono::milliseconds timeout) override {
        std::vector<ConnectionLifecycleEvent> events;
        if (!client_) return events;
        auto frame = client_->receive(timeout);
        if (!frame) return events;
        if (auto event = decode_lifecycle(*frame)) events.push_back(std::move(*event));
        return events;
    }
private:
    LifecycleCapability capability_;
    std::unique_ptr<BrokerClient> client_;
};

class BrokerProcessExecObserver final : public ProcessExecObserver {
public:
    BrokerProcessExecObserver() {
        capability_.built_in = true;
        capability_.source = "broker:linux-ebpf-process";
        try {
            client_ = std::make_unique<BrokerClient>(configured_socket_path(), configured_endpoint_slot(),
                                                     EventKind::ProcessExec);
            capability_.exec_events = true;
            capability_.exit_events = true;
            capability_.parent_identity = true;
            capability_.command_line = true;
            capability_.working_directory = true;
            capability_.security_identity = true;
            capability_.session_identity = true;
        } catch (const std::exception& error) {
            capability_.unavailable_reason = error.what();
        }
    }
    const ProcessExecCapability& capability() const noexcept override { return capability_; }
    ProcessExecHealth health() const override { return {}; }
    std::vector<ProcessExecEvent> poll(std::chrono::milliseconds timeout) override {
        std::vector<ProcessExecEvent> events;
        if (!client_) return events;
        auto frame = client_->receive(timeout);
        if (!frame) return events;
        if (auto event = decode_process_exec(*frame)) events.push_back(std::move(*event));
        return events;
    }
private:
    ProcessExecCapability capability_;
    std::unique_ptr<BrokerClient> client_;
};

class BrokerNameResolutionUnavailable final : public NameResolutionObserver {
public:
    BrokerNameResolutionUnavailable() {
        capability_.source = "broker:phase1";
        capability_.unavailable_reason =
            "name-resolution broker multiplexing is not part of large-scale simulator Phase 1";
    }
    const NameResolutionCapability& capability() const noexcept override { return capability_; }
    NameResolutionHealth health() const override { return {}; }
    std::vector<NameResolutionObservation> poll(std::chrono::milliseconds) override { return {}; }
private:
    NameResolutionCapability capability_;
};

inline std::unique_ptr<LifecycleObserver> make_broker_lifecycle_observer() {
    return std::make_unique<BrokerLifecycleObserver>();
}
inline std::unique_ptr<ProcessExecObserver> make_broker_process_exec_observer() {
    return std::make_unique<BrokerProcessExecObserver>();
}
inline std::unique_ptr<NameResolutionObserver> make_broker_name_resolution_observer() {
    return std::make_unique<BrokerNameResolutionUnavailable>();
}

inline std::atomic_bool g_stop_requested{false};
inline void stop_signal_handler(int) { g_stop_requested.store(true); }

struct EndpointMapping {
    std::string slot;
    std::uint64_t netns_inode{0};
    std::uint64_t cgroup_id{0};
};

inline EndpointMapping parse_mapping(std::string_view value) {
    const auto first = value.find(':');
    const auto second = first == std::string_view::npos ? std::string_view::npos : value.find(':', first + 1U);
    if (first == std::string_view::npos || second == std::string_view::npos || value.find(':', second + 1U) != std::string_view::npos) {
        throw std::runtime_error("--map must be SLOT:NETNS_INODE:CGROUP_ID");
    }
    EndpointMapping result;
    result.slot = std::string(value.substr(0, first));
    try {
        result.netns_inode = std::stoull(std::string(value.substr(first + 1U, second - first - 1U)));
        result.cgroup_id = std::stoull(std::string(value.substr(second + 1U)));
    } catch (...) {
        throw std::runtime_error("--map namespace and cgroup values must be unsigned integers");
    }
    if (result.slot.empty() || result.slot.size() >= kSlotLength || result.netns_inode == 0 || result.cgroup_id == 0) {
        throw std::runtime_error("--map requires a non-empty slot and non-zero namespace/cgroup identifiers");
    }
    return result;
}

inline void handle_client(int fd, const std::shared_ptr<EventRouter>& router) {
    std::array<std::byte, kMaxFrameSize + sizeof(FrameHeader)> buffer{};
    const auto received = ::recv(fd, buffer.data(), buffer.size(), 0);
    if (received <= 0) { ::close(fd); return; }
    const auto registration = decode_registration(std::span<const std::byte>(buffer.data(),
        static_cast<std::size_t>(received)));
    if (!registration || !router->has_endpoint(registration->endpoint_slot)) {
        ::close(fd);
        return;
    }
    while (!g_stop_requested.load()) {
        auto frame = router->take(registration->endpoint_slot, registration->event_kind,
                                  std::chrono::milliseconds(500));
        if (!frame) continue;
        const auto sent = ::send(fd, frame->data(), frame->size(), MSG_NOSIGNAL);
        if (sent < 0 || static_cast<std::size_t>(sent) != frame->size()) break;
    }
    ::close(fd);
}

inline int run_linux_sensor_broker(int argc, char** argv) {
    std::string socket_path = "/run/neta/sensor-broker.sock";
    std::size_t queue_capacity = 1024;
    std::vector<EndpointMapping> mappings;
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--socket" && i + 1 < argc) socket_path = argv[++i];
        else if (arg == "--queue-capacity" && i + 1 < argc) queue_capacity = std::stoull(argv[++i]);
        else if (arg == "--map" && i + 1 < argc) mappings.push_back(parse_mapping(argv[++i]));
        else if (arg == "--help") {
            std::cout << "Usage: neta-agent sensor-broker [--socket PATH] [--queue-capacity N] "
                         "--map SLOT:NETNS_INODE:CGROUP_ID [--map ...]\n";
            return 0;
        } else {
            throw std::runtime_error("unknown sensor-broker argument: " + arg);
        }
    }
    if (mappings.empty()) throw std::runtime_error("sensor-broker requires at least one --map");

    ::unsetenv("NETA_SENSOR_MODE");
    ::unsetenv("NETA_SENSOR_BROKER");
    ::unsetenv("NETA_ENDPOINT_SLOT");

    auto lifecycle = platform::make_lifecycle_observer();
    auto process_exec = platform::make_process_exec_observer();
    if (!lifecycle->capability().available()) {
        throw std::runtime_error("native lifecycle sensor is unavailable: " + lifecycle->capability().unavailable_reason);
    }
    if (!process_exec->capability().available()) {
        throw std::runtime_error("native process-exec sensor is unavailable: " + process_exec->capability().unavailable_reason);
    }

    auto router = std::make_shared<EventRouter>(queue_capacity);
    for (const auto& mapping : mappings) {
        router->register_endpoint(mapping.slot, mapping.netns_inode, mapping.cgroup_id);
    }

    g_stop_requested.store(false);
    ::signal(SIGINT, stop_signal_handler);
    ::signal(SIGTERM, stop_signal_handler);

    std::error_code error;
    const auto parent = std::filesystem::path(socket_path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, error);
    if (error) throw std::runtime_error("creating sensor-broker socket directory failed: " + error.message());
    std::filesystem::remove(socket_path, error);
    error.clear();

    const int server_fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (server_fd < 0) throw std::runtime_error("creating sensor-broker listener failed: " + std::string(std::strerror(errno)));
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(address.sun_path)) { ::close(server_fd); throw std::runtime_error("sensor-broker socket path is too long"); }
    std::memcpy(address.sun_path, socket_path.c_str(), socket_path.size() + 1U);
    if (::bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || ::listen(server_fd, 128) != 0) {
        const auto message = std::string(std::strerror(errno));
        ::close(server_fd);
        throw std::runtime_error("starting sensor-broker listener failed: " + message);
    }

    std::atomic<std::uint64_t> sequence{1};
    std::thread lifecycle_thread([&] {
        while (!g_stop_requested.load()) {
            for (const auto& event : lifecycle->poll(std::chrono::milliseconds(100))) {
                router->route(event, sequence.fetch_add(1));
            }
        }
    });
    std::thread process_thread([&] {
        while (!g_stop_requested.load()) {
            for (const auto& event : process_exec->poll(std::chrono::milliseconds(100))) {
                router->route(event, sequence.fetch_add(1));
            }
        }
    });

    std::cout << "NETA sensor broker listening on " << socket_path << " for " << mappings.size()
              << " endpoint mapping(s)\n";
    while (!g_stop_requested.load()) {
        pollfd descriptor{server_fd, POLLIN, 0};
        const int result = ::poll(&descriptor, 1, 500);
        if (result <= 0) continue;
        const int client = ::accept4(server_fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (client >= 0) std::thread(handle_client, client, router).detach();
    }

    ::close(server_fd);
    lifecycle_thread.join();
    process_thread.join();
    std::filesystem::remove(socket_path, error);
    std::cout << "NETA sensor broker stopped; unroutable events=" << router->unroutable() << '\n';
    return 0;
}

} // namespace neta::sensor_broker

#endif // !_WIN32
