#include "sensor_broker_protocol.hpp"

#ifdef _WIN32

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace neta::windows_sensor_broker::protocol {
namespace {

constexpr std::uint32_t kMagic = 0x4e534233U;  // NSB3
constexpr std::uint16_t kVersion = 1;
constexpr std::size_t kSlotLength = 64;
constexpr std::size_t kAddressLength = 64;
constexpr std::size_t kCommLength = 64;
constexpr std::size_t kPathLength = 512;
constexpr std::size_t kCommandLineLength = 1024;
constexpr std::size_t kWorkingDirectoryLength = 512;
constexpr std::size_t kIdentityLength = 192;
constexpr std::size_t kIntegrityLength = 64;

#pragma pack(push, 1)
struct FrameHeader {
    std::uint32_t magic{kMagic};
    std::uint16_t version{kVersion};
    std::uint16_t type{0};
    std::uint64_t sequence{0};
    std::uint32_t payload_size{0};
    std::uint32_t reserved{0};
};

struct RegistrationPayload {
    std::uint16_t event_kind{static_cast<std::uint16_t>(EventKind::All)};
    std::uint16_t reserved{0};
    char endpoint_slot[kSlotLength]{};
};

enum LifecycleFlags : std::uint32_t {
    LifecycleAgentPid = 1U << 0,
    LifecycleKernelPid = 1U << 1,
    LifecycleUid = 1U << 2,
    LifecycleStartTicks = 1U << 3,
    LifecycleLocal = 1U << 4,
    LifecycleLocalPort = 1U << 5,
    LifecycleRemote = 1U << 6,
    LifecycleRemotePort = 1U << 7,
    LifecyclePlatformConnectionId = 1U << 8,
    LifecycleTcpState = 1U << 9,
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
    std::uint32_t uid{0};
    std::uint32_t reserved2{0};
    std::uint64_t start_ticks{0};
    std::uint64_t platform_connection_id{0};
    std::uint16_t local_port{0};
    std::uint16_t remote_port{0};
    char comm[kCommLength]{};
    char local_address[kAddressLength]{};
    char remote_address[kAddressLength]{};
};

enum ProcessFlags : std::uint32_t {
    ProcessPid = 1U << 0,
    ProcessParentPid = 1U << 1,
    ProcessUid = 1U << 2,
    ProcessGid = 1U << 3,
    ProcessStart = 1U << 4,
    ProcessKey = 1U << 5,
    ProcessParentStart = 1U << 6,
    ProcessParentKey = 1U << 7,
    ProcessSession = 1U << 8,
    ProcessElevated = 1U << 9,
    ProcessExitCode = 1U << 10,
};

struct ProcessPayload {
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
    char comm[kCommLength]{};
    char executable_path[kPathLength]{};
    char command_line[kCommandLineLength]{};
    char working_directory[kWorkingDirectoryLength]{};
    char user_identity[kIdentityLength]{};
    char integrity_level[kIntegrityLength]{};
};
#pragma pack(pop)

static_assert(sizeof(FrameHeader) == 24);
static_assert(sizeof(FrameHeader) + sizeof(ProcessPayload) <= kMaximumFrameSize);

template <std::size_t N>
void copy_text(char (&target)[N], std::string_view value) {
    static_assert(N > 0);
    std::memset(target, 0, N);
    const auto count = std::min(value.size(), N - 1U);
    if (count != 0) std::memcpy(target, value.data(), count);
}

template <std::size_t N>
std::string read_text(const char (&value)[N]) {
    std::size_t length = 0;
    while (length < N && value[length] != '\0') ++length;
    return std::string(value, length);
}

template <typename Payload>
std::vector<std::byte> make_frame(MessageType type, std::uint64_t sequence,
                                  const Payload& payload) {
    FrameHeader header;
    header.type = static_cast<std::uint16_t>(type);
    header.sequence = sequence;
    header.payload_size = static_cast<std::uint32_t>(sizeof(Payload));
    std::vector<std::byte> frame(sizeof(FrameHeader) + sizeof(Payload));
    std::memcpy(frame.data(), &header, sizeof(header));
    std::memcpy(frame.data() + sizeof(header), &payload, sizeof(payload));
    return frame;
}

std::optional<FrameHeader> decode_header(std::span<const std::byte> frame) {
    if (frame.size() < sizeof(FrameHeader)) return std::nullopt;
    FrameHeader header{};
    std::memcpy(&header, frame.data(), sizeof(header));
    if (header.magic != kMagic || header.version != kVersion) return std::nullopt;
    if (header.payload_size > kMaximumFrameSize) return std::nullopt;
    if (frame.size() != sizeof(FrameHeader) + static_cast<std::size_t>(header.payload_size)) {
        return std::nullopt;
    }
    return header;
}

template <typename Payload>
std::optional<Payload> decode_payload(std::span<const std::byte> frame, MessageType type) {
    const auto header = decode_header(frame);
    if (!header || header->type != static_cast<std::uint16_t>(type) ||
        header->payload_size != sizeof(Payload)) {
        return std::nullopt;
    }
    Payload payload{};
    std::memcpy(&payload, frame.data() + sizeof(FrameHeader), sizeof(payload));
    return payload;
}

std::uint8_t lifecycle_type(ConnectionLifecycleEventType type) {
    switch (type) {
        case ConnectionLifecycleEventType::Connect: return 1;
        case ConnectionLifecycleEventType::Accept: return 2;
        case ConnectionLifecycleEventType::Close: return 3;
    }
    return 0;
}

std::optional<ConnectionLifecycleEventType> lifecycle_type(std::uint8_t value) {
    if (value == 1) return ConnectionLifecycleEventType::Connect;
    if (value == 2) return ConnectionLifecycleEventType::Accept;
    if (value == 3) return ConnectionLifecycleEventType::Close;
    return std::nullopt;
}

}  // namespace

std::vector<std::byte> encode_registration(const Registration& registration) {
    if (registration.endpoint_slot.empty() || registration.endpoint_slot.size() >= kSlotLength) {
        throw std::runtime_error("Windows sensor-broker endpoint slot must contain 1-63 bytes");
    }
    RegistrationPayload payload;
    copy_text(payload.endpoint_slot, registration.endpoint_slot);
    return make_frame(MessageType::Register, 0, payload);
}

std::optional<Registration> decode_registration(std::span<const std::byte> frame) {
    const auto payload = decode_payload<RegistrationPayload>(frame, MessageType::Register);
    if (!payload || payload->event_kind != static_cast<std::uint16_t>(EventKind::All)) {
        return std::nullopt;
    }
    const auto slot = read_text(payload->endpoint_slot);
    if (slot.empty()) return std::nullopt;
    return Registration{slot};
}

std::vector<std::byte> encode_lifecycle(const ConnectionLifecycleEvent& event,
                                        std::uint64_t sequence) {
    LifecyclePayload payload;
    payload.event_type = lifecycle_type(event.type);
    payload.provenance = static_cast<std::uint8_t>(event.provenance);
    payload.address_family = static_cast<std::uint8_t>(event.address_family);
    payload.protocol = static_cast<std::uint8_t>(event.protocol);
    payload.endpoint_kind = static_cast<std::uint8_t>(event.endpoint_kind);
    payload.timestamp_ns = event.timestamp_ns;

    if (event.process.agent_visible.pid) {
        payload.flags |= LifecycleAgentPid;
        payload.agent_pid = *event.process.agent_visible.pid;
        payload.agent_tgid = event.process.agent_visible.tgid.value_or(payload.agent_pid);
    }
    if (event.process.kernel.pid) {
        payload.flags |= LifecycleKernelPid;
        payload.kernel_pid = *event.process.kernel.pid;
        payload.kernel_tgid = event.process.kernel.tgid.value_or(payload.kernel_pid);
    }
    if (event.process.uid) { payload.flags |= LifecycleUid; payload.uid = *event.process.uid; }
    if (event.process.start_ticks) { payload.flags |= LifecycleStartTicks; payload.start_ticks = *event.process.start_ticks; }
    if (event.process.comm) copy_text(payload.comm, *event.process.comm);
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
    if (event.platform_connection_id) {
        payload.flags |= LifecyclePlatformConnectionId;
        payload.platform_connection_id = *event.platform_connection_id;
    }
    if (event.tcp_state) {
        payload.flags |= LifecycleTcpState;
        payload.tcp_state = *event.tcp_state;
    }
    return make_frame(MessageType::Lifecycle, sequence, payload);
}

std::optional<ConnectionLifecycleEvent> decode_lifecycle(std::span<const std::byte> frame) {
    const auto payload = decode_payload<LifecyclePayload>(frame, MessageType::Lifecycle);
    if (!payload) return std::nullopt;
    const auto type = lifecycle_type(payload->event_type);
    if (!type) return std::nullopt;

    ConnectionLifecycleEvent event;
    event.type = *type;
    event.timestamp_ns = payload->timestamp_ns;
    event.provenance = static_cast<LifecycleProvenance>(payload->provenance);
    event.address_family = static_cast<NetworkAddressFamily>(payload->address_family);
    event.protocol = static_cast<TransportProtocol>(payload->protocol);
    event.endpoint_kind = static_cast<TcpEndpointKind>(payload->endpoint_kind);

    if ((payload->flags & LifecycleAgentPid) != 0U) {
        event.process.agent_visible.pid = payload->agent_pid;
        event.process.agent_visible.tgid = payload->agent_tgid;
    }
    if ((payload->flags & LifecycleKernelPid) != 0U) {
        event.process.kernel.pid = payload->kernel_pid;
        event.process.kernel.tgid = payload->kernel_tgid;
    }
    if ((payload->flags & LifecycleUid) != 0U) event.process.uid = payload->uid;
    if ((payload->flags & LifecycleStartTicks) != 0U) event.process.start_ticks = payload->start_ticks;
    const auto comm = read_text(payload->comm);
    if (!comm.empty()) event.process.comm = comm;
    if ((payload->flags & LifecycleLocal) != 0U) {
        NetworkEndpoint endpoint{read_text(payload->local_address), std::nullopt};
        if ((payload->flags & LifecycleLocalPort) != 0U) endpoint.port = payload->local_port;
        event.local = std::move(endpoint);
    }
    if ((payload->flags & LifecycleRemote) != 0U) {
        NetworkEndpoint endpoint{read_text(payload->remote_address), std::nullopt};
        if ((payload->flags & LifecycleRemotePort) != 0U) endpoint.port = payload->remote_port;
        event.remote = std::move(endpoint);
    }
    if ((payload->flags & LifecyclePlatformConnectionId) != 0U) {
        event.platform_connection_id = payload->platform_connection_id;
    }
    if ((payload->flags & LifecycleTcpState) != 0U) event.tcp_state = payload->tcp_state;
    return event;
}

std::vector<std::byte> encode_process_exec(const ProcessExecEvent& event,
                                            std::uint64_t sequence) {
    ProcessPayload payload;
    payload.event_type = event.type == ProcessExecEventType::Start ? 1U : 2U;
    payload.timestamp_ns = event.timestamp_ns;
    if (event.pid) {
        payload.flags |= ProcessPid;
        payload.pid = *event.pid;
        payload.tgid = event.tgid.value_or(payload.pid);
    }
    if (event.parent_pid) {
        payload.flags |= ProcessParentPid;
        payload.parent_pid = *event.parent_pid;
        payload.parent_tgid = event.parent_tgid.value_or(payload.parent_pid);
    }
    if (event.uid) { payload.flags |= ProcessUid; payload.uid = *event.uid; }
    if (event.gid) { payload.flags |= ProcessGid; payload.gid = *event.gid; }
    if (event.process_start_time_ns) {
        payload.flags |= ProcessStart;
        payload.process_start_time_ns = *event.process_start_time_ns;
    }
    if (event.platform_process_key) {
        payload.flags |= ProcessKey;
        payload.platform_process_key = *event.platform_process_key;
    }
    if (event.parent_process_start_time_ns) {
        payload.flags |= ProcessParentStart;
        payload.parent_process_start_time_ns = *event.parent_process_start_time_ns;
    }
    if (event.parent_platform_process_key) {
        payload.flags |= ProcessParentKey;
        payload.parent_platform_process_key = *event.parent_platform_process_key;
    }
    if (event.session_id) { payload.flags |= ProcessSession; payload.session_id = *event.session_id; }
    if (event.elevated) {
        payload.flags |= ProcessElevated;
        payload.elevated = *event.elevated ? 1U : 0U;
    }
    if (event.exit_code) { payload.flags |= ProcessExitCode; payload.exit_code = *event.exit_code; }
    copy_text(payload.comm, event.comm);
    copy_text(payload.executable_path, event.executable_path);
    copy_text(payload.command_line, event.command_line);
    copy_text(payload.working_directory, event.working_directory);
    copy_text(payload.user_identity, event.user_identity);
    copy_text(payload.integrity_level, event.integrity_level);
    return make_frame(MessageType::ProcessExec, sequence, payload);
}

std::optional<ProcessExecEvent> decode_process_exec(std::span<const std::byte> frame) {
    const auto payload = decode_payload<ProcessPayload>(frame, MessageType::ProcessExec);
    if (!payload || (payload->event_type != 1U && payload->event_type != 2U)) return std::nullopt;
    ProcessExecEvent event;
    event.type = payload->event_type == 1U ? ProcessExecEventType::Start : ProcessExecEventType::Exit;
    event.timestamp_ns = payload->timestamp_ns;
    if ((payload->flags & ProcessPid) != 0U) { event.pid = payload->pid; event.tgid = payload->tgid; }
    if ((payload->flags & ProcessParentPid) != 0U) {
        event.parent_pid = payload->parent_pid;
        event.parent_tgid = payload->parent_tgid;
    }
    if ((payload->flags & ProcessUid) != 0U) event.uid = payload->uid;
    if ((payload->flags & ProcessGid) != 0U) event.gid = payload->gid;
    if ((payload->flags & ProcessStart) != 0U) event.process_start_time_ns = payload->process_start_time_ns;
    if ((payload->flags & ProcessKey) != 0U) event.platform_process_key = payload->platform_process_key;
    if ((payload->flags & ProcessParentStart) != 0U) event.parent_process_start_time_ns = payload->parent_process_start_time_ns;
    if ((payload->flags & ProcessParentKey) != 0U) event.parent_platform_process_key = payload->parent_platform_process_key;
    if ((payload->flags & ProcessSession) != 0U) event.session_id = payload->session_id;
    if ((payload->flags & ProcessElevated) != 0U) event.elevated = payload->elevated != 0U;
    if ((payload->flags & ProcessExitCode) != 0U) event.exit_code = payload->exit_code;
    event.comm = read_text(payload->comm);
    event.executable_path = read_text(payload->executable_path);
    event.command_line = read_text(payload->command_line);
    event.working_directory = read_text(payload->working_directory);
    event.user_identity = read_text(payload->user_identity);
    event.integrity_level = read_text(payload->integrity_level);
    return event;
}

std::optional<MessageType> message_type(std::span<const std::byte> frame) {
    const auto header = decode_header(frame);
    if (!header) return std::nullopt;
    switch (static_cast<MessageType>(header->type)) {
        case MessageType::Register:
        case MessageType::Lifecycle:
        case MessageType::ProcessExec:
            return static_cast<MessageType>(header->type);
    }
    return std::nullopt;
}

}  // namespace neta::windows_sensor_broker::protocol

#endif
