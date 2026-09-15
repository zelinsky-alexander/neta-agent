#pragma once

#ifdef _WIN32

#include "neta/lifecycle.hpp"
#include "neta/process_exec.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace neta::windows_sensor_broker::protocol {

enum class MessageType : std::uint16_t {
    Register = 1,
    Lifecycle = 2,
    ProcessExec = 3,
};

enum class EventKind : std::uint16_t {
    All = 1,
};

struct Registration {
    std::string endpoint_slot;
};

constexpr std::size_t kMaximumFrameSize = 8192;

std::vector<std::byte> encode_registration(const Registration& registration);
std::optional<Registration> decode_registration(std::span<const std::byte> frame);

std::vector<std::byte> encode_lifecycle(const ConnectionLifecycleEvent& event,
                                        std::uint64_t sequence);
std::optional<ConnectionLifecycleEvent> decode_lifecycle(std::span<const std::byte> frame);

std::vector<std::byte> encode_process_exec(const ProcessExecEvent& event,
                                           std::uint64_t sequence);
std::optional<ProcessExecEvent> decode_process_exec(std::span<const std::byte> frame);

std::optional<MessageType> message_type(std::span<const std::byte> frame);

}  // namespace neta::windows_sensor_broker::protocol

#endif
