#include "sensor_broker_pipe.hpp"
#include "sensor_broker_protocol.hpp"

#ifdef _WIN32

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>
#include <stdexcept>
#include <thread>
#include <utility>

namespace neta::windows_sensor_broker {

std::wstring normalize_pipe_name(const std::wstring& configured) {
    constexpr std::wstring_view prefix = LR"(\\.\pipe\)";
    if (configured.starts_with(prefix)) return configured;
    if (configured.empty()) return std::wstring(prefix) + L"neta-sensor-broker";
    return std::wstring(prefix) + configured;
}

HANDLE connect_named_pipe_client(const std::wstring& pipe_name,
                                 std::chrono::milliseconds timeout) {
    const auto normalized = normalize_pipe_name(pipe_name);
    const DWORD bounded = timeout.count() <= 0
        ? 0U
        : static_cast<DWORD>((std::min)(timeout.count(),
            static_cast<long long>((std::numeric_limits<DWORD>::max)())));
    if (WaitNamedPipeW(normalized.c_str(), bounded) == FALSE) {
        throw std::runtime_error("waiting for Windows sensor-broker named pipe failed with error " +
                                 std::to_string(GetLastError()));
    }
    HANDLE pipe = CreateFileW(normalized.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("opening Windows sensor-broker named pipe failed with error " +
                                 std::to_string(GetLastError()));
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr) == FALSE) {
        const DWORD error = GetLastError();
        CloseHandle(pipe);
        throw std::runtime_error("configuring Windows sensor-broker named pipe failed with error " +
                                 std::to_string(error));
    }
    return pipe;
}

bool write_pipe_message(HANDLE pipe, std::span<const std::byte> message) {
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE || message.empty()) return false;
    DWORD written = 0;
    const BOOL ok = WriteFile(pipe, message.data(), static_cast<DWORD>(message.size()), &written, nullptr);
    return ok != FALSE && written == message.size();
}

std::optional<std::vector<std::byte>> read_pipe_message(HANDLE pipe,
                                                        std::chrono::milliseconds timeout) {
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE) return std::nullopt;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        DWORD available = 0;
        if (PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) == FALSE) {
            throw std::runtime_error("peeking Windows sensor-broker pipe failed with error " +
                                     std::to_string(GetLastError()));
        }
        if (available != 0) {
            if (available > protocol::kMaximumFrameSize) {
                throw std::runtime_error("Windows sensor-broker frame exceeds protocol maximum");
            }
            std::vector<std::byte> frame(available);
            DWORD read = 0;
            if (ReadFile(pipe, frame.data(), available, &read, nullptr) == FALSE || read != available) {
                throw std::runtime_error("reading Windows sensor-broker pipe failed with error " +
                                         std::to_string(GetLastError()));
            }
            return frame;
        }
        if (timeout.count() <= 0 || std::chrono::steady_clock::now() >= deadline) return std::nullopt;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

void close_pipe(HANDLE& pipe) noexcept {
    if (pipe != nullptr && pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    pipe = INVALID_HANDLE_VALUE;
}

}  // namespace neta::windows_sensor_broker

#endif
