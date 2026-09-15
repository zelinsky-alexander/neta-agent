#include "neta/platform.hpp"
#include "neta/windows_sensor_broker.hpp"
#include "sensor_broker_native.hpp"
#include "sensor_broker_pipe.hpp"
#include "sensor_broker_process_registry.hpp"
#include "sensor_broker_protocol.hpp"
#include "sensor_broker_router.hpp"

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace neta::windows_sensor_broker {
namespace {

struct EndpointMapping {
    std::string slot;
    std::uint32_t root_pid{0};
};

std::atomic_bool stop_requested{false};

BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT ||
        signal == CTRL_SHUTDOWN_EVENT) {
        stop_requested.store(true, std::memory_order_relaxed);
        return TRUE;
    }
    return FALSE;
}

EndpointMapping parse_mapping(std::string_view value) {
    const auto separator = value.rfind(':');
    if (separator == std::string_view::npos || separator == 0 || separator + 1 >= value.size()) {
        throw std::runtime_error("--map must be SLOT:ROOT_PID");
    }
    EndpointMapping mapping;
    mapping.slot = std::string(value.substr(0, separator));
    try {
        const auto parsed = std::stoull(std::string(value.substr(separator + 1)));
        if (parsed == 0 || parsed > (std::numeric_limits<std::uint32_t>::max)()) {
            throw std::out_of_range("root PID");
        }
        mapping.root_pid = static_cast<std::uint32_t>(parsed);
    } catch (...) {
        throw std::runtime_error("--map root PID must be an integer in 1..4294967295");
    }
    if (mapping.slot.size() >= 64) throw std::runtime_error("--map slot must contain 1-63 bytes");
    return mapping;
}

std::wstring utf8_to_wide(const std::string& text) {
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0) throw std::runtime_error("named-pipe value is not valid UTF-8");
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), result.data(), required) <= 0) {
        throw std::runtime_error("named-pipe value is not valid UTF-8");
    }
    return result;
}

HANDLE create_pipe_instance(const std::wstring& pipe_name) {
    const auto normalized = normalize_pipe_name(pipe_name);
    HANDLE pipe = CreateNamedPipeW(
        normalized.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES,
        static_cast<DWORD>(protocol::kMaximumFrameSize * 2U),
        static_cast<DWORD>(protocol::kMaximumFrameSize * 2U),
        0,
        nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("CreateNamedPipeW failed with Windows error " +
                                 std::to_string(GetLastError()));
    }
    return pipe;
}

bool wait_for_connection(HANDLE pipe) {
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (event == nullptr) throw std::runtime_error("CreateEventW failed for sensor-broker accept");
    OVERLAPPED overlapped{};
    overlapped.hEvent = event;

    const BOOL connected = ConnectNamedPipe(pipe, &overlapped);
    if (connected != FALSE) {
        CloseHandle(event);
        return true;
    }
    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) {
        CloseHandle(event);
        return true;
    }
    if (error != ERROR_IO_PENDING) {
        CloseHandle(event);
        return false;
    }

    while (!stop_requested.load(std::memory_order_relaxed)) {
        const DWORD wait = WaitForSingleObject(event, 250);
        if (wait == WAIT_OBJECT_0) {
            DWORD transferred = 0;
            const BOOL ok = GetOverlappedResult(pipe, &overlapped, &transferred, FALSE);
            CloseHandle(event);
            return ok != FALSE || GetLastError() == ERROR_PIPE_CONNECTED;
        }
        if (wait != WAIT_TIMEOUT) {
            CancelIoEx(pipe, &overlapped);
            CloseHandle(event);
            return false;
        }
    }

    CancelIoEx(pipe, &overlapped);
    static_cast<void>(WaitForSingleObject(event, 1000));
    CloseHandle(event);
    return false;
}

void serve_client(HANDLE pipe, std::shared_ptr<BrokerEventRouter> router,
                  std::shared_ptr<EndpointProcessRegistry> registry) noexcept {
    try {
        const auto registration_frame = read_pipe_message(pipe, std::chrono::seconds(5));
        if (!registration_frame) throw std::runtime_error("client did not register within five seconds");
        const auto registration = protocol::decode_registration(*registration_frame);
        if (!registration || !router->has_endpoint(registration->endpoint_slot)) {
            throw std::runtime_error("client registered an unknown endpoint slot");
        }

        ULONG client_pid = 0;
        if (GetNamedPipeClientProcessId(pipe, &client_pid) == FALSE || client_pid == 0) {
            throw std::runtime_error("could not determine named-pipe client process identity");
        }
        if (!registry->endpoint_owns(registration->endpoint_slot, client_pid)) {
            throw std::runtime_error("named-pipe client process does not belong to requested endpoint slot");
        }

        while (!stop_requested.load(std::memory_order_relaxed)) {
            const auto frame = router->take(registration->endpoint_slot, std::chrono::milliseconds(500));
            if (!frame) continue;
            if (!write_pipe_message(pipe, *frame)) break;
        }
    } catch (const std::exception& error) {
        if (!stop_requested.load(std::memory_order_relaxed)) {
            std::cerr << "Windows sensor-broker client closed: " << error.what() << '\n';
        }
    }
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}

std::optional<std::uint32_t> lifecycle_pid(const ConnectionLifecycleEvent& event) {
    const auto pid = event.process.kernel.pid ? event.process.kernel.pid : event.process.agent_visible.pid;
    if (!pid || *pid <= 0 ||
        static_cast<std::uint64_t>(*pid) > static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(*pid);
}

}  // namespace

int run_windows_sensor_broker(int argc, char** argv) {
    std::wstring pipe_name = normalize_pipe_name(L"neta-sensor-broker");
    std::size_t queue_capacity = 1024;
    std::vector<EndpointMapping> mappings;

    for (int index = 2; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--pipe" && index + 1 < argc) {
            pipe_name = normalize_pipe_name(utf8_to_wide(argv[++index]));
        } else if (argument == "--queue-capacity" && index + 1 < argc) {
            queue_capacity = static_cast<std::size_t>(std::stoull(argv[++index]));
            if (queue_capacity == 0) throw std::runtime_error("--queue-capacity must be positive");
        } else if (argument == "--map" && index + 1 < argc) {
            mappings.push_back(parse_mapping(argv[++index]));
        } else if (argument == "--help") {
            std::cout << "Usage: neta-agent sensor-broker [--pipe NAME] [--queue-capacity N] "
                         "--map SLOT:ROOT_PID [--map ...]\n";
            return 0;
        } else {
            throw std::runtime_error("unknown Windows sensor-broker argument: " + argument);
        }
    }
    if (mappings.empty()) throw std::runtime_error("Windows sensor-broker requires at least one --map");

    _putenv_s("NETA_SENSOR_MODE", "native");
    _putenv_s("NETA_SENSOR_BROKER", "");
    _putenv_s("NETA_ENDPOINT_SLOT", "");

    auto lifecycle = platform::make_native_windows_lifecycle_observer();
    auto process_exec = platform::make_native_windows_process_exec_observer();
    if (!lifecycle->capability().available()) {
        throw std::runtime_error("native Windows lifecycle sensor unavailable: " +
                                 lifecycle->capability().unavailable_reason);
    }
    if (!process_exec->capability().available()) {
        throw std::runtime_error("native Windows process sensor unavailable: " +
                                 process_exec->capability().unavailable_reason);
    }

    auto registry = std::make_shared<EndpointProcessRegistry>();
    auto router = std::make_shared<BrokerEventRouter>(queue_capacity);
    for (const auto& mapping : mappings) {
        registry->register_endpoint(mapping.slot, mapping.root_pid);
        router->register_endpoint(mapping.slot);
    }

    stop_requested.store(false, std::memory_order_relaxed);
    if (SetConsoleCtrlHandler(console_handler, TRUE) == FALSE) {
        throw std::runtime_error("SetConsoleCtrlHandler failed for Windows sensor broker");
    }

    std::atomic<std::uint64_t> sequence{1};
    std::thread process_thread([&] {
        while (!stop_requested.load(std::memory_order_relaxed)) {
            for (const auto& event : process_exec->poll(std::chrono::milliseconds(100))) {
                const auto slot = registry->observe(event);
                if (!slot || !router->route_process_exec(*slot, event, sequence.fetch_add(1))) {
                    router->note_unroutable();
                }
            }
        }
    });
    std::thread lifecycle_thread([&] {
        while (!stop_requested.load(std::memory_order_relaxed)) {
            for (const auto& event : lifecycle->poll(std::chrono::milliseconds(100))) {
                const auto pid = lifecycle_pid(event);
                const auto slot = pid ? registry->resolve_pid(*pid) : std::nullopt;
                if (!slot || !router->route_lifecycle(*slot, event, sequence.fetch_add(1))) {
                    router->note_unroutable();
                }
            }
        }
    });

    std::vector<std::thread> clients;
    std::cout << "NETA Windows sensor broker listening on named pipe for " << mappings.size()
              << " endpoint mapping(s)\n";
    try {
        while (!stop_requested.load(std::memory_order_relaxed)) {
            HANDLE pipe = create_pipe_instance(pipe_name);
            if (!wait_for_connection(pipe)) {
                CloseHandle(pipe);
                continue;
            }
            clients.emplace_back(serve_client, pipe, router, registry);
        }
    } catch (...) {
        stop_requested.store(true, std::memory_order_relaxed);
        lifecycle_thread.join();
        process_thread.join();
        for (auto& client : clients) if (client.joinable()) client.join();
        SetConsoleCtrlHandler(console_handler, FALSE);
        throw;
    }

    lifecycle_thread.join();
    process_thread.join();
    for (auto& client : clients) if (client.joinable()) client.join();
    SetConsoleCtrlHandler(console_handler, FALSE);

    std::uint64_t dropped = 0;
    for (const auto& mapping : mappings) dropped += router->dropped(mapping.slot);
    std::cout << "NETA Windows sensor broker stopped; unroutable=" << router->unroutable()
              << " queue_drops=" << dropped << '\n';
    return 0;
}

}  // namespace neta::windows_sensor_broker

#endif
