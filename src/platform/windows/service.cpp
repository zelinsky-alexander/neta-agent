#include "neta/windows_service.hpp"

#include "neta/cli/observation_command.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace neta::platform {
namespace {

constexpr wchar_t service_name[] = L"NETAAgent";
constexpr wchar_t event_source_name[] = L"NETAAgent";
constexpr wchar_t event_source_registry_path[] =
    L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\NETAAgent";
constexpr DWORD event_id_service_failure = 1001;
constexpr DWORD service_error_unhandled_exception = 0x4E01;
constexpr DWORD service_error_unknown_exception = 0x4E02;

SERVICE_STATUS_HANDLE service_status_handle = nullptr;
SERVICE_STATUS service_status{};
std::mutex service_status_mutex;
std::vector<std::string> service_process_args;
int service_exit_code = 0;

std::filesystem::path program_data_root() {
    wchar_t buffer[32768]{};
    constexpr DWORD buffer_count = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    const DWORD length = GetEnvironmentVariableW(L"ProgramData", buffer, buffer_count);
    if (length != 0 && length < buffer_count) {
        return std::filesystem::path(buffer) / L"NETA";
    }
    return std::filesystem::path(L"C:\\ProgramData\\NETA");
}

std::filesystem::path service_log_path() {
    return program_data_root() / L"logs" / L"neta-agent-service.log";
}

std::string utc_timestamp() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer),
                  "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  static_cast<unsigned>(time.wYear),
                  static_cast<unsigned>(time.wMonth),
                  static_cast<unsigned>(time.wDay),
                  static_cast<unsigned>(time.wHour),
                  static_cast<unsigned>(time.wMinute),
                  static_cast<unsigned>(time.wSecond),
                  static_cast<unsigned>(time.wMilliseconds));
    return buffer;
}

std::wstring widen_utf8(const std::string& text) {
    if (text.empty()) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                             text.data(), static_cast<int>(text.size()),
                                             nullptr, 0);
    if (required <= 0) {
        return std::wstring(text.begin(), text.end());
    }
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                        text.data(), static_cast<int>(text.size()),
                        wide.data(), required);
    return wide;
}

void ensure_event_source_registered() noexcept {
    HKEY key = nullptr;
    const LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, event_source_registry_path,
                                        0, nullptr, REG_OPTION_NON_VOLATILE,
                                        KEY_SET_VALUE, nullptr, &key, nullptr);
    if (result != ERROR_SUCCESS || key == nullptr) return;

    const DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE |
                        EVENTLOG_INFORMATION_TYPE;
    static_cast<void>(RegSetValueExW(
        key, L"TypesSupported", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&types), sizeof(types)));
    RegCloseKey(key);
}

void report_windows_event(WORD type, DWORD event_id, const std::string& message) noexcept {
    try {
        ensure_event_source_registered();
        HANDLE source = RegisterEventSourceW(nullptr, event_source_name);
        if (source == nullptr) return;
        const auto wide = widen_utf8(message);
        const wchar_t* strings[] = {wide.c_str()};
        static_cast<void>(ReportEventW(source, type, 0, event_id, nullptr,
                                       1, 0, strings, nullptr));
        DeregisterEventSource(source);
    } catch (...) {
        // Event Log reporting is best effort and must never hide the original failure.
    }
}

class ServiceLogSession {
public:
    ServiceLogSession() noexcept {
        try {
            const auto path = service_log_path();
            std::filesystem::create_directories(path.parent_path());
            stream_.open(path, std::ios::out | std::ios::app);
            if (!stream_.is_open()) return;
            stream_.setf(std::ios::unitbuf);
            previous_stdout_ = std::cout.rdbuf(stream_.rdbuf());
            previous_stderr_ = std::cerr.rdbuf(stream_.rdbuf());
            write("INFO", "Windows service logging initialized: " + path.string());
        } catch (...) {
            // The service can still run if its diagnostic file cannot be opened.
        }
    }

    ~ServiceLogSession() {
        if (previous_stdout_ != nullptr) std::cout.rdbuf(previous_stdout_);
        if (previous_stderr_ != nullptr) std::cerr.rdbuf(previous_stderr_);
    }

    void write(const char* level, const std::string& message) noexcept {
        try {
            std::lock_guard lock(mutex_);
            if (stream_.is_open()) {
                stream_ << utc_timestamp() << " [" << level << "] " << message << '\n';
            }
        } catch (...) {
            // Logging failures must not recursively fail the service.
        }
    }

private:
    std::ofstream stream_;
    std::streambuf* previous_stdout_{nullptr};
    std::streambuf* previous_stderr_{nullptr};
    std::mutex mutex_;
};

int process_exit_code(DWORD value, int fallback) {
    if (value == 0 || value > static_cast<DWORD>(std::numeric_limits<int>::max())) {
        return fallback;
    }
    return static_cast<int>(value);
}

void record_service_failure(ServiceLogSession& log,
                            const std::string& diagnostic) noexcept {
    log.write("ERROR", diagnostic);
    std::string debug = diagnostic;
    debug += '\n';
    OutputDebugStringA(debug.c_str());
    report_windows_event(EVENTLOG_ERROR_TYPE, event_id_service_failure, diagnostic);
}

void report_service_status(DWORD current_state, DWORD win32_exit_code = NO_ERROR,
                           DWORD service_specific_exit_code = 0, DWORD wait_hint_ms = 0) {
    std::lock_guard lock(service_status_mutex);
    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwCurrentState = current_state;
    service_status.dwWin32ExitCode = win32_exit_code;
    service_status.dwServiceSpecificExitCode = service_specific_exit_code;
    service_status.dwWaitHint = wait_hint_ms;
    service_status.dwCheckPoint =
        current_state == SERVICE_START_PENDING || current_state == SERVICE_STOP_PENDING
            ? service_status.dwCheckPoint + 1
            : 0;
    service_status.dwControlsAccepted =
        current_state == SERVICE_RUNNING
            ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            : 0;
    if (service_status_handle != nullptr) {
        SetServiceStatus(service_status_handle, &service_status);
    }
}

DWORD WINAPI service_control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 0, 5000);
            cli::request_observation_stop();
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            if (service_status_handle != nullptr) {
                std::lock_guard lock(service_status_mutex);
                SetServiceStatus(service_status_handle, &service_status);
            }
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

std::vector<std::string> observation_args_from_service_command() {
    std::vector<std::string> args{"neta-agent", "run"};
    bool has_database = false;
    std::optional<std::string> state_dir;

    for (std::size_t index = 2; index < service_process_args.size(); ++index) {
        const auto& argument = service_process_args[index];
        if (argument == "--state-dir") {
            if (index + 1 >= service_process_args.size()) {
                throw std::runtime_error("--state-dir needs a value");
            }
            state_dir = service_process_args[++index];
            continue;
        }
        if (argument == "--db") has_database = true;
        args.push_back(argument);
    }

    const auto root = program_data_root();
    std::filesystem::create_directories(root);
    if (!has_database) {
        args.emplace_back("--db");
        args.push_back((root / L"neta.db").string());
    }

    const auto effective_state_dir = state_dir.value_or((root / L"identity").string());
    if (_putenv_s("NETA_FLEET_STATE_DIR", effective_state_dir.c_str()) != 0) {
        throw std::runtime_error("failed to set NETA_FLEET_STATE_DIR for Windows service");
    }

    return args;
}

void WINAPI service_main(DWORD, LPWSTR*) {
    ServiceLogSession service_log;
    service_status_handle = RegisterServiceCtrlHandlerExW(service_name,
                                                          service_control_handler,
                                                          nullptr);
    if (service_status_handle == nullptr) {
        const DWORD error = GetLastError();
        service_exit_code = process_exit_code(error, 1);
        record_service_failure(
            service_log,
            "NETAAgent failed to register its Service Control Manager handler; win32_error=" +
                std::to_string(error));
        return;
    }

    service_status = {};
    report_service_status(SERVICE_START_PENDING, NO_ERROR, 0, 10000);

    try {
        auto args = observation_args_from_service_command();
        std::vector<char*> argv;
        argv.reserve(args.size());
        for (auto& argument : args) argv.push_back(argument.data());

        report_service_status(SERVICE_RUNNING);
        service_log.write("INFO", "NETAAgent entered SERVICE_RUNNING");
        cli::run_observation_command(static_cast<int>(argv.size()), argv.data(), true);
        service_exit_code = 0;
        service_log.write("INFO", "NETAAgent observation loop stopped cleanly");
        report_service_status(SERVICE_STOPPED);
    } catch (const std::system_error& error) {
        const auto& code = error.code();
        std::string diagnostic = "NETAAgent service failed: ";
        diagnostic += error.what();
        diagnostic += " [error_category=";
        diagnostic += code.category().name();
        diagnostic += ", error_code=";
        diagnostic += std::to_string(code.value());
        diagnostic += ']';
        record_service_failure(service_log, diagnostic);

        const bool is_win32_error = &code.category() == &std::system_category() &&
            code.value() > 0 &&
            static_cast<unsigned long long>(code.value()) <=
                static_cast<unsigned long long>(std::numeric_limits<DWORD>::max());
        if (is_win32_error) {
            const DWORD win32_error = static_cast<DWORD>(code.value());
            service_exit_code = process_exit_code(win32_error, 1);
            report_service_status(SERVICE_STOPPED, win32_error);
        } else {
            service_exit_code = static_cast<int>(service_error_unhandled_exception);
            report_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                                  service_error_unhandled_exception);
        }
    } catch (const std::exception& error) {
        service_exit_code = static_cast<int>(service_error_unhandled_exception);
        std::string diagnostic = "NETAAgent service failed: ";
        diagnostic += error.what();
        diagnostic += " [service_error=";
        diagnostic += std::to_string(service_error_unhandled_exception);
        diagnostic += ']';
        record_service_failure(service_log, diagnostic);
        report_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                              service_error_unhandled_exception);
    } catch (...) {
        service_exit_code = static_cast<int>(service_error_unknown_exception);
        const std::string diagnostic =
            "NETAAgent service failed with an unknown exception [service_error=" +
            std::to_string(service_error_unknown_exception) + ']';
        record_service_failure(service_log, diagnostic);
        report_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                              service_error_unknown_exception);
    }
}

} // namespace

int run_windows_service(int argc, char** argv) {
    service_process_args.clear();
    service_process_args.reserve(static_cast<std::size_t>(argc));
    for (int index = 0; index < argc; ++index) {
        service_process_args.emplace_back(argv[index] == nullptr ? "" : argv[index]);
    }
    service_exit_code = 0;

    SERVICE_TABLE_ENTRYW dispatch_table[] = {
        {const_cast<LPWSTR>(service_name), service_main},
        {nullptr, nullptr},
    };

    if (StartServiceCtrlDispatcherW(dispatch_table) == FALSE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            throw std::runtime_error(
                "Windows service command must be launched by the Service Control Manager");
        }
        throw std::runtime_error("StartServiceCtrlDispatcherW failed with Windows error " +
                                 std::to_string(error));
    }
    return service_exit_code;
}

} // namespace neta::platform

// Keep the DNS Client manifest-provider implementation isolated from the Schannel
// observer translation unit. Both use generic ETW helper names in anonymous namespaces.
#include "dns_etw_observer.cpp"
