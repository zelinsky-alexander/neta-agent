#include "neta/windows_service.hpp"

#include "neta/cli/observation_command.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace neta::platform {
namespace {

constexpr wchar_t service_name[] = L"NETAAgent";

SERVICE_STATUS_HANDLE service_status_handle = nullptr;
SERVICE_STATUS service_status{};
std::mutex service_status_mutex;
std::vector<std::string> service_process_args;
int service_exit_code = 0;

std::filesystem::path program_data_root() {
    wchar_t buffer[32768]{};
    const DWORD length = GetEnvironmentVariableW(L"ProgramData", buffer,
                                                  static_cast<DWORD>(std::size(buffer)));
    if (length != 0 && length < std::size(buffer)) {
        return std::filesystem::path(buffer) / L"NETA";
    }
    return std::filesystem::path(L"C:\\ProgramData\\NETA");
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
    service_status_handle = RegisterServiceCtrlHandlerExW(service_name,
                                                          service_control_handler,
                                                          nullptr);
    if (service_status_handle == nullptr) {
        service_exit_code = static_cast<int>(GetLastError());
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
        cli::run_observation_command(static_cast<int>(argv.size()), argv.data(), true);
        service_exit_code = 0;
        report_service_status(SERVICE_STOPPED);
    } catch (const std::exception& error) {
        service_exit_code = 2;
        std::string diagnostic = "NETAAgent service failed: ";
        diagnostic += error.what();
        diagnostic += '\n';
        OutputDebugStringA(diagnostic.c_str());
        report_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                              static_cast<DWORD>(service_exit_code));
    } catch (...) {
        service_exit_code = 2;
        OutputDebugStringA("NETAAgent service failed with unknown exception\n");
        report_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                              static_cast<DWORD>(service_exit_code));
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
