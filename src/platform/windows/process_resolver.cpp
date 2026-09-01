#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>

namespace neta::platform {
namespace {

struct HandleCloser {
    void operator()(HANDLE handle) const noexcept {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
};

using UniqueHandle = std::unique_ptr<void, HandleCloser>;

std::string narrow_utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                            result.data(), size, nullptr, nullptr) <= 0) {
        return {};
    }
    return result;
}

std::optional<ProcessIdentity> resolve_pid(std::int64_t pid_value) {
    if (pid_value <= 0 || pid_value > static_cast<std::int64_t>(MAXDWORD)) return std::nullopt;
    const DWORD pid = static_cast<DWORD>(pid_value);
    UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process) return std::nullopt;

    ProcessIdentity identity;
    identity.pid = pid_value;

    wchar_t path_buffer[32768]{};
    DWORD path_size = static_cast<DWORD>(std::size(path_buffer));
    if (QueryFullProcessImageNameW(process.get(), 0, path_buffer, &path_size) != FALSE) {
        const std::wstring path(path_buffer, path_size);
        identity.executable_path = narrow_utf8(path);
        const auto slash = path.find_last_of(L"\\/");
        identity.comm = narrow_utf8(slash == std::wstring::npos ? path : path.substr(slash + 1));
    }

    FILETIME creation{}, exit{}, kernel{}, user{};
    if (GetProcessTimes(process.get(), &creation, &exit, &kernel, &user) != FALSE) {
        ULARGE_INTEGER value{};
        value.LowPart = creation.dwLowDateTime;
        value.HighPart = creation.dwHighDateTime;
        identity.start_ticks = value.QuadPart;
    }

    return identity;
}

class WindowsProcessResolver final : public ProcessResolver {
public:
    std::optional<ProcessIdentity> resolve(std::uint64_t) override {
        return std::nullopt;
    }

    std::optional<ProcessIdentity> resolve(const SocketObservation& socket) override {
        if (!socket.owning_pid) return std::nullopt;
        return resolve_pid(*socket.owning_pid);
    }
};

} // namespace

std::unique_ptr<ProcessResolver> make_process_resolver() {
    return std::make_unique<WindowsProcessResolver>();
}

} // namespace neta::platform
