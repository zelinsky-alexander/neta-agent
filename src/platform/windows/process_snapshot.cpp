#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <optional>
#include <string>
#include <vector>

namespace neta::platform {
namespace {

std::string wide_to_utf8(const wchar_t* text, std::size_t length) {
    if (text == nullptr || length == 0) return {};
    const int required = WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(length),
                                             nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(length), result.data(), required,
                            nullptr, nullptr) <= 0) {
        return {};
    }
    return result;
}

std::optional<std::uint64_t> creation_key(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return std::nullopt;
    FILETIME creation{}, exit{}, kernel{}, user{};
    const BOOL ok = GetProcessTimes(process, &creation, &exit, &kernel, &user);
    CloseHandle(process);
    if (ok == FALSE) return std::nullopt;
    ULARGE_INTEGER value{};
    value.LowPart = creation.dwLowDateTime;
    value.HighPart = creation.dwHighDateTime;
    return value.QuadPart;
}

std::string process_image(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return {};
    wchar_t path[32768]{};
    DWORD length = static_cast<DWORD>(std::size(path));
    const BOOL ok = QueryFullProcessImageNameW(process, 0, path, &length);
    CloseHandle(process);
    return ok == FALSE ? std::string{} : wide_to_utf8(path, length);
}

struct TokenEvidence {
    std::string sid;
    std::string integrity;
    std::optional<bool> elevated;
};

TokenEvidence token_evidence(DWORD pid) {
    TokenEvidence result;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return result;
    HANDLE token = nullptr;
    if (OpenProcessToken(process, TOKEN_QUERY, &token) == FALSE) {
        CloseHandle(process);
        return result;
    }

    DWORD size = 0;
    static_cast<void>(GetTokenInformation(token, TokenUser, nullptr, 0, &size));
    if (size > 0) {
        std::vector<std::byte> buffer(size);
        if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size) != FALSE) {
            const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
            LPWSTR text = nullptr;
            if (ConvertSidToStringSidW(user->User.Sid, &text) != FALSE && text != nullptr) {
                result.sid = wide_to_utf8(text, std::wcslen(text));
                LocalFree(text);
            }
        }
    }

    TOKEN_ELEVATION elevation{};
    size = sizeof(elevation);
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE) {
        result.elevated = elevation.TokenIsElevated != 0;
    }

    size = 0;
    static_cast<void>(GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size));
    if (size > 0) {
        std::vector<std::byte> buffer(size);
        if (GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), size, &size) != FALSE) {
            const auto* level = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
            const DWORD count = *GetSidSubAuthorityCount(level->Label.Sid);
            if (count > 0) {
                const DWORD rid = *GetSidSubAuthority(level->Label.Sid, count - 1U);
                if (rid >= SECURITY_MANDATORY_SYSTEM_RID) result.integrity = "system";
                else if (rid >= SECURITY_MANDATORY_HIGH_RID) result.integrity = "high";
                else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) result.integrity = "medium";
                else result.integrity = "low";
            }
        }
    }

    CloseHandle(token);
    CloseHandle(process);
    return result;
}

}  // namespace

std::vector<ProcessExecEvent> snapshot_processes() {
    std::vector<ProcessExecEvent> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry) == FALSE) {
        CloseHandle(snapshot);
        return result;
    }

    do {
        if (entry.th32ProcessID == 0) continue;
        const auto key = creation_key(entry.th32ProcessID);
        if (!key) continue;

        ProcessExecEvent event;
        event.type = ProcessExecEventType::Start;
        event.pid = static_cast<std::int64_t>(entry.th32ProcessID);
        event.tgid = static_cast<std::int64_t>(entry.th32ProcessID);
        event.parent_pid = static_cast<std::int64_t>(entry.th32ParentProcessID);
        event.parent_tgid = static_cast<std::int64_t>(entry.th32ParentProcessID);
        event.platform_process_key = *key;
        event.timestamp_ns = *key * 100ULL;
        event.comm = wide_to_utf8(entry.szExeFile, std::wcslen(entry.szExeFile));
        event.executable_path = process_image(entry.th32ProcessID);
        if (entry.th32ParentProcessID != 0) {
            event.parent_platform_process_key = creation_key(entry.th32ParentProcessID);
        }
        DWORD session = 0;
        if (ProcessIdToSessionId(entry.th32ProcessID, &session) != FALSE) event.session_id = session;
        const auto token = token_evidence(entry.th32ProcessID);
        event.user_identity = token.sid;
        event.integrity_level = token.integrity;
        event.elevated = token.elevated;
        result.push_back(std::move(event));
    } while (Process32NextW(snapshot, &entry) != FALSE);

    CloseHandle(snapshot);
    return result;
}

}  // namespace neta::platform
