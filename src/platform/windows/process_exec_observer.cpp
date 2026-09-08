#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <sddl.h>
#include <tdh.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

constexpr GUID kProcessGuid{
    0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
constexpr UCHAR kProcessStart = 1;
constexpr UCHAR kProcessEnd = 2;
constexpr UCHAR kProcessDcStart = 3;
constexpr UCHAR kProcessDcEnd = 4;
constexpr UCHAR kProcessDefunct = 39;
constexpr std::size_t kMaxQueuedEvents = 8192;

bool same_guid(const GUID& left, const GUID& right) noexcept {
    return std::memcmp(&left, &right, sizeof(GUID)) == 0;
}

std::vector<std::byte> property_bytes(const EVENT_RECORD& record, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
    descriptor.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(const_cast<EVENT_RECORD*>(&record), 0, nullptr, 1, &descriptor,
                           &size) != ERROR_SUCCESS || size == 0) {
        return {};
    }
    std::vector<std::byte> result(size);
    if (TdhGetProperty(const_cast<EVENT_RECORD*>(&record), 0, nullptr, 1, &descriptor,
                       size, reinterpret_cast<PBYTE>(result.data())) != ERROR_SUCCESS) {
        return {};
    }
    return result;
}

template <typename T>
std::optional<T> scalar_property(const EVENT_RECORD& record, const wchar_t* name) {
    const auto bytes = property_bytes(record, name);
    if (bytes.size() < sizeof(T)) return std::nullopt;
    T value{};
    std::memcpy(&value, bytes.data(), sizeof(T));
    return value;
}

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

std::string text_property(const EVENT_RECORD& record, const wchar_t* name) {
    const auto bytes = property_bytes(record, name);
    if (bytes.empty()) return {};
    if (bytes.size() >= sizeof(wchar_t) && bytes.size() % sizeof(wchar_t) == 0) {
        const auto* text = reinterpret_cast<const wchar_t*>(bytes.data());
        const std::size_t capacity = bytes.size() / sizeof(wchar_t);
        std::size_t length = 0;
        while (length < capacity && text[length] != L'\0') ++length;
        if (length > 0) {
            const auto converted = wide_to_utf8(text, length);
            if (!converted.empty()) return converted;
        }
    }
    const auto* text = reinterpret_cast<const char*>(bytes.data());
    std::size_t length = 0;
    while (length < bytes.size() && text[length] != '\0') ++length;
    return std::string(text, length);
}

std::optional<std::uint64_t> process_creation_key(DWORD pid) {
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
    if (ok == FALSE) return {};
    return wide_to_utf8(path, length);
}

std::string leaf_name(const std::string& path) {
    const auto slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

struct TokenEvidence {
    std::string sid;
    std::string integrity;
    std::optional<bool> elevated;
};

TokenEvidence process_token_evidence(DWORD pid) {
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

std::vector<std::byte> trace_properties_buffer(const std::wstring& name) {
    const auto bytes = sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1U) * sizeof(wchar_t);
    std::vector<std::byte> buffer(bytes);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(bytes);
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1;
    properties->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties->FlushTimer = 1;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    auto* output = reinterpret_cast<wchar_t*>(buffer.data() + properties->LoggerNameOffset);
    std::copy(name.begin(), name.end(), output);
    output[name.size()] = L'\0';
    return buffer;
}

class WindowsProcessExecObserver final : public ProcessExecObserver {
public:
    WindowsProcessExecObserver() {
        capability_.built_in = true;
        capability_.source = "windows:etw-process";
        session_name_ = L"NETA-MS5-PROCESS-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                        std::to_wstring(GetTickCount64());
        properties_buffer_ = trace_properties_buffer(session_name_);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer_.data());
        const ULONG start = StartTraceW(&session_handle_, session_name_.c_str(), properties);
        if (start != ERROR_SUCCESS) {
            capability_.unavailable_reason = "StartTraceW failed with Windows error " +
                                             std::to_string(start);
            session_handle_ = 0;
            return;
        }

        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName = const_cast<LPWSTR>(session_name_.c_str());
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = &WindowsProcessExecObserver::callback;
        logfile.Context = this;
        trace_handle_ = OpenTraceW(&logfile);
        if (trace_handle_ == INVALID_PROCESSTRACE_HANDLE) {
            const DWORD error = GetLastError();
            stop_session();
            capability_.unavailable_reason = "OpenTraceW failed with Windows error " +
                                             std::to_string(error);
            return;
        }

        capability_.exec_events = true;
        capability_.exit_events = true;
        capability_.parent_identity = true;
        capability_.command_line = true;
        capability_.security_identity = true;
        capability_.session_identity = true;
        capability_.drop_counter = true;
        worker_ = std::thread([this] {
            TRACEHANDLE handle = trace_handle_;
            static_cast<void>(ProcessTrace(&handle, 1, nullptr, nullptr));
        });
    }

    ~WindowsProcessExecObserver() override {
        stop_session();
        if (trace_handle_ != INVALID_PROCESSTRACE_HANDLE) {
            static_cast<void>(CloseTrace(trace_handle_));
            trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
        }
        if (worker_.joinable()) worker_.join();
    }

    const ProcessExecCapability& capability() const noexcept override { return capability_; }

    ProcessExecHealth health() const override {
        if (!capability_.drop_counter || session_handle_ == 0) return {};
        std::uint64_t dropped = locally_dropped_.load(std::memory_order_relaxed);
        auto buffer = trace_properties_buffer(session_name_);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
        if (ControlTraceW(session_handle_, session_name_.c_str(), properties,
                          EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS) {
            dropped += properties->EventsLost;
        }
        return ProcessExecHealth{dropped};
    }

    std::vector<ProcessExecEvent> poll(std::chrono::milliseconds timeout) override {
        std::unique_lock lock(mutex_);
        if (queue_.empty() && timeout.count() > 0) {
            condition_.wait_for(lock, timeout, [this] { return !queue_.empty() || stopping_; });
        }
        std::vector<ProcessExecEvent> result;
        result.reserve(queue_.size());
        while (!queue_.empty()) {
            result.push_back(std::move(queue_.front()));
            queue_.pop_front();
        }
        return result;
    }

private:
    static void WINAPI callback(EVENT_RECORD* record) {
        if (record == nullptr || record->UserContext == nullptr) return;
        static_cast<WindowsProcessExecObserver*>(record->UserContext)->consume(*record);
    }

    void stop_session() noexcept {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        condition_.notify_all();
        if (session_handle_ != 0) {
            auto buffer = trace_properties_buffer(session_name_);
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
            static_cast<void>(ControlTraceW(session_handle_, session_name_.c_str(), properties,
                                            EVENT_TRACE_CONTROL_STOP));
            session_handle_ = 0;
        }
    }

    void consume(const EVENT_RECORD& record) {
        if (!same_guid(record.EventHeader.ProviderId, kProcessGuid)) return;
        const UCHAR opcode = record.EventHeader.EventDescriptor.Opcode;
        const bool start = opcode == kProcessStart || opcode == kProcessDcStart;
        const bool exit = opcode == kProcessEnd || opcode == kProcessDcEnd || opcode == kProcessDefunct;
        if (!start && !exit) return;

        const auto pid = scalar_property<std::uint32_t>(record, L"ProcessId");
        if (!pid || *pid == 0) return;

        ProcessExecEvent event;
        event.type = exit ? ProcessExecEventType::Exit : ProcessExecEventType::Start;
        event.timestamp_ns = static_cast<std::uint64_t>(record.EventHeader.TimeStamp.QuadPart);
        event.pid = static_cast<std::int64_t>(*pid);
        event.tgid = static_cast<std::int64_t>(*pid);
        if (const auto parent = scalar_property<std::uint32_t>(record, L"ParentId")) {
            event.parent_pid = static_cast<std::int64_t>(*parent);
            event.parent_tgid = static_cast<std::int64_t>(*parent);
        }
        if (const auto key = scalar_property<std::uint64_t>(record, L"UniqueProcessKey")) {
            event.platform_process_key = *key;
        }
        event.process_start_time_ns = process_creation_key(*pid);
        if (!event.platform_process_key) event.platform_process_key = event.process_start_time_ns;

        if (start) {
            event.executable_path = process_image(*pid);
            if (event.executable_path.empty()) event.executable_path = text_property(record, L"ImageFileName");
            event.comm = leaf_name(event.executable_path);
            event.command_line = text_property(record, L"CommandLine");
            DWORD session = 0;
            if (ProcessIdToSessionId(*pid, &session) != FALSE) event.session_id = session;
            const auto token = process_token_evidence(*pid);
            event.user_identity = token.sid;
            event.integrity_level = token.integrity;
            event.elevated = token.elevated;
        }

        {
            std::lock_guard lock(mutex_);
            if (queue_.size() >= kMaxQueuedEvents) {
                queue_.pop_front();
                locally_dropped_.fetch_add(1, std::memory_order_relaxed);
            }
            queue_.push_back(std::move(event));
        }
        condition_.notify_one();
    }

    ProcessExecCapability capability_;
    std::wstring session_name_;
    std::vector<std::byte> properties_buffer_;
    TRACEHANDLE session_handle_{0};
    TRACEHANDLE trace_handle_{INVALID_PROCESSTRACE_HANDLE};
    std::thread worker_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<ProcessExecEvent> queue_;
    bool stopping_{false};
    std::atomic<std::uint64_t> locally_dropped_{0};
};

}  // namespace

std::unique_ptr<ProcessExecObserver> make_process_exec_observer() {
    return std::make_unique<WindowsProcessExecObserver>();
}

}  // namespace neta::platform
