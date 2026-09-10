#include "neta/platform.hpp"
#include "dns_etw_decoder.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <deque>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

constexpr wchar_t kProviderName[] = L"Microsoft-Windows-DNS-Client";
constexpr USHORT kQueryStartEventId = 3006;
constexpr USHORT kQueryCompletedEventId = 3008;
constexpr std::size_t kMaxQueuedEvents = 8192;
constexpr std::size_t kMaxPendingQueries = 4096;
constexpr std::uint64_t kPendingMaxAgeNs = 30'000'000'000ULL;

bool same_guid(const GUID& left, const GUID& right) noexcept {
    return std::memcmp(&left, &right, sizeof(GUID)) == 0;
}

bool zero_guid(const GUID& guid) noexcept {
    const GUID zero{};
    return same_guid(guid, zero);
}

GUID make_session_guid() noexcept {
    GUID guid{0x742b764d, 0x384c, 0x4f0b, {0xa1, 0x61, 0x4e, 0x45, 0x54, 0x41, 0x44, 0x4e}};
    const auto pid = static_cast<std::uint32_t>(GetCurrentProcessId());
    const auto tick = static_cast<std::uint32_t>(GetTickCount64());
    guid.Data1 ^= pid;
    guid.Data2 ^= static_cast<unsigned short>(tick & 0xffffU);
    guid.Data3 ^= static_cast<unsigned short>((tick >> 16U) & 0xffffU);
    return guid;
}

std::uint64_t qpc_to_ns(LONGLONG ticks, LONGLONG frequency) noexcept {
    if (ticks <= 0 || frequency <= 0) return 0;
    constexpr std::uint64_t billion = 1'000'000'000ULL;
    const auto value = static_cast<std::uint64_t>(ticks);
    const auto freq = static_cast<std::uint64_t>(frequency);
    return (value / freq) * billion + ((value % freq) * billion) / freq;
}

std::optional<GUID> provider_guid_by_name(const wchar_t* provider_name) {
    ULONG bytes = 0;
    ULONG rc = TdhEnumerateProviders(nullptr, &bytes);
    if (rc != ERROR_INSUFFICIENT_BUFFER || bytes == 0) return std::nullopt;
    std::vector<std::byte> buffer(bytes);
    auto* info = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(buffer.data());
    rc = TdhEnumerateProviders(info, &bytes);
    if (rc != ERROR_SUCCESS) return std::nullopt;
    for (ULONG index = 0; index < info->NumberOfProviders; ++index) {
        const auto& provider = info->TraceProviderInfoArray[index];
        if (provider.ProviderNameOffset >= bytes) continue;
        const auto* name = reinterpret_cast<const wchar_t*>(buffer.data() + provider.ProviderNameOffset);
        if (_wcsicmp(name, provider_name) == 0) return provider.ProviderGuid;
    }
    return std::nullopt;
}

std::vector<std::byte> trace_properties_buffer(const std::wstring& name,
                                                const GUID& session_guid) {
    const auto bytes = sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1U) * sizeof(wchar_t);
    std::vector<std::byte> buffer(bytes);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(bytes);
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    // Use QPC to match the timestamp domain used by the Windows TCP lifecycle collector
    // and std::chrono::steady_clock based socket observations.
    properties->Wnode.ClientContext = 1;
    properties->Wnode.Guid = session_guid;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->FlushTimer = 1;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    auto* output = reinterpret_cast<wchar_t*>(buffer.data() + properties->LoggerNameOffset);
    std::copy(name.begin(), name.end(), output);
    output[name.size()] = L'\0';
    return buffer;
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

std::string first_text_property(const EVENT_RECORD& record,
                                std::initializer_list<const wchar_t*> names) {
    for (const auto* name : names) {
        auto value = text_property(record, name);
        if (!value.empty()) return value;
    }
    return {};
}

std::optional<std::uint64_t> unsigned_property(const EVENT_RECORD& record, const wchar_t* name) {
    const auto bytes = property_bytes(record, name);
    if (bytes.empty()) return std::nullopt;
    if (bytes.size() >= sizeof(std::uint64_t)) {
        std::uint64_t value{};
        std::memcpy(&value, bytes.data(), sizeof(value));
        return value;
    }
    if (bytes.size() >= sizeof(std::uint32_t)) {
        std::uint32_t value{};
        std::memcpy(&value, bytes.data(), sizeof(value));
        return value;
    }
    if (bytes.size() >= sizeof(std::uint16_t)) {
        std::uint16_t value{};
        std::memcpy(&value, bytes.data(), sizeof(value));
        return value;
    }
    if (bytes.size() >= sizeof(std::uint8_t)) {
        return static_cast<std::uint8_t>(bytes.front());
    }
    return std::nullopt;
}

std::optional<std::uint64_t> first_unsigned_property(
    const EVENT_RECORD& record, std::initializer_list<const wchar_t*> names) {
    for (const auto* name : names) {
        if (auto value = unsigned_property(record, name)) return value;
    }
    return std::nullopt;
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
    return slash == std::string::npos ? path : path.substr(slash + 1U);
}

DWORD client_pid(const EVENT_RECORD& record) {
    const auto property = first_unsigned_property(
        record, {L"ClientPID", L"ClientPid", L"ProcessId", L"PID"});
    if (property && *property > 0 && *property <= MAXDWORD) return static_cast<DWORD>(*property);
    return record.EventHeader.ProcessId;
}

std::string guid_key(const GUID& guid) {
    if (zero_guid(guid)) return {};
    wchar_t text[64]{};
    const int count = StringFromGUID2(guid, text, static_cast<int>(std::size(text)));
    return count > 1 ? wide_to_utf8(text, static_cast<std::size_t>(count - 1)) : std::string{};
}

struct PendingQuery {
    std::uint64_t started_ns{0};
    DWORD pid{0};
    std::string query_name;
    std::uint32_t query_type{0};
};

std::string pending_key(const EVENT_RECORD& record, DWORD pid, const std::string& query_name) {
    auto key = guid_key(record.EventHeader.ActivityId);
    if (!key.empty()) return "activity:" + key;
    if (pid == 0 || query_name.empty()) return {};
    return "pid:" + std::to_string(pid) + "|name:" + query_name;
}

class WindowsDnsEtwObserver final : public NameResolutionObserver {
public:
    WindowsDnsEtwObserver() : session_guid_(make_session_guid()) {
        capability_.built_in = true;
        capability_.drop_counter = true;
        capability_.source = "windows:dns-etw";

        LARGE_INTEGER frequency{};
        if (QueryPerformanceFrequency(&frequency) == FALSE || frequency.QuadPart <= 0) {
            capability_.unavailable_reason = "QueryPerformanceFrequency failed for DNS ETW";
            return;
        }
        qpc_frequency_ = frequency.QuadPart;

        const auto provider = provider_guid_by_name(kProviderName);
        if (!provider) {
            capability_.unavailable_reason = "Microsoft-Windows-DNS-Client ETW provider is not registered";
            return;
        }
        provider_guid_ = *provider;

        session_name_ = L"NETA-DNS-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                        std::to_wstring(GetTickCount64());
        properties_buffer_ = trace_properties_buffer(session_name_, session_guid_);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer_.data());
        const ULONG start = StartTraceW(&session_handle_, session_name_.c_str(), properties);
        if (start != ERROR_SUCCESS) {
            capability_.unavailable_reason = "StartTraceW for DNS ETW failed with Windows error " +
                                             std::to_string(start);
            session_handle_ = 0;
            return;
        }

        const ULONG enable = EnableTraceEx2(session_handle_, &provider_guid_,
                                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                            TRACE_LEVEL_VERBOSE, ~0ULL, 0, 0, nullptr);
        if (enable != ERROR_SUCCESS) {
            capability_.unavailable_reason =
                "EnableTraceEx2 for Microsoft-Windows-DNS-Client failed with Windows error " +
                std::to_string(enable);
            stop_session();
            return;
        }

        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName = const_cast<LPWSTR>(session_name_.c_str());
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                                   PROCESS_TRACE_MODE_EVENT_RECORD |
                                   PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        logfile.EventRecordCallback = &WindowsDnsEtwObserver::callback;
        logfile.Context = this;
        trace_handle_ = OpenTraceW(&logfile);
        if (trace_handle_ == INVALID_PROCESSTRACE_HANDLE) {
            const DWORD error = GetLastError();
            stop_session();
            capability_.unavailable_reason = "OpenTraceW for DNS ETW failed with Windows error " +
                                             std::to_string(error);
            return;
        }

        capability_.system_resolver_events = true;
        worker_ = std::thread([this] {
            TRACEHANDLE handle = trace_handle_;
            static_cast<void>(ProcessTrace(&handle, 1, nullptr, nullptr));
        });
    }

    ~WindowsDnsEtwObserver() override {
        stop_session();
        if (trace_handle_ != INVALID_PROCESSTRACE_HANDLE) {
            static_cast<void>(CloseTrace(trace_handle_));
            trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
        }
        if (worker_.joinable()) worker_.join();
    }

    const NameResolutionCapability& capability() const noexcept override { return capability_; }

    NameResolutionHealth health() const override {
        std::uint64_t dropped = locally_dropped_.load(std::memory_order_relaxed);
        if (session_handle_ != 0) {
            auto buffer = trace_properties_buffer(session_name_, session_guid_);
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
            if (ControlTraceW(session_handle_, session_name_.c_str(), properties,
                              EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS) {
                dropped += properties->EventsLost;
            }
        }
        NameResolutionHealth result;
        result.dropped_events = dropped;
        result.events_received = events_received_.load(std::memory_order_relaxed);
        result.events_decoded = events_decoded_.load(std::memory_order_relaxed);
        result.decode_failures = decode_failures_.load(std::memory_order_relaxed);
        result.unmatched_processes = unmatched_processes_.load(std::memory_order_relaxed);
        result.unsupported_event_versions = unsupported_event_versions_.load(std::memory_order_relaxed);
        return result;
    }

    std::vector<NameResolutionObservation> poll(std::chrono::milliseconds timeout) override {
        std::unique_lock lock(mutex_);
        if (queue_.empty() && timeout.count() > 0) {
            condition_.wait_for(lock, timeout, [this] { return !queue_.empty() || stopping_; });
        }
        std::vector<NameResolutionObservation> result;
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
        static_cast<WindowsDnsEtwObserver*>(record->UserContext)->consume(*record);
    }

    void stop_session() noexcept {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        condition_.notify_all();
        if (session_handle_ != 0) {
            static_cast<void>(EnableTraceEx2(session_handle_, &provider_guid_,
                                             EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                                             TRACE_LEVEL_NONE, 0, 0, 0, nullptr));
            auto buffer = trace_properties_buffer(session_name_, session_guid_);
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
            static_cast<void>(ControlTraceW(session_handle_, session_name_.c_str(), properties,
                                            EVENT_TRACE_CONTROL_STOP));
            session_handle_ = 0;
        }
    }

    void trim_pending(std::uint64_t now_ns) {
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (now_ns != 0 && it->second.started_ns != 0 && now_ns >= it->second.started_ns &&
                now_ns - it->second.started_ns > kPendingMaxAgeNs) {
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
        while (pending_.size() > kMaxPendingQueries) pending_.erase(pending_.begin());
    }

    void consume(const EVENT_RECORD& record) {
        if (!same_guid(record.EventHeader.ProviderId, provider_guid_)) return;
        const USHORT event_id = record.EventHeader.EventDescriptor.Id;
        if (event_id != kQueryStartEventId && event_id != kQueryCompletedEventId) return;
        events_received_.fetch_add(1, std::memory_order_relaxed);

        const std::uint64_t timestamp = qpc_to_ns(record.EventHeader.TimeStamp.QuadPart, qpc_frequency_);
        DWORD pid = client_pid(record);
        std::string query_name = first_text_property(
            record, {L"QueryName", L"Name", L"HostName", L"Hostname"});
        const auto query_type_value = first_unsigned_property(record, {L"QueryType", L"Type"});
        std::uint32_t query_type = query_type_value
            ? static_cast<std::uint32_t>(*query_type_value) : 0U;
        const auto key = pending_key(record, pid, query_name);

        if (event_id == kQueryStartEventId) {
            if (!query_name.empty() && pid != 0 && !key.empty()) {
                pending_[key] = PendingQuery{timestamp, pid, std::move(query_name), query_type};
                trim_pending(timestamp);
            }
            return;
        }

        const auto status_value = first_unsigned_property(
            record, {L"QueryStatus", L"Status", L"ErrorCode", L"ResultCode"});
        const std::string result_text = first_text_property(
            record, {L"QueryResults", L"Results", L"Addresses", L"Address"});
        const std::string canonical_name = first_text_property(
            record, {L"CanonicalName", L"CName", L"CNAME"});
        auto addresses = windows_dns::extract_addresses(result_text);

        std::uint64_t started_ns = timestamp;
        if (!key.empty()) {
            const auto found = pending_.find(key);
            if (found != pending_.end()) {
                started_ns = found->second.started_ns;
                if (pid == 0) pid = found->second.pid;
                if (query_name.empty()) query_name = found->second.query_name;
                if (query_type == 0) query_type = found->second.query_type;
                pending_.erase(found);
            }
        }
        trim_pending(timestamp);

        if (query_name.empty() || pid == 0 || !status_value) {
            decode_failures_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        NameResolutionObservation observation;
        observation.started_ns = started_ns;
        observation.completed_ns = timestamp;
        observation.query_kind = windows_dns::query_kind(query_type);
        observation.mechanism = NameResolutionMechanism::SystemResolverEvent;
        observation.query_name = std::move(query_name);
        if (!canonical_name.empty()) observation.canonical_name = canonical_name;
        observation.addresses = std::move(addresses);
        observation.result_code = static_cast<int>(
            static_cast<std::int32_t>(static_cast<std::uint32_t>(*status_value)));
        observation.source = "windows:dns-etw";

        observation.process.agent_visible.pid = static_cast<std::int64_t>(pid);
        observation.process.agent_visible.tgid = static_cast<std::int64_t>(pid);
        observation.process.kernel.pid = static_cast<std::int64_t>(pid);
        observation.process.kernel.tgid = static_cast<std::int64_t>(pid);

        const auto creation = process_creation_key(pid);
        if (creation) observation.process.start_ticks = *creation;
        const auto image = process_image(pid);
        if (!image.empty()) observation.process.comm = leaf_name(image);

        if (creation) {
            observation.fidelity = EvidenceFidelity::Exact;
        } else {
            observation.fidelity = EvidenceFidelity::Supporting;
            unmatched_processes_.fetch_add(1, std::memory_order_relaxed);
        }

        // Keep failed lookups even without addresses so DNS-001 can consume them.
        // Successful forward lookups require a usable A/AAAA result for DNS-to-TCP correlation.
        if (windows_dns::successful_status(observation.result_code) &&
            observation.query_kind == NameResolutionQueryKind::Forward &&
            observation.addresses.empty()) {
            decode_failures_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        {
            std::lock_guard lock(mutex_);
            if (queue_.size() >= kMaxQueuedEvents) {
                queue_.pop_front();
                locally_dropped_.fetch_add(1, std::memory_order_relaxed);
            }
            queue_.push_back(std::move(observation));
        }
        events_decoded_.fetch_add(1, std::memory_order_relaxed);
        condition_.notify_one();
    }

    NameResolutionCapability capability_;
    GUID provider_guid_{};
    GUID session_guid_{};
    std::wstring session_name_;
    std::vector<std::byte> properties_buffer_;
    TRACEHANDLE session_handle_{0};
    TRACEHANDLE trace_handle_{INVALID_PROCESSTRACE_HANDLE};
    LONGLONG qpc_frequency_{0};
    std::thread worker_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<NameResolutionObservation> queue_;
    std::unordered_map<std::string, PendingQuery> pending_;
    bool stopping_{false};
    std::atomic<std::uint64_t> locally_dropped_{0};
    std::atomic<std::uint64_t> events_received_{0};
    std::atomic<std::uint64_t> events_decoded_{0};
    std::atomic<std::uint64_t> decode_failures_{0};
    std::atomic<std::uint64_t> unmatched_processes_{0};
    std::atomic<std::uint64_t> unsupported_event_versions_{0};
};

} // namespace

std::unique_ptr<NameResolutionObserver> make_name_resolution_observer() {
    return std::make_unique<WindowsDnsEtwObserver>();
}

} // namespace neta::platform
