#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
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
#include <unordered_map>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

constexpr GUID kTcpIpGuid{
    0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};

constexpr UCHAR kConnectIpv4 = 12;
constexpr UCHAR kDisconnectIpv4 = 13;
constexpr UCHAR kAcceptIpv4 = 15;
constexpr UCHAR kConnectIpv6 = 28;
constexpr UCHAR kDisconnectIpv6 = 29;
constexpr UCHAR kAcceptIpv6 = 31;
constexpr std::size_t kMaxQueuedEvents = 8192;
constexpr std::size_t kMaxActiveConnections = 16384;

bool same_guid(const GUID& left, const GUID& right) noexcept {
    return std::memcmp(&left, &right, sizeof(GUID)) == 0;
}

std::uint64_t qpc_to_ns(LONGLONG ticks, LONGLONG frequency) noexcept {
    if (ticks <= 0 || frequency <= 0) return 0;
    constexpr std::uint64_t billion = 1'000'000'000ULL;
    const auto value = static_cast<std::uint64_t>(ticks);
    const auto freq = static_cast<std::uint64_t>(frequency);
    return (value / freq) * billion + ((value % freq) * billion) / freq;
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

std::optional<std::uint16_t> port_property(const EVENT_RECORD& record, const wchar_t* name) {
    const auto raw = scalar_property<std::uint16_t>(record, name);
    if (!raw) return std::nullopt;
    return ntohs(*raw);
}

std::optional<std::string> address_property(const EVENT_RECORD& record, const wchar_t* name,
                                            bool ipv6) {
    const auto bytes = property_bytes(record, name);
    const std::size_t required = ipv6 ? 16U : 4U;
    if (bytes.size() < required) return std::nullopt;
    char output[INET6_ADDRSTRLEN]{};
    const int family = ipv6 ? AF_INET6 : AF_INET;
    if (InetNtopA(family, bytes.data(), output, static_cast<DWORD>(sizeof(output))) == nullptr) {
        return std::nullopt;
    }
    return std::string(output);
}

std::optional<std::uint64_t> process_start_identity(DWORD pid) {
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

std::optional<std::string> process_name(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return std::nullopt;
    wchar_t buffer[32768]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (QueryFullProcessImageNameW(process, 0, buffer, &size) == FALSE) {
        CloseHandle(process);
        return std::nullopt;
    }
    CloseHandle(process);
    const wchar_t* begin = buffer;
    const wchar_t* end = buffer + size;
    const wchar_t* leaf = end;
    while (leaf != begin && leaf[-1] != L'\\' && leaf[-1] != L'/') --leaf;
    const int required = WideCharToMultiByte(CP_UTF8, 0, leaf, static_cast<int>(end - leaf),
                                             nullptr, 0, nullptr, nullptr);
    if (required <= 0) return std::nullopt;
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, leaf, static_cast<int>(end - leaf), result.data(),
                            required, nullptr, nullptr) <= 0) {
        return std::nullopt;
    }
    return result;
}

struct ActiveConnection {
    NetworkAddressFamily family{NetworkAddressFamily::Unknown};
    NetworkEndpoint local;
    NetworkEndpoint remote;
};

std::uint64_t connection_key(std::uint32_t pid, std::uint32_t connid) noexcept {
    return (static_cast<std::uint64_t>(pid) << 32U) | connid;
}

GUID session_guid() noexcept {
    const auto pid = static_cast<std::uint32_t>(GetCurrentProcessId());
    const auto ticks = GetTickCount64();
    GUID value{};
    value.Data1 = 0x4e455441U; // "NETA"
    value.Data2 = static_cast<USHORT>(0x5700U | (pid & 0xffU));
    value.Data3 = static_cast<USHORT>(0x4000U | ((pid >> 8U) & 0x0fffU));
    for (std::size_t i = 0; i < std::size(value.Data4); ++i) {
        value.Data4[i] = static_cast<UCHAR>((ticks >> (i * 8U)) & 0xffU);
    }
    value.Data4[0] = static_cast<UCHAR>((value.Data4[0] & 0x3fU) | 0x80U);
    return value;
}

std::vector<std::byte> trace_properties_buffer(const std::wstring& name) {
    const auto bytes = sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1U) * sizeof(wchar_t);
    std::vector<std::byte> buffer(bytes);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(bytes);
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1; // QueryPerformanceCounter timestamps.
    properties->Wnode.Guid = session_guid();
    properties->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties->FlushTimer = 1;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    auto* name_out = reinterpret_cast<wchar_t*>(buffer.data() + properties->LoggerNameOffset);
    std::copy(name.begin(), name.end(), name_out);
    name_out[name.size()] = L'\0';
    return buffer;
}

class WindowsEtwLifecycleObserver final : public LifecycleObserver {
public:
    WindowsEtwLifecycleObserver() {
        capability_.built_in = true;
        capability_.source = "windows:etw-tcpip";
        LARGE_INTEGER frequency{};
        if (QueryPerformanceFrequency(&frequency) == FALSE || frequency.QuadPart <= 0) {
            capability_.unavailable_reason = "QueryPerformanceFrequency failed";
            return;
        }
        qpc_frequency_ = frequency.QuadPart;

        session_name_ = L"NETA-W3-TCPIP-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                        std::to_wstring(GetTickCount64());
        properties_buffer_ = trace_properties_buffer(session_name_);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer_.data());
        const ULONG start_status = StartTraceW(&session_handle_, session_name_.c_str(), properties);
        if (start_status != ERROR_SUCCESS) {
            capability_.unavailable_reason = "StartTraceW failed with Windows error " +
                                             std::to_string(start_status);
            session_handle_ = 0;
            return;
        }

        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName = const_cast<LPWSTR>(session_name_.c_str());
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = &WindowsEtwLifecycleObserver::event_record_callback;
        logfile.Context = this;
        trace_handle_ = OpenTraceW(&logfile);
        if (trace_handle_ == INVALID_PROCESSTRACE_HANDLE) {
            const DWORD error = GetLastError();
            stop_session();
            capability_.unavailable_reason = "OpenTraceW failed with Windows error " +
                                             std::to_string(error);
            return;
        }

        capability_.connect_events = true;
        capability_.accept_events = true;
        capability_.close_events = true;
        capability_.drop_counter = true;
        worker_ = std::thread([this] {
            TRACEHANDLE handle = trace_handle_;
            static_cast<void>(ProcessTrace(&handle, 1, nullptr, nullptr));
        });
    }

    ~WindowsEtwLifecycleObserver() override {
        stop_session();
        if (trace_handle_ != INVALID_PROCESSTRACE_HANDLE) {
            static_cast<void>(CloseTrace(trace_handle_));
            trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
        }
        if (worker_.joinable()) worker_.join();
    }

    const LifecycleCapability& capability() const noexcept override { return capability_; }

    LifecycleHealth health() const override {
        if (!capability_.drop_counter || session_handle_ == 0) return {};
        std::uint64_t dropped = locally_dropped_;
        auto query_buffer = trace_properties_buffer(session_name_);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(query_buffer.data());
        const ULONG status = ControlTraceW(session_handle_, session_name_.c_str(), properties,
                                           EVENT_TRACE_CONTROL_QUERY);
        if (status == ERROR_SUCCESS) dropped += properties->EventsLost;
        return LifecycleHealth{dropped};
    }

    std::vector<ConnectionLifecycleEvent> poll(std::chrono::milliseconds timeout) override {
        if (!capability_.available()) return {};
        std::unique_lock lock(mutex_);
        if (queue_.empty() && timeout.count() > 0) {
            condition_.wait_for(lock, timeout, [this] { return !queue_.empty() || stopping_; });
        }
        std::vector<ConnectionLifecycleEvent> result;
        result.reserve(queue_.size());
        while (!queue_.empty()) {
            result.push_back(std::move(queue_.front()));
            queue_.pop_front();
        }
        return result;
    }

private:
    static void WINAPI event_record_callback(EVENT_RECORD* record) {
        if (record == nullptr || record->UserContext == nullptr) return;
        static_cast<WindowsEtwLifecycleObserver*>(record->UserContext)->consume(*record);
    }

    void stop_session() noexcept {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        condition_.notify_all();
        if (session_handle_ != 0) {
            auto stop_buffer = trace_properties_buffer(session_name_);
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stop_buffer.data());
            static_cast<void>(ControlTraceW(session_handle_, session_name_.c_str(), properties,
                                            EVENT_TRACE_CONTROL_STOP));
            session_handle_ = 0;
        }
    }

    void consume(const EVENT_RECORD& record) {
        if (!same_guid(record.EventHeader.ProviderId, kTcpIpGuid)) return;
        const UCHAR opcode = record.EventHeader.EventDescriptor.Opcode;
        const bool ipv6 = opcode == kConnectIpv6 || opcode == kAcceptIpv6 ||
                          opcode == kDisconnectIpv6;
        const bool connect = opcode == kConnectIpv4 || opcode == kConnectIpv6;
        const bool accept = opcode == kAcceptIpv4 || opcode == kAcceptIpv6;
        const bool disconnect = opcode == kDisconnectIpv4 || opcode == kDisconnectIpv6;
        if (!connect && !accept && !disconnect) return;

        const auto pid = scalar_property<std::uint32_t>(record, L"PID");
        const auto connid = scalar_property<std::uint32_t>(record, L"connid");
        if (!pid || !connid) return;

        ConnectionLifecycleEvent event;
        event.timestamp_ns = qpc_to_ns(record.EventHeader.TimeStamp.QuadPart, qpc_frequency_);
        event.provenance = LifecycleProvenance::WindowsEtw;
        event.process.agent_visible.pid = static_cast<std::int64_t>(*pid);
        event.process.agent_visible.tgid = static_cast<std::int64_t>(*pid);
        event.process.kernel = event.process.agent_visible;
        // ProcessIdentity.uid is a legacy numeric field with no Windows SID equivalent. Keep the
        // lifecycle availability marker explicit; zero here is only the existing storage default.
        event.process.uid = 0;
        event.process.start_ticks = process_start_identity(*pid);
        event.process.comm = process_name(*pid);
        event.address_family = ipv6 ? NetworkAddressFamily::IPv6 : NetworkAddressFamily::IPv4;
        event.protocol = TransportProtocol::Tcp;
        event.endpoint_kind = disconnect ? TcpEndpointKind::LifecycleTail
                                         : TcpEndpointKind::Connection;
        event.platform_connection_id = *connid;

        const auto key = connection_key(*pid, *connid);
        if (disconnect) {
            event.type = ConnectionLifecycleEventType::Close;
            const auto active = active_connections_.find(key);
            if (active != active_connections_.end()) {
                event.address_family = active->second.family;
                event.local = active->second.local;
                event.remote = active->second.remote;
                active_connections_.erase(active);
            }
        } else {
            const auto source_address = address_property(record, L"saddr", ipv6);
            const auto destination_address = address_property(record, L"daddr", ipv6);
            const auto source_port = port_property(record, L"sport");
            const auto destination_port = port_property(record, L"dport");
            if (!source_address || !destination_address || !source_port || !destination_port) {
                return;
            }
            if (connect) {
                event.type = ConnectionLifecycleEventType::Connect;
                event.local = NetworkEndpoint{*source_address, *source_port};
                event.remote = NetworkEndpoint{*destination_address, *destination_port};
            } else {
                event.type = ConnectionLifecycleEventType::Accept;
                // For accept, the remote peer is the source and the local accepted endpoint is
                // the destination. This follows the TCP/IP provider's source/destination schema.
                event.local = NetworkEndpoint{*destination_address, *destination_port};
                event.remote = NetworkEndpoint{*source_address, *source_port};
            }
            if (active_connections_.size() >= kMaxActiveConnections) {
                const auto oldest = active_order_.front();
                active_order_.pop_front();
                active_connections_.erase(oldest);
                ++locally_dropped_;
            }
            active_connections_[key] = ActiveConnection{event.address_family, *event.local,
                                                        *event.remote};
            active_order_.push_back(key);
        }

        if (!event.local || !event.remote) return;
        std::lock_guard lock(mutex_);
        if (queue_.size() >= kMaxQueuedEvents) {
            queue_.pop_front();
            ++locally_dropped_;
        }
        queue_.push_back(std::move(event));
        condition_.notify_one();
    }

    LifecycleCapability capability_;
    std::wstring session_name_;
    std::vector<std::byte> properties_buffer_;
    TRACEHANDLE session_handle_{0};
    TRACEHANDLE trace_handle_{INVALID_PROCESSTRACE_HANDLE};
    LONGLONG qpc_frequency_{0};
    std::thread worker_;

    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<ConnectionLifecycleEvent> queue_;
    bool stopping_{false};
    mutable std::uint64_t locally_dropped_{0};

    std::unordered_map<std::uint64_t, ActiveConnection> active_connections_;
    std::deque<std::uint64_t> active_order_;
};

} // namespace

std::unique_ptr<LifecycleObserver> make_lifecycle_observer() {
    return std::make_unique<WindowsEtwLifecycleObserver>();
}

} // namespace neta::platform
