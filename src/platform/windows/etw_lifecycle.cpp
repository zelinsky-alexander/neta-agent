#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iostream>
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
constexpr std::uint64_t kMaxDecodeDiagnostics = 64;

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
std::optional<T> scalar_from_bytes(const std::vector<std::byte>& bytes) {
    if (bytes.size() < sizeof(T)) return std::nullopt;
    T value{};
    std::memcpy(&value, bytes.data(), sizeof(T));
    return value;
}

template <typename T>
std::optional<T> scalar_property(const EVENT_RECORD& record, const wchar_t* name) {
    return scalar_from_bytes<T>(property_bytes(record, name));
}

std::optional<std::uint32_t> pid_property(const EVENT_RECORD& record) {
    if (const auto pid = scalar_property<std::uint32_t>(record, L"PID")) return pid;
    return scalar_property<std::uint32_t>(record, L"pid");
}

std::optional<std::uint64_t> connid_property(const EVENT_RECORD& record) {
    auto bytes = property_bytes(record, L"connid");
    if (bytes.empty()) bytes = property_bytes(record, L"ConnId");
    if (bytes.size() >= sizeof(std::uint64_t)) {
        return scalar_from_bytes<std::uint64_t>(bytes);
    }
    if (const auto value = scalar_from_bytes<std::uint32_t>(bytes)) {
        return static_cast<std::uint64_t>(*value);
    }
    return std::nullopt;
}

std::optional<std::uint16_t> port_property(const EVENT_RECORD& record, const wchar_t* name) {
    const auto bytes = property_bytes(record, name);
    if (bytes.size() >= sizeof(std::uint16_t)) {
        std::uint16_t raw{};
        std::memcpy(&raw, bytes.data(), sizeof(raw));
        return ntohs(raw);
    }
    return std::nullopt;
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

template <typename T>
std::optional<T> raw_scalar(const EVENT_RECORD& record, std::size_t offset) {
    if (record.UserData == nullptr || offset > record.UserDataLength ||
        record.UserDataLength - offset < sizeof(T)) {
        return std::nullopt;
    }
    T value{};
    const auto* bytes = static_cast<const std::byte*>(record.UserData);
    std::memcpy(&value, bytes + offset, sizeof(T));
    return value;
}

std::optional<std::string> raw_address(const EVENT_RECORD& record, std::size_t offset,
                                       bool ipv6) {
    const std::size_t size = ipv6 ? 16U : 4U;
    if (record.UserData == nullptr || offset > record.UserDataLength ||
        record.UserDataLength - offset < size) {
        return std::nullopt;
    }
    const auto* bytes = static_cast<const std::byte*>(record.UserData) + offset;
    char output[INET6_ADDRSTRLEN]{};
    const int family = ipv6 ? AF_INET6 : AF_INET;
    if (InetNtopA(family, bytes, output, static_cast<DWORD>(sizeof(output))) == nullptr) {
        return std::nullopt;
    }
    return std::string(output);
}

std::optional<std::uint16_t> raw_port(const EVENT_RECORD& record, std::size_t offset) {
    const auto raw = raw_scalar<std::uint16_t>(record, offset);
    if (!raw) return std::nullopt;
    return ntohs(*raw);
}

struct DecodedTcpPayload {
    std::uint32_t pid{0};
    std::uint64_t connid{0};
    std::string source_address;
    std::string destination_address;
    std::uint16_t source_port{0};
    std::uint16_t destination_port{0};
};

std::optional<std::uint64_t> raw_pointer_value(const EVENT_RECORD& record, std::size_t offset) {
    const bool provider_32_bit =
        (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
    if (!provider_32_bit) {
        if (const auto value64 = raw_scalar<std::uint64_t>(record, offset)) return value64;
    }
    if (const auto value32 = raw_scalar<std::uint32_t>(record, offset)) {
        return static_cast<std::uint64_t>(*value32);
    }
    return std::nullopt;
}

std::optional<DecodedTcpPayload> decode_documented_mof_layout(const EVENT_RECORD& record,
                                                              bool ipv6,
                                                              bool connect_or_accept) {
    // Microsoft documents the Vista+ kernel TCP/IP MOF payloads as:
    // PID, size, daddr, saddr, dport, sport, ... , connid.  The Pointer
    // qualifier on connid makes the final field pointer-sized on a 64-bit
    // provider.  TDH normally decodes these fields; this raw path is a bounded
    // compatibility fallback for hosts where TDH does not expose one of the
    // extension properties consistently.
    constexpr std::size_t pid_offset = 0;
    const std::size_t destination_address_offset = 8;
    const std::size_t source_address_offset = ipv6 ? 24U : 12U;
    const std::size_t destination_port_offset = ipv6 ? 40U : 16U;
    const std::size_t source_port_offset = ipv6 ? 42U : 18U;
    const std::size_t connid_offset = ipv6
        ? (connect_or_accept ? 64U : 48U)
        : (connect_or_accept ? 40U : 24U);

    const auto pid = raw_scalar<std::uint32_t>(record, pid_offset);
    const auto daddr = raw_address(record, destination_address_offset, ipv6);
    const auto saddr = raw_address(record, source_address_offset, ipv6);
    const auto dport = raw_port(record, destination_port_offset);
    const auto sport = raw_port(record, source_port_offset);
    const auto connid = raw_pointer_value(record, connid_offset);
    if (!pid || !daddr || !saddr || !dport || !sport || !connid) return std::nullopt;

    return DecodedTcpPayload{*pid, *connid, *saddr, *daddr, *sport, *dport};
}

std::optional<DecodedTcpPayload> decode_tcp_payload(const EVENT_RECORD& record, bool ipv6,
                                                    bool connect_or_accept) {
    const auto pid = pid_property(record);
    const auto connid = connid_property(record);
    const auto source_address = address_property(record, L"saddr", ipv6);
    const auto destination_address = address_property(record, L"daddr", ipv6);
    const auto source_port = port_property(record, L"sport");
    const auto destination_port = port_property(record, L"dport");
    if (pid && connid && source_address && destination_address && source_port &&
        destination_port) {
        return DecodedTcpPayload{*pid, *connid, *source_address, *destination_address,
                                 *source_port, *destination_port};
    }
    return decode_documented_mof_layout(record, ipv6, connect_or_accept);
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

struct ActiveKey {
    std::uint32_t pid{0};
    std::uint64_t connid{0};
    bool operator==(const ActiveKey&) const = default;
};

struct ActiveKeyHash {
    std::size_t operator()(const ActiveKey& key) const noexcept {
        const auto mixed = key.connid ^ (static_cast<std::uint64_t>(key.pid) << 32U);
        return std::hash<std::uint64_t>{}(mixed);
    }
};

struct ActiveConnection {
    NetworkAddressFamily family{NetworkAddressFamily::Unknown};
    NetworkEndpoint local;
    NetworkEndpoint remote;
    std::optional<std::uint64_t> process_start_ticks;
    std::uint64_t generation{0};
};

GUID session_guid() noexcept {
    const auto pid = static_cast<std::uint32_t>(GetCurrentProcessId());
    const auto ticks = GetTickCount64();
    GUID value{};
    value.Data1 = 0x4e455441U;
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
    properties->Wnode.ClientContext = 1;
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
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                                   PROCESS_TRACE_MODE_EVENT_RECORD |
                                   PROCESS_TRACE_MODE_RAW_TIMESTAMP;
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
        std::uint64_t dropped = locally_dropped_.load(std::memory_order_relaxed);
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

    void diagnose_decode_failure(const EVENT_RECORD& record, const char* reason) {
        locally_dropped_.fetch_add(1, std::memory_order_relaxed);
        const auto diagnostic_index = decode_diagnostics_.fetch_add(1, std::memory_order_relaxed);
        if (diagnostic_index >= kMaxDecodeDiagnostics) return;
        std::cerr << "NETA ETW decode failure: " << reason
                  << " opcode=" << static_cast<unsigned>(record.EventHeader.EventDescriptor.Opcode)
                  << " version=" << static_cast<unsigned>(record.EventHeader.EventDescriptor.Version)
                  << " flags=0x" << std::hex << record.EventHeader.Flags << std::dec
                  << " header-pid=" << record.EventHeader.ProcessId
                  << " user-data-bytes=" << record.UserDataLength << '\n';
        if (diagnostic_index + 1 == kMaxDecodeDiagnostics) {
            std::cerr << "NETA ETW decode diagnostics suppressed after "
                      << kMaxDecodeDiagnostics << " records\n";
        }
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

    void evict_active_connection_if_needed() {
        while (active_connections_.size() >= kMaxActiveConnections && !active_order_.empty()) {
            const auto [old_key, old_generation] = active_order_.front();
            active_order_.pop_front();
            const auto old = active_connections_.find(old_key);
            if (old == active_connections_.end() || old->second.generation != old_generation) {
                continue;
            }
            active_connections_.erase(old);
            locally_dropped_.fetch_add(1, std::memory_order_relaxed);
            break;
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

        const auto decoded = decode_tcp_payload(record, ipv6, connect || accept);
        if (!decoded) {
            diagnose_decode_failure(record, "missing PID/connid/tuple in TDH and MOF fallback");
            return;
        }

        ConnectionLifecycleEvent event;
        event.timestamp_ns = qpc_to_ns(record.EventHeader.TimeStamp.QuadPart, qpc_frequency_);
        event.provenance = LifecycleProvenance::WindowsEtw;
        event.process.agent_visible.pid = static_cast<std::int64_t>(decoded->pid);
        event.process.agent_visible.tgid = static_cast<std::int64_t>(decoded->pid);
        event.process.kernel = event.process.agent_visible;
        event.process.uid = 0;
        event.process.start_ticks = process_start_identity(decoded->pid);
        event.process.comm = process_name(decoded->pid);
        event.address_family = ipv6 ? NetworkAddressFamily::IPv6 : NetworkAddressFamily::IPv4;
        event.protocol = TransportProtocol::Tcp;
        event.endpoint_kind = disconnect ? TcpEndpointKind::LifecycleTail
                                         : TcpEndpointKind::Connection;
        event.platform_connection_id = decoded->connid;

        const ActiveKey key{decoded->pid, decoded->connid};
        if (disconnect) {
            event.type = ConnectionLifecycleEventType::Close;
            const auto active = active_connections_.find(key);
            if (active != active_connections_.end()) {
                event.address_family = active->second.family;
                event.local = active->second.local;
                event.remote = active->second.remote;
                event.process.start_ticks = active->second.process_start_ticks;
                active_connections_.erase(active);
            } else {
                event.local = NetworkEndpoint{decoded->source_address, decoded->source_port};
                event.remote = NetworkEndpoint{decoded->destination_address,
                                               decoded->destination_port};
            }
        } else {
            // For both CONNECT and ACCEPT the kernel TCP/IP MOF payload is expressed from
            // the process/socket perspective: saddr/sport is the process-local endpoint and
            // daddr/dport is the peer. Keeping that orientation is required for accepted
            // sockets on Win10/Win11; reversing ACCEPT turns the client port into the local
            // server port and breaks exact inbound correlation.
            event.type = connect ? ConnectionLifecycleEventType::Connect
                                 : ConnectionLifecycleEventType::Accept;
            event.local = NetworkEndpoint{decoded->source_address, decoded->source_port};
            event.remote = NetworkEndpoint{decoded->destination_address,
                                           decoded->destination_port};
            evict_active_connection_if_needed();
            const auto generation = ++next_generation_;
            active_connections_[key] = ActiveConnection{event.address_family, *event.local,
                                                        *event.remote, event.process.start_ticks,
                                                        generation};
            active_order_.emplace_back(key, generation);
        }

        if (!event.local || !event.remote) {
            diagnose_decode_failure(record, "lifecycle record decoded without complete tuple");
            return;
        }
        std::lock_guard lock(mutex_);
        if (queue_.size() >= kMaxQueuedEvents) {
            queue_.pop_front();
            locally_dropped_.fetch_add(1, std::memory_order_relaxed);
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
    mutable std::atomic<std::uint64_t> locally_dropped_{0};
    std::atomic<std::uint64_t> decode_diagnostics_{0};

    std::unordered_map<ActiveKey, ActiveConnection, ActiveKeyHash> active_connections_;
    std::deque<std::pair<ActiveKey, std::uint64_t>> active_order_;
    std::uint64_t next_generation_{0};
};

} // namespace

std::unique_ptr<LifecycleObserver> make_lifecycle_observer() {
    return std::make_unique<WindowsEtwLifecycleObserver>();
}

} // namespace neta::platform
