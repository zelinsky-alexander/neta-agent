#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <iphlpapi.h>
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
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

constexpr wchar_t kSchannelProviderName[] = L"Microsoft-Windows-Schannel";
constexpr std::size_t kMaxQueuedEvents = 4096;

bool same_guid(const GUID& left, const GUID& right) noexcept {
    return std::memcmp(&left, &right, sizeof(GUID)) == 0;
}

GUID make_session_guid() noexcept {
    GUID guid{0x6e455441, 0x544c, 0x5357, {0x9a, 0x11, 0x57, 0x49, 0x4e, 0x54, 0x4c, 0x53}};
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
    properties->Wnode.ClientContext = 1; // QPC timestamps.
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
                            nullptr, nullptr) <= 0) return {};
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
            auto value = wide_to_utf8(text, length);
            if (!value.empty()) return value;
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

std::string ipv4_to_string(DWORD address) {
    IN_ADDR in{};
    in.S_un.S_addr = address;
    char buffer[INET_ADDRSTRLEN]{};
    if (InetNtopA(AF_INET, &in, buffer, static_cast<DWORD>(sizeof(buffer))) == nullptr) return {};
    return buffer;
}

std::string ipv6_to_string(const UCHAR address[16]) {
    IN6_ADDR in{};
    std::memcpy(&in, address, sizeof(in));
    char buffer[INET6_ADDRSTRLEN]{};
    if (InetNtopA(AF_INET6, &in, buffer, static_cast<DWORD>(sizeof(buffer))) == nullptr) return {};
    return buffer;
}

struct TcpCandidate {
    DWORD pid{0};
    std::string local_address;
    std::uint16_t local_port{0};
    std::string remote_address;
    std::uint16_t remote_port{0};
    bool local_is_listener{false};
};

void collect_ipv4_candidates(DWORD pid, std::vector<TcpCandidate>& out) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) !=
        ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<std::byte> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    std::vector<std::pair<DWORD,std::uint16_t>> listeners;
    for (DWORD i=0;i<table->dwNumEntries;++i) {
        const auto& row=table->table[i];
        if (row.dwOwningPid==pid && row.dwState==MIB_TCP_STATE_LISTEN)
            listeners.emplace_back(row.dwLocalAddr, ntohs(static_cast<u_short>(row.dwLocalPort)));
    }
    for (DWORD i=0;i<table->dwNumEntries;++i) {
        const auto& row=table->table[i];
        if (row.dwOwningPid!=pid || row.dwState==MIB_TCP_STATE_LISTEN ||
            row.dwState==MIB_TCP_STATE_CLOSED || row.dwState==MIB_TCP_STATE_DELETE_TCB) continue;
        TcpCandidate c;
        c.pid=pid;
        c.local_address=ipv4_to_string(row.dwLocalAddr);
        c.local_port=ntohs(static_cast<u_short>(row.dwLocalPort));
        c.remote_address=ipv4_to_string(row.dwRemoteAddr);
        c.remote_port=ntohs(static_cast<u_short>(row.dwRemotePort));
        c.local_is_listener=std::any_of(listeners.begin(),listeners.end(),[&](const auto& item){
            return item.second==c.local_port && (item.first==row.dwLocalAddr || item.first==0);
        });
        if (!c.local_address.empty() && !c.remote_address.empty() && c.remote_port!=0) out.push_back(std::move(c));
    }
}

void collect_ipv6_candidates(DWORD pid, std::vector<TcpCandidate>& out) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) !=
        ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<std::byte> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;
    const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
    std::vector<std::uint16_t> listeners;
    for (DWORD i=0;i<table->dwNumEntries;++i) {
        const auto& row=table->table[i];
        if (row.dwOwningPid==pid && row.dwState==MIB_TCP_STATE_LISTEN)
            listeners.push_back(ntohs(static_cast<u_short>(row.dwLocalPort)));
    }
    for (DWORD i=0;i<table->dwNumEntries;++i) {
        const auto& row=table->table[i];
        if (row.dwOwningPid!=pid || row.dwState==MIB_TCP_STATE_LISTEN ||
            row.dwState==MIB_TCP_STATE_CLOSED || row.dwState==MIB_TCP_STATE_DELETE_TCB) continue;
        TcpCandidate c;
        c.pid=pid;
        c.local_address=ipv6_to_string(row.ucLocalAddr);
        c.local_port=ntohs(static_cast<u_short>(row.dwLocalPort));
        c.remote_address=ipv6_to_string(row.ucRemoteAddr);
        c.remote_port=ntohs(static_cast<u_short>(row.dwRemotePort));
        c.local_is_listener=std::find(listeners.begin(),listeners.end(),c.local_port)!=listeners.end();
        if (!c.local_address.empty() && !c.remote_address.empty() && c.remote_port!=0) out.push_back(std::move(c));
    }
}

bool text_matches_address(const std::string& hint, const std::string& address) {
    return hint.empty() || hint == address;
}

std::optional<TcpCandidate> unique_tcp_candidate(const EVENT_RECORD& record, DWORD pid) {
    std::vector<TcpCandidate> candidates;
    collect_ipv4_candidates(pid,candidates);
    collect_ipv6_candidates(pid,candidates);
    if (candidates.empty()) return std::nullopt;

    const auto remote_hint=first_text_property(record,{L"RemoteAddress",L"RemoteAddr",L"ServerAddress",L"PeerAddress"});
    const auto local_hint=first_text_property(record,{L"LocalAddress",L"LocalAddr",L"ClientAddress"});
    const auto remote_port=first_unsigned_property(record,{L"RemotePort",L"ServerPort",L"PeerPort"});
    const auto local_port=first_unsigned_property(record,{L"LocalPort",L"ClientPort"});

    std::vector<TcpCandidate> filtered;
    for (const auto& c : candidates) {
        if (!text_matches_address(remote_hint,c.remote_address) || !text_matches_address(local_hint,c.local_address)) continue;
        if (remote_port && *remote_port<=65535 && c.remote_port!=static_cast<std::uint16_t>(*remote_port)) continue;
        if (local_port && *local_port<=65535 && c.local_port!=static_cast<std::uint16_t>(*local_port)) continue;
        filtered.push_back(c);
    }
    if (filtered.size()==1) return filtered.front();
    return std::nullopt;
}

std::optional<std::uint64_t> process_creation_key(DWORD pid) {
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if (process==nullptr) return std::nullopt;
    FILETIME creation{},exit{},kernel{},user{};
    const BOOL ok=GetProcessTimes(process,&creation,&exit,&kernel,&user);
    CloseHandle(process);
    if (ok==FALSE) return std::nullopt;
    ULARGE_INTEGER value{};
    value.LowPart=creation.dwLowDateTime;
    value.HighPart=creation.dwHighDateTime;
    return value.QuadPart;
}

std::string process_image(DWORD pid) {
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if (process==nullptr) return {};
    wchar_t path[32768]{};
    DWORD length=static_cast<DWORD>(std::size(path));
    const BOOL ok=QueryFullProcessImageNameW(process,0,path,&length);
    CloseHandle(process);
    if (ok==FALSE) return {};
    return wide_to_utf8(path,length);
}

std::string leaf_name(const std::string& path) {
    const auto slash=path.find_last_of("\\/");
    return slash==std::string::npos?path:path.substr(slash+1U);
}

std::string protocol_text(const EVENT_RECORD& record) {
    auto value=first_text_property(record,{L"Protocol",L"ProtocolName",L"TlsVersion",L"TLSVersion",L"Version"});
    if (!value.empty()) return value;
    const auto numeric=first_unsigned_property(record,{L"Protocol",L"ProtocolVersion",L"TlsVersion"});
    if (!numeric) return {};
    switch (*numeric) {
        case 0x0301: return "TLSv1.0";
        case 0x0302: return "TLSv1.1";
        case 0x0303: return "TLSv1.2";
        case 0x0304: return "TLSv1.3";
        default: return "0x" + std::to_string(*numeric);
    }
}

std::string cipher_text(const EVENT_RECORD& record) {
    auto value=first_text_property(record,{L"CipherSuite",L"CipherSuiteName",L"Cipher",L"CipherName"});
    if (!value.empty()) return value;
    const auto numeric=first_unsigned_property(record,{L"CipherSuite",L"Cipher"});
    return numeric?std::to_string(*numeric):std::string{};
}

class WindowsSchannelTlsObserver final : public TlsSessionObserver {
public:
    WindowsSchannelTlsObserver():session_guid_(make_session_guid()) {
        capability_.source="windows:schannel-etw";
        capability_.endpoint="Microsoft-Windows-Schannel";
        capability_.receive_drop_counter=true;

        LARGE_INTEGER frequency{};
        if (QueryPerformanceFrequency(&frequency)==FALSE || frequency.QuadPart<=0) {
            capability_.unavailable_reason="QueryPerformanceFrequency failed for Schannel ETW";
            return;
        }
        qpc_frequency_=frequency.QuadPart;
        const auto provider=provider_guid_by_name(kSchannelProviderName);
        if (!provider) {
            capability_.unavailable_reason="Microsoft-Windows-Schannel ETW provider is not registered";
            return;
        }
        provider_guid_=*provider;
        session_name_=L"NETA-TLS-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
        properties_buffer_=trace_properties_buffer(session_name_,session_guid_);
        auto* properties=reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer_.data());
        const ULONG start=StartTraceW(&session_handle_,session_name_.c_str(),properties);
        if (start!=ERROR_SUCCESS) {
            capability_.unavailable_reason="StartTraceW for Schannel ETW failed with Windows error "+std::to_string(start);
            session_handle_=0;
            return;
        }
        const ULONG enable=EnableTraceEx2(session_handle_,&provider_guid_,EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                          TRACE_LEVEL_VERBOSE,~0ULL,0,0,nullptr);
        if (enable!=ERROR_SUCCESS) {
            capability_.unavailable_reason="EnableTraceEx2 for Microsoft-Windows-Schannel failed with Windows error "+std::to_string(enable);
            stop_session();
            return;
        }
        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName=const_cast<LPWSTR>(session_name_.c_str());
        logfile.ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD|PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        logfile.EventRecordCallback=&WindowsSchannelTlsObserver::callback;
        logfile.Context=this;
        trace_handle_=OpenTraceW(&logfile);
        if (trace_handle_==INVALID_PROCESSTRACE_HANDLE) {
            const DWORD error=GetLastError();
            stop_session();
            capability_.unavailable_reason="OpenTraceW for Schannel ETW failed with Windows error "+std::to_string(error);
            return;
        }
        // ETW event ownership is kernel supplied, so PID provenance does not rely on
        // self-reported application data. Tuple attachment remains conservative: an
        // event is emitted only when exactly one live TCP tuple matches the process
        // (and any address/port hints exposed by the provider).
        capability_.application_instrumentation=true;
        capability_.sender_credentials_verified=true;
        worker_=std::thread([this]{TRACEHANDLE handle=trace_handle_;static_cast<void>(ProcessTrace(&handle,1,nullptr,nullptr));});
    }

    ~WindowsSchannelTlsObserver() override {
        stop_session();
        if (trace_handle_!=INVALID_PROCESSTRACE_HANDLE) {
            static_cast<void>(CloseTrace(trace_handle_));
            trace_handle_=INVALID_PROCESSTRACE_HANDLE;
        }
        if (worker_.joinable()) worker_.join();
    }

    const TlsSessionCapability& capability() const noexcept override { return capability_; }

    TlsSessionHealth health() const override {
        TlsSessionHealth result;
        std::uint64_t dropped=locally_dropped_.load(std::memory_order_relaxed);
        if (session_handle_!=0) {
            auto buffer=trace_properties_buffer(session_name_,session_guid_);
            auto* properties=reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
            if (ControlTraceW(session_handle_,session_name_.c_str(),properties,EVENT_TRACE_CONTROL_QUERY)==ERROR_SUCCESS)
                dropped+=properties->EventsLost;
        }
        result.dropped_events=dropped;
        result.rejected_events=rejected_.load(std::memory_order_relaxed);
        return result;
    }

    std::vector<TlsSessionObservation> poll(std::chrono::milliseconds timeout) override {
        std::unique_lock lock(mutex_);
        if (queue_.empty() && timeout.count()>0)
            condition_.wait_for(lock,timeout,[this]{return !queue_.empty()||stopping_;});
        std::vector<TlsSessionObservation> result;
        result.reserve(queue_.size());
        while (!queue_.empty()) {result.push_back(std::move(queue_.front()));queue_.pop_front();}
        return result;
    }

private:
    static void WINAPI callback(EVENT_RECORD* record) {
        if (record==nullptr || record->UserContext==nullptr) return;
        static_cast<WindowsSchannelTlsObserver*>(record->UserContext)->consume(*record);
    }

    void consume(const EVENT_RECORD& record) {
        if (std::memcmp(&record.EventHeader.ProviderId,&provider_guid_,sizeof(GUID))!=0) return;
        DWORD pid=record.EventHeader.ProcessId;
        if (auto property=first_unsigned_property(record,{L"ProcessId",L"ProcessID",L"PID"});
            property && *property>0 && *property<=MAXDWORD) pid=static_cast<DWORD>(*property);
        if (pid==0) {rejected_.fetch_add(1,std::memory_order_relaxed);return;}

        auto tls_version=protocol_text(record);
        auto cipher=cipher_text(record);
        auto alpn=first_text_property(record,{L"ApplicationProtocol",L"ALPN",L"Alpn"});
        auto sni=first_text_property(record,{L"ServerName",L"TargetName",L"SNI",L"HostName"});
        // Ignore generic Schannel diagnostics that do not expose negotiated-session
        // metadata. This prevents error/configuration events from masquerading as
        // successful TLS observations.
        if (tls_version.empty() && cipher.empty() && alpn.empty()) return;

        const auto tuple=unique_tcp_candidate(record,pid);
        if (!tuple) {rejected_.fetch_add(1,std::memory_order_relaxed);return;}

        TlsSessionObservation observation;
        observation.observed_ns=qpc_to_ns(record.EventHeader.TimeStamp.QuadPart,qpc_frequency_);
        observation.local_role=tuple->local_is_listener?TlsSessionRole::Server:TlsSessionRole::Client;
        observation.process.pid=static_cast<std::int64_t>(pid);
        observation.process.start_ticks=process_creation_key(pid);
        observation.process.executable_path=process_image(pid);
        observation.process.comm=leaf_name(observation.process.executable_path);
        observation.local={tuple->local_address,tuple->local_port};
        observation.remote={tuple->remote_address,tuple->remote_port};
        observation.tls_version=std::move(tls_version);
        observation.cipher=std::move(cipher);
        observation.alpn=std::move(alpn);
        observation.sni=std::move(sni);
        observation.fidelity=EvidenceFidelity::StronglyCorrelated;
        observation.source="windows:schannel-etw";

        std::lock_guard lock(mutex_);
        if (queue_.size()>=kMaxQueuedEvents) {
            queue_.pop_front();
            locally_dropped_.fetch_add(1,std::memory_order_relaxed);
        }
        queue_.push_back(std::move(observation));
        condition_.notify_one();
    }

    void stop_session() noexcept {
        {
            std::lock_guard lock(mutex_);
            stopping_=true;
            condition_.notify_all();
        }
        if (session_handle_!=0) {
            auto buffer=trace_properties_buffer(session_name_,session_guid_);
            auto* properties=reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
            static_cast<void>(ControlTraceW(session_handle_,session_name_.c_str(),properties,EVENT_TRACE_CONTROL_STOP));
            session_handle_=0;
        }
    }

    GUID session_guid_{};
    GUID provider_guid_{};
    LONGLONG qpc_frequency_{0};
    std::wstring session_name_;
    std::vector<std::byte> properties_buffer_;
    TRACEHANDLE session_handle_{0};
    TRACEHANDLE trace_handle_{INVALID_PROCESSTRACE_HANDLE};
    std::thread worker_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<TlsSessionObservation> queue_;
    bool stopping_{false};
    std::atomic<std::uint64_t> locally_dropped_{0};
    std::atomic<std::uint64_t> rejected_{0};
    TlsSessionCapability capability_;
};

class UnavailableWindowsTlsObserver final : public TlsSessionObserver {
public:
    explicit UnavailableWindowsTlsObserver(std::string reason) {
        capability_.source="windows:schannel-etw";
        capability_.endpoint="Microsoft-Windows-Schannel";
        capability_.unavailable_reason=std::move(reason);
    }
    const TlsSessionCapability& capability() const noexcept override {return capability_;}
    TlsSessionHealth health() const override {return {};}
    std::vector<TlsSessionObservation> poll(std::chrono::milliseconds) override {return {};}
private:
    TlsSessionCapability capability_;
};

} // namespace

std::unique_ptr<TlsSessionObserver> make_windows_tls_session_observer() {
    try {
        auto observer=std::make_unique<WindowsSchannelTlsObserver>();
        if (!observer->capability().available())
            return std::make_unique<UnavailableWindowsTlsObserver>(observer->capability().unavailable_reason);
        return observer;
    } catch (const std::exception& error) {
        return std::make_unique<UnavailableWindowsTlsObserver>(error.what());
    }
}

} // namespace neta::platform
