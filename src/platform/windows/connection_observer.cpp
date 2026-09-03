#include "neta/platform.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

std::uint64_t now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
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

TcpEndpointKind endpoint_kind(DWORD state) {
    if (state == MIB_TCP_STATE_LISTEN) return TcpEndpointKind::Listener;
    if (state == MIB_TCP_STATE_CLOSED || state == MIB_TCP_STATE_DELETE_TCB) {
        return TcpEndpointKind::LifecycleTail;
    }
    return TcpEndpointKind::Connection;
}

void collect_ipv4(std::vector<SocketObservation>& out) {
    ULONG size = 0;
    DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                                   TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER) {
        if (rc == NO_ERROR) return;
        throw std::runtime_error("GetExtendedTcpTable(AF_INET) size query failed");
    }

    std::vector<std::byte> buffer(size);
    rc = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET,
                             TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR) throw std::runtime_error("GetExtendedTcpTable(AF_INET) failed");

    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    const std::uint64_t observed = now_ns();
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        SocketObservation socket;
        socket.owning_pid = static_cast<std::int64_t>(row.dwOwningPid);
        socket.local_ip = ipv4_to_string(row.dwLocalAddr);
        socket.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        socket.remote_ip = ipv4_to_string(row.dwRemoteAddr);
        socket.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        socket.endpoint_kind = endpoint_kind(row.dwState);
        socket.transport.observed_ns = observed;
        socket.transport.state = static_cast<std::uint8_t>(row.dwState & 0xffU);
        out.push_back(std::move(socket));
    }
}

void collect_ipv6(std::vector<SocketObservation>& out) {
    ULONG size = 0;
    DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6,
                                   TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER) {
        if (rc == NO_ERROR) return;
        throw std::runtime_error("GetExtendedTcpTable(AF_INET6) size query failed");
    }

    std::vector<std::byte> buffer(size);
    rc = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET6,
                             TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR) throw std::runtime_error("GetExtendedTcpTable(AF_INET6) failed");

    const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
    const std::uint64_t observed = now_ns();
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        SocketObservation socket;
        socket.owning_pid = static_cast<std::int64_t>(row.dwOwningPid);
        socket.local_ip = ipv6_to_string(row.ucLocalAddr);
        socket.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        socket.remote_ip = ipv6_to_string(row.ucRemoteAddr);
        socket.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        socket.endpoint_kind = endpoint_kind(row.dwState);
        socket.transport.observed_ns = observed;
        socket.transport.state = static_cast<std::uint8_t>(row.dwState & 0xffU);
        out.push_back(std::move(socket));
    }
}

class WindowsConnectionObserver final : public ConnectionObserver {
public:
    std::vector<SocketObservation> snapshot() override {
        std::vector<SocketObservation> result;
        collect_ipv4(result);
        collect_ipv6(result);
        return result;
    }
};

} // namespace

std::unique_ptr<ConnectionObserver> make_connection_observer() {
    return std::make_unique<WindowsConnectionObserver>();
}

} // namespace neta::platform
