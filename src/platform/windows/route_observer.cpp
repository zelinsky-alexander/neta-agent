#include "neta/platform.hpp"
#include "neta/crypto.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <chrono>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

namespace neta::platform {
namespace {

std::uint64_t wall_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string sockaddr_to_string(const SOCKADDR_INET& address) {
    char buffer[INET6_ADDRSTRLEN]{};
    if (address.si_family == AF_INET) {
        if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&address.Ipv4.sin_addr), buffer,
                      static_cast<DWORD>(sizeof(buffer))) == nullptr) return {};
    } else if (address.si_family == AF_INET6) {
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&address.Ipv6.sin6_addr), buffer,
                      static_cast<DWORD>(sizeof(buffer))) == nullptr) return {};
    } else {
        return {};
    }
    return buffer;
}

bool parse_destination(const std::string& text, SOCKADDR_INET& out) {
    if (InetPtonA(AF_INET, text.c_str(), &out.Ipv4.sin_addr) == 1) {
        out.si_family = AF_INET;
        return true;
    }
    if (InetPtonA(AF_INET6, text.c_str(), &out.Ipv6.sin6_addr) == 1) {
        out.si_family = AF_INET6;
        return true;
    }
    return false;
}

std::string interface_name_utf8(const NET_LUID& luid) {
    wchar_t name[IF_MAX_STRING_SIZE + 1]{};
    if (ConvertInterfaceLuidToNameW(&luid, name, static_cast<SIZE_T>(std::size(name))) != NO_ERROR)
        return {};

    const int required = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 1) return {};
    std::string utf8(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, name, -1, utf8.data(), required, nullptr, nullptr) <= 0)
        return {};
    utf8.pop_back();
    return utf8;
}

class WindowsRouteObserver final : public RouteObserver {
public:
    std::optional<RouteObservation> route_to(const std::string& destination) override {
        SOCKADDR_INET target{};
        if (!parse_destination(destination, target)) return std::nullopt;

        MIB_IPFORWARD_ROW2 route{};
        SOCKADDR_INET source{};
        const DWORD rc = GetBestRoute2(nullptr, 0, nullptr, &target, 0, &route, &source);
        if (rc != NO_ERROR) return std::nullopt;

        RouteObservation out;
        out.destination = destination;
        out.source = sockaddr_to_string(source);
        out.gateway = sockaddr_to_string(route.NextHop);
        out.interface_index = route.InterfaceIndex;
        out.metric = route.Metric;
        out.observed_ns = wall_now_ns();

        NET_LUID luid{};
        if (ConvertInterfaceIndexToLuid(route.InterfaceIndex, &luid) == NO_ERROR)
            out.interface_name = interface_name_utf8(luid);

        std::ostringstream canonical;
        canonical << out.destination << '|' << out.source << '|' << out.gateway << '|'
                  << out.interface_index << '|' << out.interface_name << "||";
        if (out.metric) canonical << *out.metric;
        out.sha256 = sha256_hex(canonical.str());
        return out;
    }
};

} // namespace

std::unique_ptr<RouteObserver> make_route_observer() {
    return std::make_unique<WindowsRouteObserver>();
}

} // namespace neta::platform
