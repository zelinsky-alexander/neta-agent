#include "neta/platform.hpp"
#include "neta/crypto.hpp"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <sstream>

namespace neta::platform {
namespace {

std::uint64_t wall_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

bool add_attr(nlmsghdr* nlh, std::size_t max_len, int type, const void* data, std::size_t len) {
    const auto attr_len = RTA_LENGTH(len);
    const auto new_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(attr_len);
    if (new_len > max_len) return false;
    auto* rta = reinterpret_cast<rtattr*>(reinterpret_cast<char*>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = static_cast<unsigned short>(type);
    rta->rta_len = static_cast<unsigned short>(attr_len);
    std::memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = static_cast<unsigned int>(new_len);
    return true;
}

std::string addr_string(int family, const void* data) {
    std::array<char, INET6_ADDRSTRLEN> buf{};
    return inet_ntop(family, data, buf.data(), buf.size()) ? std::string(buf.data()) : std::string{};
}

class LinuxRouteObserver final : public RouteObserver {
public:
    std::optional<RouteObservation> route_to(const std::string& destination) override {
        std::array<unsigned char, 16> dst{};
        int family = AF_INET;
        std::size_t address_len = 4;
        if (inet_pton(AF_INET, destination.c_str(), dst.data()) != 1) {
            family = AF_INET6;
            address_len = 16;
            if (inet_pton(AF_INET6, destination.c_str(), dst.data()) != 1) return std::nullopt;
        }

        const int raw_fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (raw_fd < 0) return std::nullopt;
        std::unique_ptr<int, void(*)(int*)> fd(new int(raw_fd), [](int* p) { if (p) { ::close(*p); delete p; } });

        struct Request {
            nlmsghdr nlh{};
            rtmsg rtm{};
            std::array<char, 256> attrs{};
        } req;
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
        req.nlh.nlmsg_type = RTM_GETROUTE;
        req.nlh.nlmsg_flags = NLM_F_REQUEST;
        req.nlh.nlmsg_seq = 1;
        req.rtm.rtm_family = static_cast<unsigned char>(family);
        req.rtm.rtm_dst_len = static_cast<unsigned char>(family == AF_INET ? 32 : 128);
        if (!add_attr(&req.nlh, sizeof(req), RTA_DST, dst.data(), address_len)) return std::nullopt;

        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        if (::sendto(*fd, &req, req.nlh.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) < 0)
            return std::nullopt;

        std::array<char, 8192> buffer{};
        const auto received = ::recv(*fd, buffer.data(), buffer.size(), 0);
        if (received <= 0) return std::nullopt;
        int remaining = static_cast<int>(received);
        for (nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buffer.data()); NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type != RTM_NEWROUTE) continue;
            auto* route = reinterpret_cast<rtmsg*>(NLMSG_DATA(nlh));
            RouteObservation out;
            out.destination = destination;
            out.observed_ns = wall_now_ns();
            out.table = route->rtm_table;
            int attr_len = static_cast<int>(RTM_PAYLOAD(nlh));
            for (rtattr* attr = RTM_RTA(route); RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
                if (attr->rta_type == RTA_OIF && RTA_PAYLOAD(attr) >= sizeof(std::uint32_t)) {
                    out.interface_index = *reinterpret_cast<std::uint32_t*>(RTA_DATA(attr));
                    std::array<char, IF_NAMESIZE> name{};
                    if (if_indextoname(out.interface_index, name.data())) out.interface_name = name.data();
                } else if (attr->rta_type == RTA_GATEWAY) {
                    out.gateway = addr_string(family, RTA_DATA(attr));
                } else if (attr->rta_type == RTA_PREFSRC) {
                    out.source = addr_string(family, RTA_DATA(attr));
                } else if (attr->rta_type == RTA_TABLE && RTA_PAYLOAD(attr) >= sizeof(std::uint32_t)) {
                    out.table = *reinterpret_cast<std::uint32_t*>(RTA_DATA(attr));
                } else if (attr->rta_type == RTA_PRIORITY && RTA_PAYLOAD(attr) >= sizeof(std::uint32_t)) {
                    out.metric = *reinterpret_cast<std::uint32_t*>(RTA_DATA(attr));
                }
            }
            std::ostringstream canonical;
            canonical << out.destination << '|' << out.source << '|' << out.gateway << '|'
                      << out.interface_index << '|' << out.interface_name << '|';
            if (out.table) canonical << *out.table;
            canonical << '|';
            if (out.metric) canonical << *out.metric;
            out.sha256 = sha256_hex(canonical.str());
            return out;
        }
        return std::nullopt;
    }
};

} // namespace

std::unique_ptr<RouteObserver> make_route_observer() {
    return std::make_unique<LinuxRouteObserver>();
}

} // namespace neta::platform
