#include "neta/platform.hpp"

#include <arpa/inet.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace neta::platform {
namespace {

class Fd {
public:
    explicit Fd(int fd = -1) : fd_(fd) {}
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};

std::string address_to_string(int family, const std::uint32_t* address) {
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (!inet_ntop(family, address, buffer.data(), buffer.size())) return {};
    return buffer.data();
}

std::uint64_t steady_now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
           static_cast<std::uint64_t>(ts.tv_nsec);
}

class LinuxConnectionObserver final : public ConnectionObserver {
public:
    std::vector<SocketObservation> snapshot() override {
        std::vector<SocketObservation> result;
        collect(AF_INET, result);
        collect(AF_INET6, result);
        return result;
    }

private:
    void collect(std::uint8_t family, std::vector<SocketObservation>& out) {
        Fd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG));
        if (fd.get() < 0)
            throw std::runtime_error("NETLINK_SOCK_DIAG socket failed: " + std::string(std::strerror(errno)));

        struct Request {
            nlmsghdr nlh{};
            inet_diag_req_v2 req{};
        } request;

        request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(inet_diag_req_v2));
        request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
        request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.nlh.nlmsg_seq = family;
        request.req.sdiag_family = family;
        request.req.sdiag_protocol = IPPROTO_TCP;
        request.req.idiag_states = 0xFFFFFFFFU;
        request.req.idiag_ext = static_cast<std::uint8_t>(1U << (INET_DIAG_INFO - 1));

        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        iovec iov{&request, request.nlh.nlmsg_len};
        msghdr msg{&kernel, sizeof(kernel), &iov, 1, nullptr, 0, 0};
        if (::sendmsg(fd.get(), &msg, 0) < 0)
            throw std::runtime_error("SOCK_DIAG request failed: " + std::string(std::strerror(errno)));

        std::array<char, 64 * 1024> buffer{};
        bool done = false;
        while (!done) {
            const auto received = ::recv(fd.get(), buffer.data(), buffer.size(), 0);
            if (received < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("SOCK_DIAG receive failed: " + std::string(std::strerror(errno)));
            }
            if (received == 0) break;

            int remaining = static_cast<int>(received);
            for (nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buffer.data()); NLMSG_OK(nlh, remaining);
                 nlh = NLMSG_NEXT(nlh, remaining)) {
                if (nlh->nlmsg_type == NLMSG_DONE) { done = true; break; }
                if (nlh->nlmsg_type == NLMSG_ERROR) {
                    const auto* err = reinterpret_cast<nlmsgerr*>(NLMSG_DATA(nlh));
                    if (err->error == -ENOENT || err->error == -EOPNOTSUPP) return;
                    if (err->error != 0)
                        throw std::runtime_error("SOCK_DIAG kernel error: " + std::to_string(-err->error));
                    continue;
                }
                if (nlh->nlmsg_type != SOCK_DIAG_BY_FAMILY) continue;

                const auto* diag = reinterpret_cast<const inet_diag_msg*>(NLMSG_DATA(nlh));
                SocketObservation item;
                item.local_ip = address_to_string(diag->idiag_family, diag->id.idiag_src);
                item.remote_ip = address_to_string(diag->idiag_family, diag->id.idiag_dst);
                item.local_port = ntohs(diag->id.idiag_sport);
                item.remote_port = ntohs(diag->id.idiag_dport);
                item.socket_inode = diag->idiag_inode;
                item.uid = diag->idiag_uid;
                item.socket_cookie = static_cast<std::uint64_t>(diag->id.idiag_cookie[0]) |
                                     (static_cast<std::uint64_t>(diag->id.idiag_cookie[1]) << 32U);
                item.transport.observed_ns = steady_now_ns();
                item.transport.state = diag->idiag_state;
                item.transport.send_queue_bytes = diag->idiag_wqueue;
                item.transport.recv_queue_bytes = diag->idiag_rqueue;

                int attr_len = static_cast<int>(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag)));
                auto* attr = reinterpret_cast<rtattr*>(reinterpret_cast<char*>(const_cast<inet_diag_msg*>(diag)) + NLMSG_ALIGN(sizeof(*diag)));
                for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
                    if (attr->rta_type == INET_DIAG_INFO && RTA_PAYLOAD(attr) >= sizeof(tcp_info)) {
                        const auto* info = reinterpret_cast<const tcp_info*>(RTA_DATA(attr));
                        item.transport.rtt_us = info->tcpi_rtt;
                        item.transport.rtt_variance_us = info->tcpi_rttvar;
                        item.transport.total_retrans = info->tcpi_total_retrans;
                        item.transport.lost = info->tcpi_lost;
                        item.transport.unacked = info->tcpi_unacked;
                        item.transport.snd_cwnd = info->tcpi_snd_cwnd;
                        item.transport.snd_ssthresh = info->tcpi_snd_ssthresh;
                        item.transport.snd_mss = info->tcpi_snd_mss;
                        item.transport.rcv_mss = info->tcpi_rcv_mss;
                    }
                }
                out.push_back(std::move(item));
            }
        }
    }
};

} // namespace

bool eligible_for_new_connection(const SocketObservation& socket) {
    switch (socket.transport.state) {
        case TCP_TIME_WAIT:
        case TCP_CLOSE:
        case TCP_LISTEN:
            return false;
        default:
            return true;
    }
}

std::unique_ptr<ConnectionObserver> make_connection_observer() {
    return std::make_unique<LinuxConnectionObserver>();
}

} // namespace neta::platform
