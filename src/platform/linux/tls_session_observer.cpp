#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "neta/platform.hpp"

#include "tls_session_decoder.hpp"
#include "tls_session_wire.h"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace neta::platform {
namespace {

std::string configured_endpoint() {
    const char* value = std::getenv("NETA_TLS_CONTEXT_SOCKET");
    if (value && *value != '\0') return value;
    return "@neta-agent-tls-uid-" +
           std::to_string(static_cast<unsigned long long>(::getuid()));
}

bool make_unix_address(const std::string& endpoint, sockaddr_un& address,
                       socklen_t& length) {
    address = {};
    address.sun_family = AF_UNIX;
    if (endpoint.empty()) return false;
    if (endpoint.front() == '@') {
        const auto name = endpoint.substr(1);
        if (name.size() + 1 > sizeof(address.sun_path)) return false;
        address.sun_path[0] = '\0';
        std::memcpy(address.sun_path + 1, name.data(), name.size());
        length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());
        return true;
    }
    if (endpoint.size() >= sizeof(address.sun_path)) return false;
    std::memcpy(address.sun_path, endpoint.c_str(), endpoint.size() + 1);
    length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + endpoint.size() + 1);
    return true;
}

class LinuxTlsSessionObserver final : public TlsSessionObserver {
public:
    LinuxTlsSessionObserver() {
#ifndef NETA_TLS_CONTEXT_SHIM_BUILT
        throw std::runtime_error("OpenSSL TLS context instrumentation shim is not built in this configuration");
#endif
        endpoint_ = configured_endpoint();
        sockaddr_un address{};
        socklen_t length = 0;
        if (!make_unix_address(endpoint_, address, length)) {
            throw std::runtime_error("invalid TLS context socket endpoint");
        }
        fd_ = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd_ < 0) {
            throw std::runtime_error("creating TLS context socket failed: " +
                                     std::string(std::strerror(errno)));
        }
        int enabled = 1;
        if (::setsockopt(fd_, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) {
            throw std::runtime_error("enabling TLS context sender credentials failed: " +
                                     std::string(std::strerror(errno)));
        }
        int receive_buffer = 1024 * 1024;
        static_cast<void>(::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF,
                                      &receive_buffer, sizeof(receive_buffer)));
#ifdef SO_RXQ_OVFL
        if (::setsockopt(fd_, SOL_SOCKET, SO_RXQ_OVFL, &enabled, sizeof(enabled)) == 0) {
            overflow_counter_enabled_ = true;
        }
#endif
        if (::bind(fd_, reinterpret_cast<const sockaddr*>(&address), length) != 0) {
            throw std::runtime_error("binding TLS context socket " + endpoint_ + " failed: " +
                                     std::string(std::strerror(errno)));
        }
        capability_.application_instrumentation = true;
        capability_.sender_credentials_verified = true;
        capability_.receive_drop_counter = overflow_counter_enabled_;
        capability_.source = "OpenSSL 3 application instrumentation";
        capability_.endpoint = endpoint_;
    }

    ~LinuxTlsSessionObserver() override {
        if (fd_ >= 0) ::close(fd_);
    }

    const TlsSessionCapability& capability() const noexcept override { return capability_; }

    TlsSessionHealth health() const override {
        TlsSessionHealth value;
        if (overflow_counter_enabled_) value.dropped_events = dropped_events_;
        value.rejected_events = rejected_events_;
        return value;
    }

    std::vector<TlsSessionObservation> poll(std::chrono::milliseconds timeout) override {
        std::vector<TlsSessionObservation> observations;
        if (fd_ < 0) return observations;
        const auto bounded = std::clamp<std::int64_t>(
            timeout.count(), 0, static_cast<std::int64_t>(std::numeric_limits<int>::max()));
        pollfd descriptor{fd_, POLLIN, 0};
        const int ready = ::poll(&descriptor, 1, static_cast<int>(bounded));
        if (ready < 0) {
            if (errno == EINTR) return observations;
            throw std::runtime_error("polling TLS context socket failed: " +
                                     std::string(std::strerror(errno)));
        }
        if (ready == 0 || (descriptor.revents & POLLIN) == 0) return observations;

        constexpr std::size_t max_batch = 256;
        while (observations.size() < max_batch) {
            neta_tls_session_wire_event wire{};
            std::array<std::byte, CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(sizeof(std::uint32_t))>
                control{};
            iovec iov{&wire, sizeof(wire)};
            msghdr message{};
            message.msg_iov = &iov;
            message.msg_iovlen = 1;
            message.msg_control = control.data();
            message.msg_controllen = control.size();
            const auto received = ::recvmsg(fd_, &message, MSG_DONTWAIT);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                throw std::runtime_error("receiving TLS context event failed: " +
                                         std::string(std::strerror(errno)));
            }
            if (received == 0 || (message.msg_flags & MSG_TRUNC) != 0) {
                ++rejected_events_;
                continue;
            }

            std::optional<std::int64_t> credential_pid;
            std::optional<std::uint32_t> credential_uid;
            for (cmsghdr* header = CMSG_FIRSTHDR(&message); header;
                 header = CMSG_NXTHDR(&message, header)) {
                if (header->cmsg_level != SOL_SOCKET) continue;
                if (header->cmsg_type == SCM_CREDENTIALS &&
                    header->cmsg_len >= CMSG_LEN(sizeof(ucred))) {
                    ucred credentials{};
                    std::memcpy(&credentials, CMSG_DATA(header), sizeof(credentials));
                    credential_pid = static_cast<std::int64_t>(credentials.pid);
                    credential_uid = static_cast<std::uint32_t>(credentials.uid);
                }
#ifdef SO_RXQ_OVFL
                else if (header->cmsg_type == SO_RXQ_OVFL &&
                         header->cmsg_len >= CMSG_LEN(sizeof(std::uint32_t))) {
                    std::uint32_t dropped = 0;
                    std::memcpy(&dropped, CMSG_DATA(header), sizeof(dropped));
                    dropped_events_ = std::max<std::uint64_t>(dropped_events_, dropped);
                }
#endif
            }
            const auto* first = reinterpret_cast<const std::byte*>(&wire);
            const auto decoded = linux_tls::decode_tls_session_event(
                {first, static_cast<std::size_t>(received)}, credential_pid, credential_uid);
            if (decoded.observation) observations.push_back(*decoded.observation);
            else ++rejected_events_;
        }
        return observations;
    }

private:
    int fd_{-1};
    std::string endpoint_;
    bool overflow_counter_enabled_{false};
    std::uint64_t dropped_events_{0};
    std::uint64_t rejected_events_{0};
    TlsSessionCapability capability_;
};

class UnavailableTlsSessionObserver final : public TlsSessionObserver {
public:
    explicit UnavailableTlsSessionObserver(std::string reason) {
        capability_.source = "OpenSSL 3 application instrumentation";
        capability_.endpoint = configured_endpoint();
        capability_.unavailable_reason = std::move(reason);
    }
    const TlsSessionCapability& capability() const noexcept override { return capability_; }
    TlsSessionHealth health() const override { return {}; }
    std::vector<TlsSessionObservation> poll(std::chrono::milliseconds) override { return {}; }
private:
    TlsSessionCapability capability_;
};

} // namespace

std::unique_ptr<TlsSessionObserver> make_tls_session_observer() {
    try {
        return std::make_unique<LinuxTlsSessionObserver>();
    } catch (const std::exception& error) {
        return std::make_unique<UnavailableTlsSessionObserver>(error.what());
    }
}

} // namespace neta::platform
