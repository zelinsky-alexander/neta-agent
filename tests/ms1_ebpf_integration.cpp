#include "neta/platform.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

class Fd {
public:
    explicit Fd(int value = -1) : value_(value) {}
    ~Fd() { if (value_ >= 0) ::close(value_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(other.value_) { other.value_ = -1; }
    Fd& operator=(Fd&&) = delete;
    int get() const { return value_; }
    void close_now() {
        if (value_ >= 0) ::close(value_);
        value_ = -1;
    }
private:
    int value_;
};

Fd socket_or_throw() {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error(std::strerror(errno));
    return Fd(fd);
}

std::uint64_t cookie_for(int fd) {
    std::uint64_t cookie = 0;
    socklen_t size = sizeof(cookie);
    if (::getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &size) != 0) {
        throw std::runtime_error("SO_COOKIE failed: " + std::string(std::strerror(errno)));
    }
    return cookie;
}

std::uint16_t local_port_for(int fd) {
    sockaddr_in address{};
    socklen_t size = sizeof(address);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
        throw std::runtime_error("getsockname failed: " + std::string(std::strerror(errno)));
    }
    return ntohs(address.sin_port);
}

Fd connect_loopback(std::uint16_t port) {
    auto client = socket_or_throw();
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(client.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        throw std::runtime_error("connect failed: " + std::string(std::strerror(errno)));
    }
    return client;
}

Fd accept_or_throw(int listener) {
    const int fd = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd < 0) throw std::runtime_error("accept failed: " + std::string(std::strerror(errno)));
    return Fd(fd);
}

bool has_event(const std::vector<neta::ConnectionLifecycleEvent>& events,
               neta::ConnectionLifecycleEventType type, std::uint64_t cookie) {
    for (const auto& event : events) {
        if (event.type == type && event.socket_cookie == cookie) return true;
    }
    return false;
}

bool has_accept_event(const std::vector<neta::ConnectionLifecycleEvent>& events,
                      std::uint16_t local_port, std::uint16_t remote_port) {
    for (const auto& event : events) {
        if (event.type == neta::ConnectionLifecycleEventType::Accept &&
            event.local && event.local->port == local_port &&
            event.remote && event.remote->port == remote_port &&
            !event.socket_cookie) {
            return true;
        }
    }
    return false;
}

std::string endpoint_text(const std::optional<neta::NetworkEndpoint>& endpoint) {
    if (!endpoint) return "<unavailable>";
    return endpoint->address + ':' +
           (endpoint->port ? std::to_string(*endpoint->port) : "<unavailable>");
}

void dump_event(std::size_t index, const neta::ConnectionLifecycleEvent& event) {
    std::cerr << "event[" << index << "]"
              << " type=" << neta::to_string(event.type)
              << " kernel_pid=" << (event.process.kernel.pid
                  ? std::to_string(*event.process.kernel.pid) : "<unavailable>")
              << " kernel_tgid=" << (event.process.kernel.tgid
                  ? std::to_string(*event.process.kernel.tgid) : "<unavailable>")
              << " agent_pid=" << (event.process.agent_visible.pid
                  ? std::to_string(*event.process.agent_visible.pid) : "<unavailable>")
              << " agent_tgid=" << (event.process.agent_visible.tgid
                  ? std::to_string(*event.process.agent_visible.tgid) : "<unavailable>")
              << " agent_pidns_dev=" << (event.process.agent_pid_namespace
                  ? std::to_string(event.process.agent_pid_namespace->device) : "<unavailable>")
              << " agent_pidns_ino=" << (event.process.agent_pid_namespace
                  ? std::to_string(event.process.agent_pid_namespace->inode) : "<unavailable>")
              << " uid=" << (event.process.uid
                  ? std::to_string(*event.process.uid) : "<unavailable>")
              << " cookie_present=" << (event.socket_cookie ? 1 : 0)
              << " cookie=" << (event.socket_cookie
                  ? std::to_string(*event.socket_cookie) : "<unavailable>")
              << " local=" << endpoint_text(event.local)
              << " remote=" << endpoint_text(event.remote) << '\n';
}

} // namespace

int main() {
    try {
        auto lifecycle = neta::platform::make_lifecycle_observer();
        if (!lifecycle->capability().available()) {
            std::cout << "SKIP: " << lifecycle->capability().unavailable_reason << '\n';
            return 77;
        }

        auto listener = socket_or_throw();
        const int enabled = 1;
        if (::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
            throw std::runtime_error("SO_REUSEADDR failed");
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(listener.get(), 4) != 0) {
            throw std::runtime_error("listener setup failed: " + std::string(std::strerror(errno)));
        }
        socklen_t address_size = sizeof(address);
        if (::getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
            throw std::runtime_error("getsockname failed");
        }
        const auto port = ntohs(address.sin_port);

        auto client = connect_loopback(port);
        auto accepted = accept_or_throw(listener.get());
        const auto client_cookie = cookie_for(client.get());
        const auto accepted_cookie = cookie_for(accepted.get());
        const auto client_local_port = local_port_for(client.get());

        auto sockets = neta::platform::make_connection_observer()->snapshot();
        bool client_cookie_correlation = false;
        bool accept_fallback_correlation = false;
        for (const auto& socket : sockets) {
            if (socket.socket_cookie == client_cookie && socket.remote_port == port) {
                client_cookie_correlation = true;
            }
            if (socket.socket_cookie == accepted_cookie && socket.local_port == port &&
                socket.remote_port == client_local_port) {
                accept_fallback_correlation = true;
            }
        }

        auto short_client = connect_loopback(port);
        auto short_accepted = accept_or_throw(listener.get());
        const auto short_cookie = cookie_for(short_client.get());
        const auto short_accepted_cookie = cookie_for(short_accepted.get());
        const auto short_client_local_port = local_port_for(short_client.get());
        short_client.close_now();
        short_accepted.close_now();
        client.close_now();
        accepted.close_now();

        std::vector<neta::ConnectionLifecycleEvent> events;
        bool client_connect_seen = false;
        bool accept_seen = false;
        bool client_close_seen = false;
        bool accepted_close_seen = false;
        bool short_connect_seen = false;
        bool short_accept_seen = false;
        bool short_client_close_seen = false;
        bool short_accepted_close_seen = false;
        bool short_lived_attributed = false;
        bool accept_cookie_fabricated = false;

        const auto refresh_assertions = [&] {
            client_connect_seen = has_event(
                events, neta::ConnectionLifecycleEventType::Connect, client_cookie);
            accept_seen = has_accept_event(events, port, client_local_port);
            client_close_seen = has_event(
                events, neta::ConnectionLifecycleEventType::Close, client_cookie);
            accepted_close_seen = has_event(
                events, neta::ConnectionLifecycleEventType::Close, accepted_cookie);
            short_connect_seen = has_event(
                events, neta::ConnectionLifecycleEventType::Connect, short_cookie);
            short_accept_seen = has_accept_event(events, port, short_client_local_port);
            short_client_close_seen = has_event(
                events, neta::ConnectionLifecycleEventType::Close, short_cookie);
            short_accepted_close_seen = has_event(
                events, neta::ConnectionLifecycleEventType::Close, short_accepted_cookie);
            short_lived_attributed = false;
            accept_cookie_fabricated = false;
            for (const auto& event : events) {
                if (event.type == neta::ConnectionLifecycleEventType::Connect &&
                    event.socket_cookie == short_cookie &&
                    event.process.agent_visible.tgid == ::getpid()) {
                    short_lived_attributed = true;
                }
                if (event.type == neta::ConnectionLifecycleEventType::Accept &&
                    event.socket_cookie) {
                    accept_cookie_fabricated = true;
                }
            }
        };

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            auto batch = lifecycle->poll(std::chrono::milliseconds(100));
            events.insert(events.end(), batch.begin(), batch.end());
            refresh_assertions();
            if (client_connect_seen && accept_seen && client_close_seen &&
                accepted_close_seen && short_connect_seen && short_accept_seen &&
                short_client_close_seen && short_accepted_close_seen &&
                short_lived_attributed && !accept_cookie_fabricated) {
                break;
            }
        }

        refresh_assertions();

        std::cout << "client_connect_seen=" << client_connect_seen << '\n'
                  << "accept_seen=" << accept_seen << '\n'
                  << "client_close_seen=" << client_close_seen << '\n'
                  << "accepted_close_seen=" << accepted_close_seen << '\n'
                  << "short_connect_seen=" << short_connect_seen << '\n'
                  << "short_accept_seen=" << short_accept_seen << '\n'
                  << "short_client_close_seen=" << short_client_close_seen << '\n'
                  << "short_accepted_close_seen=" << short_accepted_close_seen << '\n'
                  << "short_lived_attributed=" << short_lived_attributed << '\n'
                  << "client_cookie_correlation=" << client_cookie_correlation << '\n'
                  << "accept_fallback_correlation=" << accept_fallback_correlation << '\n'
                  << "accept_cookie_fabricated=" << accept_cookie_fabricated << '\n';

        if (!client_connect_seen || !accept_seen || !client_close_seen ||
            !accepted_close_seen || !short_connect_seen || !short_accept_seen ||
            !short_client_close_seen || !short_accepted_close_seen ||
            !short_lived_attributed || !client_cookie_correlation ||
            !accept_fallback_correlation || accept_cookie_fabricated) {
            std::cerr << "MS1 eBPF integration assertions failed; events=" << events.size() << '\n'
                      << "integration process getpid()=" << ::getpid() << '\n'
                      << "client_cookie=" << client_cookie << '\n'
                      << "accepted_cookie=" << accepted_cookie << '\n'
                      << "short_cookie=" << short_cookie << '\n'
                      << "short_accepted_cookie=" << short_accepted_cookie << '\n'
                      << "client_local_port=" << client_local_port << '\n'
                      << "short_client_local_port=" << short_client_local_port << '\n';
            for (std::size_t index = 0; index < events.size(); ++index) {
                dump_event(index, events[index]);
            }
            return 1;
        }
        std::cout << "MS1 eBPF integration PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "MS1 eBPF integration error: " << error.what() << '\n';
        return 1;
    }
}
