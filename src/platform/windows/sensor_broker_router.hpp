#pragma once

#ifdef _WIN32

#include "neta/lifecycle.hpp"
#include "neta/process_exec.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace neta::windows_sensor_broker {

class BrokerEventRouter {
public:
    explicit BrokerEventRouter(std::size_t queue_capacity);
    ~BrokerEventRouter();
    BrokerEventRouter(BrokerEventRouter&&) noexcept;
    BrokerEventRouter& operator=(BrokerEventRouter&&) noexcept;
    BrokerEventRouter(const BrokerEventRouter&) = delete;
    BrokerEventRouter& operator=(const BrokerEventRouter&) = delete;

    void register_endpoint(const std::string& slot);
    bool has_endpoint(const std::string& slot) const;

    bool route_lifecycle(const std::string& slot,
                         const ConnectionLifecycleEvent& event,
                         std::uint64_t sequence);
    bool route_process_exec(const std::string& slot,
                            const ProcessExecEvent& event,
                            std::uint64_t sequence);

    std::optional<std::vector<std::byte>> take(const std::string& slot,
                                                std::chrono::milliseconds timeout);
    std::uint64_t dropped(const std::string& slot) const;
    void note_unroutable();
    std::uint64_t unroutable() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace neta::windows_sensor_broker

#endif
