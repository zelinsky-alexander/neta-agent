#pragma once

#ifdef _WIN32

#include "neta/process_exec.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace neta::windows_sensor_broker {

class EndpointProcessRegistry {
public:
    EndpointProcessRegistry();
    ~EndpointProcessRegistry();
    EndpointProcessRegistry(EndpointProcessRegistry&&) noexcept;
    EndpointProcessRegistry& operator=(EndpointProcessRegistry&&) noexcept;
    EndpointProcessRegistry(const EndpointProcessRegistry&) = delete;
    EndpointProcessRegistry& operator=(const EndpointProcessRegistry&) = delete;

    void register_endpoint(std::string slot, std::uint32_t root_pid);
    std::optional<std::string> resolve_pid(std::uint32_t pid);
    std::optional<std::string> observe(const ProcessExecEvent& event);
    bool endpoint_owns(const std::string& slot, std::uint32_t pid);
    std::size_t endpoint_count() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace neta::windows_sensor_broker

#endif
