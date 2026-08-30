#pragma once

#include <string>

namespace neta {

enum class TcpEndpointKind {
    Unknown,
    Connection,
    Listener,
    LifecycleTail,
};

[[nodiscard]] bool eligible_connection_seed(TcpEndpointKind kind) noexcept;
std::string to_string(TcpEndpointKind kind);

} // namespace neta
