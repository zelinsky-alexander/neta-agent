#include "neta/tcp_state.hpp"

namespace neta {

bool eligible_connection_seed(TcpEndpointKind kind) noexcept {
    return kind == TcpEndpointKind::Connection;
}

std::string to_string(TcpEndpointKind kind) {
    switch (kind) {
        case TcpEndpointKind::Connection: return "CONNECTION";
        case TcpEndpointKind::Listener: return "LISTENER";
        case TcpEndpointKind::LifecycleTail: return "LIFECYCLE_TAIL";
        case TcpEndpointKind::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

} // namespace neta
