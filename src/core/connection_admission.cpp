#include "neta/connection_admission.hpp"

namespace neta {

std::optional<std::int64_t> begin_attributed_connection(
    HistoryStore& store,
    platform::ProcessResolver& resolver,
    const SocketObservation& socket,
    const std::string& target_host) {
    if (!eligible_connection_seed(socket.endpoint_kind)) return std::nullopt;

    const auto process = resolver.resolve(socket);
    if (!process) return std::nullopt;

    return store.begin_connection(
        socket,
        process,
        target_host,
        socket.transport.observed_ns);
}

} // namespace neta
