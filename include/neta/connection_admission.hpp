#pragma once

#include "neta/history_store.hpp"
#include "neta/platform.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace neta {

// Admit a newly observed socket only after live process attribution succeeds.
// A failed lookup returns no connection ID and is intentionally not cached, so
// the next polling pass retries attribution instead of persisting anonymous
// history.
std::optional<std::int64_t> begin_attributed_connection(
    HistoryStore& store,
    platform::ProcessResolver& resolver,
    const SocketObservation& socket,
    const std::string& target_host);

} // namespace neta
