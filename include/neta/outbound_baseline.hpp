#pragma once

#include "neta/history_store.hpp"

#include <cstdint>
#include <optional>

namespace neta {

Baseline accept_outbound_connection_baseline(HistoryStore& store,
                                             std::int64_t connection_id);

std::optional<AssuranceVerdict> evaluate_outbound_connection(
    HistoryStore& store, std::int64_t connection_id);

} // namespace neta
