#pragma once

#include "neta/history_store.hpp"

#include <chrono>
#include <cstdint>

namespace neta {

class StorageMaintenance {
public:
    using Clock = std::chrono::steady_clock;

    StorageMaintenance(HistoryStore& store, std::uint64_t max_bytes,
                       std::chrono::seconds interval);

    [[nodiscard]] bool run_if_due(Clock::time_point now);
    void run_now();

private:
    HistoryStore& store_;
    std::uint64_t max_bytes_;
    std::chrono::seconds interval_;
    Clock::time_point next_run_{Clock::time_point::min()};
};

} // namespace neta
