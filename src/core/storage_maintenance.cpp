#include "neta/storage_maintenance.hpp"

namespace neta {

StorageMaintenance::StorageMaintenance(HistoryStore& store, std::uint64_t max_bytes,
                                       std::chrono::seconds interval)
    : store_(store), max_bytes_(max_bytes), interval_(interval) {}

bool StorageMaintenance::run_if_due(Clock::time_point now) {
    if (now < next_run_) return false;
    store_.prune_to_budget(max_bytes_);
    next_run_ = now + interval_;
    return true;
}

void StorageMaintenance::run_now() {
    store_.prune_to_budget(max_bytes_);
    next_run_ = Clock::now() + interval_;
}

} // namespace neta
