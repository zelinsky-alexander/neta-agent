#include "neta/evidence_scheduler.hpp"

#include <algorithm>

namespace neta {

EvidenceScheduler::EvidenceScheduler(std::chrono::milliseconds transport_interval,
                                     std::chrono::milliseconds early_transport_followup)
    : transport_interval_(transport_interval),
      early_transport_followup_(early_transport_followup) {}

void EvidenceScheduler::connection_admitted(std::int64_t connection_id) {
    active_.insert(connection_id);
    pending_routes_.insert(connection_id);
    immediate_transport_ = true;
    early_transport_followup_pending_ = true;
}

void EvidenceScheduler::connection_closed(std::int64_t connection_id) {
    active_.erase(connection_id);
    pending_routes_.erase(connection_id);
    if (active_.empty()) {
        immediate_transport_ = false;
        early_transport_followup_pending_ = false;
    }
}

bool EvidenceScheduler::transport_due(Clock::time_point now,
                                      bool polling_discovery_required) const noexcept {
    return polling_discovery_required ||
           (!active_.empty() && (immediate_transport_ || now >= next_transport_sample_));
}

std::chrono::milliseconds EvidenceScheduler::wait_time(Clock::time_point now) const noexcept {
    if (active_.empty()) return transport_interval_;
    if (immediate_transport_ || now >= next_transport_sample_) return std::chrono::milliseconds(0);
    return std::chrono::duration_cast<std::chrono::milliseconds>(next_transport_sample_ - now);
}

void EvidenceScheduler::transport_sampled(Clock::time_point now) noexcept {
    if (immediate_transport_) {
        immediate_transport_ = false;
        next_transport_sample_ = now + early_transport_followup_;
    } else if (early_transport_followup_pending_) {
        early_transport_followup_pending_ = false;
        next_transport_sample_ = now + transport_interval_;
    } else {
        next_transport_sample_ = now + transport_interval_;
    }
    routes_ready_ = !pending_routes_.empty();
}

std::vector<std::int64_t> EvidenceScheduler::take_route_observations_due() {
    if (!routes_ready_) return {};
    std::vector<std::int64_t> due(pending_routes_.begin(), pending_routes_.end());
    pending_routes_.clear();
    routes_ready_ = false;
    return due;
}

} // namespace neta
