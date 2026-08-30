#pragma once

#include <chrono>
#include <cstdint>
#include <unordered_set>
#include <vector>

namespace neta {

class EvidenceScheduler {
public:
    using Clock = std::chrono::steady_clock;

    explicit EvidenceScheduler(
        std::chrono::milliseconds transport_interval,
        std::chrono::milliseconds early_transport_followup = std::chrono::milliseconds(50));

    void connection_admitted(std::int64_t connection_id);
    void connection_closed(std::int64_t connection_id);
    [[nodiscard]] bool transport_due(Clock::time_point now,
                                     bool polling_discovery_required) const noexcept;
    [[nodiscard]] std::chrono::milliseconds wait_time(Clock::time_point now) const noexcept;
    void transport_sampled(Clock::time_point now) noexcept;
    [[nodiscard]] std::vector<std::int64_t> take_route_observations_due();
    [[nodiscard]] std::size_t active_connections() const noexcept { return active_.size(); }

private:
    std::chrono::milliseconds transport_interval_;
    std::chrono::milliseconds early_transport_followup_;
    Clock::time_point next_transport_sample_{Clock::time_point::min()};
    bool immediate_transport_{false};
    bool early_transport_followup_pending_{false};
    bool routes_ready_{false};
    std::unordered_set<std::int64_t> active_;
    std::unordered_set<std::int64_t> pending_routes_;
};

} // namespace neta
