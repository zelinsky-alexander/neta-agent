#include "neta/evidence_scheduler.hpp"

#include <cassert>
#include <chrono>
#include <iostream>

int main() {
    using namespace std::chrono_literals;
    neta::EvidenceScheduler scheduler(1s, 50ms);
    const auto start = neta::EvidenceScheduler::Clock::time_point{};
    assert(!scheduler.transport_due(start, false));
    assert(scheduler.transport_due(start, true));
    scheduler.connection_admitted(7);
    assert(scheduler.active_connections() == 1);
    assert(scheduler.transport_due(start, false));
    assert(scheduler.take_route_observations_due().empty());
    scheduler.transport_sampled(start);
    const auto routes = scheduler.take_route_observations_due();
    assert(routes.size() == 1);
    assert(routes.front() == 7);
    assert(!scheduler.transport_due(start + 49ms, false));
    assert(scheduler.transport_due(start + 50ms, false));
    scheduler.transport_sampled(start + 50ms);
    assert(!scheduler.transport_due(start + 1049ms, false));
    assert(scheduler.transport_due(start + 1050ms, false));
    scheduler.transport_sampled(start + 1050ms);
    scheduler.connection_closed(7);
    assert(scheduler.active_connections() == 0);
    assert(!scheduler.transport_due(start + 2s, false));
    assert(scheduler.transport_due(start + 1100ms, true));
    scheduler.connection_admitted(8);
    scheduler.connection_closed(8);
    scheduler.transport_sampled(start + 2s);
    assert(scheduler.take_route_observations_due().empty());
    std::cout << "Evidence scheduler tests passed\n";
}
