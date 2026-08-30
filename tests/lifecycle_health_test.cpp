#include "neta/lifecycle.hpp"

#include <cassert>
#include <iostream>

int main() {
    neta::LifecycleHealth unavailable;
    assert(!unavailable.dropped_events);
    assert(!unavailable.evidence_may_be_incomplete());
    neta::LifecycleHealth healthy{0};
    assert(!healthy.evidence_may_be_incomplete());
    neta::LifecycleHealth dropped{3};
    assert(dropped.evidence_may_be_incomplete());
    std::cout << "Lifecycle health tests passed\n";
}
