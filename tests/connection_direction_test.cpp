#include "neta/connection_direction.hpp"

#include <cassert>
#include <iostream>

int main() {
    using namespace neta;
    assert(to_string(ConnectionDirection::Outbound) == "OUTBOUND");
    assert(to_string(ConnectionDirection::Inbound) == "INBOUND");
    assert(to_string(ConnectionDirection::Unknown) == "UNKNOWN");
    assert(connection_direction_from_string("OUTBOUND") == ConnectionDirection::Outbound);
    assert(connection_direction_from_string("INBOUND") == ConnectionDirection::Inbound);
    assert(connection_direction_from_string("") == ConnectionDirection::Unknown);
    assert(connection_direction_from_string("legacy") == ConnectionDirection::Unknown);
    std::cout << "Connection direction tests passed\n";
}
