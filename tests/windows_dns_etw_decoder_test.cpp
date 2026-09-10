#include "dns_etw_decoder.hpp"

#include <cassert>
#include <iostream>

int main() {
    using namespace neta;
    using namespace neta::platform::windows_dns;

    assert(query_kind(1) == NameResolutionQueryKind::Forward);
    assert(query_kind(28) == NameResolutionQueryKind::Forward);
    assert(query_kind(12) == NameResolutionQueryKind::Reverse);
    assert(query_kind(15) == NameResolutionQueryKind::Unknown);

    const auto addresses = extract_addresses(
        "type: 1 203.0.113.10; type: 28 2001:db8::1; duplicate=203.0.113.10");
    assert(addresses.size() == 2);
    assert(addresses[0].family == NetworkAddressFamily::IPv4);
    assert(addresses[0].address == "203.0.113.10");
    assert(addresses[1].family == NetworkAddressFamily::IPv6);
    assert(addresses[1].address == "2001:db8::1");

    assert(successful_status(std::nullopt));
    assert(successful_status(0));
    assert(!successful_status(9003));

    std::cout << "Windows DNS ETW decoder helpers OK\n";
    return 0;
}
