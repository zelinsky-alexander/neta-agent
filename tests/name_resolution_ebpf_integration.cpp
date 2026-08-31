#include "neta/platform.hpp"

#include <netdb.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <string>

int main() {
    using namespace std::chrono_literals;
    auto observer = neta::platform::make_name_resolution_observer();
    if (!observer->capability().available()) {
        std::cerr << "SKIP: resolver eBPF unavailable: "
                  << observer->capability().unavailable_reason << '\n';
        return 77;
    }

    addrinfo* addresses = nullptr;
    const int result = ::getaddrinfo("localhost", nullptr, nullptr, &addresses);
    if (addresses) ::freeaddrinfo(addresses);
    if (result != 0) {
        std::cerr << "getaddrinfo localhost failed: " << ::gai_strerror(result) << '\n';
        return 1;
    }

    for (int attempt = 0; attempt < 20; ++attempt) {
        for (const auto& observation : observer->poll(50ms)) {
            if (observation.query_name != "localhost") continue;
            if (observation.mechanism != neta::NameResolutionMechanism::ApplicationResolverApi) {
                std::cerr << "unexpected resolver mechanism\n";
                return 1;
            }
            if (!observation.result_code || *observation.result_code != 0) {
                std::cerr << "resolver event did not report successful getaddrinfo\n";
                return 1;
            }
            if (observation.addresses.empty()) {
                std::cerr << "successful resolver event contained no returned addresses\n";
                return 1;
            }
            std::cout << "Observed glibc getaddrinfo event with "
                      << observation.addresses.size() << " address(es)\n";
            return 0;
        }
    }

    std::cerr << "resolver collector did not observe the controlled getaddrinfo call\n";
    return 1;
}
