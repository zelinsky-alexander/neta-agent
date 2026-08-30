#include "neta/cli/observation_options.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>

namespace {

template <std::size_t Size>
neta::cli::ObservationOptions parse(const char* const (&arguments)[Size], bool service = false) {
    char* argv[Size]{};
    for (std::size_t index = 0; index < Size; ++index) {
        argv[index] = const_cast<char*>(arguments[index]);
    }
    return neta::cli::parse_observation_options(static_cast<int>(Size), argv, service);
}

} // namespace

int main() {
    const char* all_args[] = {"neta-agent", "observe", "--all", "--local-port", "443",
                              "--remote-port", "50000", "--process", "server",
                              "--exclude-process", "ignored", "--duration", "2"};
    const auto all = parse(all_args);
    assert(all.mode == neta::ObservationMode::All);
    assert(all.filter.local_port == 443);
    assert(all.filter.remote_port == 50000);
    assert(all.filter.include_processes.contains("server"));
    assert(all.filter.exclude_processes.contains("ignored"));
    assert(all.duration == std::chrono::seconds(2));

    const char* run_args[] = {"neta-agent", "run", "--duration", "0"};
    assert(parse(run_args, true).mode == neta::ObservationMode::All);

    const char* invalid_args[] = {"neta-agent", "observe", "--all", "--inbound"};
    bool rejected = false;
    try {
        static_cast<void>(parse(invalid_args));
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
    std::cout << "Observation option tests passed\n";
}
