#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>

namespace neta {

// Allocates and durably persists the next monotonic NAP/1 message sequence.
// The interprocess lock is held only while local sequence state is read/updated;
// callers perform network I/O after this function returns.
std::uint64_t next_nap_sequence(
    const std::filesystem::path& state_dir,
    std::chrono::milliseconds lock_timeout = std::chrono::seconds(5));

// Initializes sequence state for a newly enrolled identity.
void initialize_nap_sequence_state(const std::filesystem::path& state_dir,
                                   std::uint64_t initial_sequence = 0);

} // namespace neta
