#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

namespace neta {

enum class NapSequenceHealth {
    Healthy,
    Recovered,
    LegacyMigrationRequired,
    Unrecoverable,
};

struct NapSequenceStatus {
    NapSequenceHealth health{NapSequenceHealth::Unrecoverable};
    bool has_sequence{false};
    std::uint64_t sequence{0};
    bool slot0_valid{false};
    bool slot1_valid{false};
    bool legacy_valid{false};
    std::string detail;
    std::string recovery_detail;
};

std::string to_string(NapSequenceHealth health);

// Allocates and durably persists the next monotonic NAP/1 message sequence.
// The interprocess lock is held only while local sequence state is read/updated;
// callers perform network I/O after this function returns.
std::uint64_t next_nap_sequence(
    const std::filesystem::path& state_dir,
    std::chrono::milliseconds lock_timeout = std::chrono::seconds(5));

// Initializes redundant sequence state for a newly enrolled identity.
void initialize_nap_sequence_state(const std::filesystem::path& state_dir,
                                   std::uint64_t initial_sequence = 0);

// Read-only local health inspection. It never increments or repairs sequence state.
NapSequenceStatus inspect_nap_sequence_state(
    const std::filesystem::path& state_dir,
    std::chrono::milliseconds lock_timeout = std::chrono::seconds(5));

} // namespace neta
