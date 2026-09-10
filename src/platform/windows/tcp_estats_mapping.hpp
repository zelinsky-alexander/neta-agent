#pragma once

#include "neta/model.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <tcpestats.h>

#include <algorithm>
#include <cstdint>
#include <limits>

namespace neta::platform::windows_tcp_estats {

inline std::uint32_t milliseconds_to_microseconds(ULONG milliseconds) noexcept {
    constexpr std::uint64_t scale = 1000ULL;
    const auto value = static_cast<std::uint64_t>(milliseconds) * scale;
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(
        value, std::numeric_limits<std::uint32_t>::max()));
}

inline std::uint32_t segments_from_bytes(ULONG bytes, std::uint32_t mss) noexcept {
    if (bytes == 0 || mss == 0) return 0;
    const auto segments = static_cast<std::uint64_t>(bytes) /
                          static_cast<std::uint64_t>(mss);
    if (segments == 0) return 1;
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(
        segments, std::numeric_limits<std::uint32_t>::max()));
}

inline void apply_path(TcpSnapshot& snapshot, const TCP_ESTATS_PATH_ROD_v0& path) noexcept {
    snapshot.total_retrans = static_cast<std::uint32_t>(path.PktsRetrans);
    snapshot.snd_mss = static_cast<std::uint32_t>(path.CurMss);

    // Path RTT fields are reported in milliseconds. They provide a safe fallback
    // on systems where FineRtt collection is unavailable; FineRtt overwrites these
    // with microsecond values when available.
    if (path.SmoothedRtt != 0) {
        snapshot.rtt_us = milliseconds_to_microseconds(path.SmoothedRtt);
    }
    if (path.RttVar != 0) {
        snapshot.rtt_variance_us = milliseconds_to_microseconds(path.RttVar);
    }
}

inline void apply_fine_rtt(TcpSnapshot& snapshot,
                           const TCP_ESTATS_FINE_RTT_ROD_v0& fine_rtt) noexcept {
    // FineRtt is already reported in microseconds. SumRtt is Microsoft's
    // smoothed RTT value for this structure.
    if (fine_rtt.SumRtt != 0) snapshot.rtt_us = fine_rtt.SumRtt;
    if (fine_rtt.RttVar != 0) snapshot.rtt_variance_us = fine_rtt.RttVar;
}

inline void apply_sender_congestion(
    TcpSnapshot& snapshot, const TCP_ESTATS_SND_CONG_ROD_v0& congestion) noexcept {
    // Windows reports CurCwnd/CurSsthresh in bytes while Linux tcp_info reports
    // tcpi_snd_cwnd/tcpi_snd_ssthresh in MSS-sized segments. Normalize Windows
    // to the Linux/shared TcpSnapshot unit.
    snapshot.snd_cwnd = segments_from_bytes(congestion.CurCwnd, snapshot.snd_mss);
    snapshot.snd_ssthresh = segments_from_bytes(congestion.CurSsthresh, snapshot.snd_mss);
}

} // namespace neta::platform::windows_tcp_estats
