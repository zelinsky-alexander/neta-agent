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

inline std::uint32_t clamp_u32(std::uint64_t value) noexcept {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(
        value, std::numeric_limits<std::uint32_t>::max()));
}

inline std::uint32_t milliseconds_to_microseconds(ULONG milliseconds) noexcept {
    constexpr std::uint64_t scale = 1000ULL;
    return clamp_u32(static_cast<std::uint64_t>(milliseconds) * scale);
}

inline std::uint32_t segments_from_bytes(std::uint64_t bytes, std::uint32_t mss) noexcept {
    if (bytes == 0 || mss == 0) return 0;
    const auto segments = (bytes + static_cast<std::uint64_t>(mss) - 1ULL) /
                          static_cast<std::uint64_t>(mss);
    return clamp_u32(segments);
}

inline std::uint32_t sum_queue_bytes(std::uint64_t first, std::uint64_t second) noexcept {
    const auto capped_first = std::min<std::uint64_t>(
        first, std::numeric_limits<std::uint32_t>::max());
    const auto remaining = static_cast<std::uint64_t>(
        std::numeric_limits<std::uint32_t>::max()) - capped_first;
    return clamp_u32(capped_first + std::min(second, remaining));
}

inline void apply_syn_options(TcpSnapshot& snapshot,
                              const TCP_ESTATS_SYN_OPTS_ROS_v0& syn) noexcept {
    // Windows reports the peer MSS received in the SYN as MssRcvd. That is the
    // maximum payload we may send, so it maps to Linux tcp_info::tcpi_snd_mss.
    // MssSent is our advertised receive MSS and maps to tcpi_rcv_mss.
    if (syn.MssRcvd != 0) snapshot.snd_mss = static_cast<std::uint32_t>(syn.MssRcvd);
    if (syn.MssSent != 0) snapshot.rcv_mss = static_cast<std::uint32_t>(syn.MssSent);
}

inline void apply_data(TcpSnapshot& snapshot, const TCP_ESTATS_DATA_ROD_v0& data) noexcept {
    snapshot.bytes_sent = static_cast<std::uint64_t>(data.DataBytesOut);
    snapshot.bytes_received = static_cast<std::uint64_t>(data.DataBytesIn);
    snapshot.transfer_source = "windows:tcp-estats:data";
    snapshot.transfer_fidelity = EvidenceFidelity::StronglyCorrelated;
}

inline void apply_path(TcpSnapshot& snapshot, const TCP_ESTATS_PATH_ROD_v0& path) noexcept {
    snapshot.total_retrans = static_cast<std::uint32_t>(path.PktsRetrans);
    if (path.CurMss != 0) snapshot.snd_mss = static_cast<std::uint32_t>(path.CurMss);

    // Path RTT fields are reported in milliseconds. They provide a safe fallback
    // on systems where FineRtt collection is unavailable; FineRtt overwrites these
    // with microsecond values when available.
    if (path.SmoothedRtt != 0) {
        snapshot.rtt_us = milliseconds_to_microseconds(path.SmoothedRtt);
    }
    if (path.RttVar != 0) {
        snapshot.rtt_variance_us = milliseconds_to_microseconds(path.RttVar);
    }

    // Windows EStats does not expose a direct equivalent of Linux tcpi_lost.
    // Do not fabricate one from timeout/duplicate-ACK counters: zero continues
    // to mean unavailable/no observed value in the shared snapshot model.
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
    snapshot.snd_cwnd = segments_from_bytes(
        static_cast<std::uint64_t>(congestion.CurCwnd), snapshot.snd_mss);
    snapshot.snd_ssthresh = segments_from_bytes(
        static_cast<std::uint64_t>(congestion.CurSsthresh), snapshot.snd_mss);
}

inline void apply_send_buffer(TcpSnapshot& snapshot,
                              const TCP_ESTATS_SEND_BUFF_ROD_v0& send_buffer) noexcept {
    // Linux inet_diag idiag_wqueue represents current TCP write-side queue
    // pressure. Windows splits this into retransmission-queue bytes and
    // application bytes waiting for their first transmission. Preserve both.
    snapshot.send_queue_bytes = sum_queue_bytes(
        static_cast<std::uint64_t>(send_buffer.CurRetxQueue),
        static_cast<std::uint64_t>(send_buffer.CurAppWQueue));

    // Linux tcpi_unacked is measured in packets. Windows has no identical field,
    // but CurRetxQueue is the currently retained unacknowledged/retransmittable
    // byte queue. Normalizing it by the current MSS gives the closest bounded
    // packet-count analogue without inventing loss events.
    if (snapshot.snd_mss != 0) {
        snapshot.unacked = segments_from_bytes(
            static_cast<std::uint64_t>(send_buffer.CurRetxQueue), snapshot.snd_mss);
    }
}

inline void apply_receiver(TcpSnapshot& snapshot,
                           const TCP_ESTATS_REC_ROD_v0& receiver) noexcept {
    // Approximate Linux idiag_rqueue with the two Windows receive-side queues:
    // bytes waiting for the application plus out-of-order bytes being reassembled.
    snapshot.recv_queue_bytes = sum_queue_bytes(
        static_cast<std::uint64_t>(receiver.CurAppRQueue),
        static_cast<std::uint64_t>(receiver.CurReasmQueue));
}

} // namespace neta::platform::windows_tcp_estats
