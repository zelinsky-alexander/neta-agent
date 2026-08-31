#pragma once

#include "neta/tcp_state.hpp"
#include "neta/connection_direction.hpp"
#include "neta/route_semantics.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neta {

enum class EvidenceFidelity { Exact, StronglyCorrelated, Supporting, Contextual };

enum class PerformanceState { Normal, Degraded, Failed, InsufficientEvidence };
enum class TrustState { Stable, Changed, Suspicious, Unverified };

struct HostEnvironment {
    std::string boot_id;
    std::string os{"Linux"};
    std::string kernel_release;
    bool is_wsl{false};
    std::uint64_t network_namespace_inode{0};
};

struct ProcessIdentity {
    std::int64_t pid{-1};
    std::uint32_t uid{0};
    std::optional<std::uint64_t> start_ticks;
    std::string comm;
    std::string executable_path;
};

struct TcpSnapshot {
    std::uint64_t observed_ns{0};
    std::uint8_t state{0};
    std::uint32_t rtt_us{0};
    std::uint32_t rtt_variance_us{0};
    std::uint32_t total_retrans{0};
    std::uint32_t lost{0};
    std::uint32_t unacked{0};
    std::uint32_t snd_cwnd{0};
    std::uint32_t snd_ssthresh{0};
    std::uint32_t snd_mss{0};
    std::uint32_t rcv_mss{0};
    std::uint32_t send_queue_bytes{0};
    std::uint32_t recv_queue_bytes{0};
};

struct SocketObservation {
    std::uint64_t socket_cookie{0};
    std::uint64_t socket_inode{0};
    std::optional<std::uint64_t> network_namespace_inode;
    std::uint32_t uid{0};
    std::string local_ip;
    std::uint16_t local_port{0};
    std::string remote_ip;
    std::uint16_t remote_port{0};
    TcpEndpointKind endpoint_kind{TcpEndpointKind::Unknown};
    TcpSnapshot transport;
};

struct RouteObservation {
    std::string destination;
    std::string source;
    std::string gateway;
    std::string interface_name;
    std::uint32_t interface_index{0};
    std::optional<std::uint32_t> table;
    std::optional<std::uint32_t> metric;
    std::uint64_t observed_ns{0};
    std::string sha256;
    RouteRelation relation{RouteRelation::Unknown};
};

struct TlsObservation {
    std::string target_host;
    std::uint16_t target_port{443};
    std::uint64_t observed_ns{0};
    std::string tls_version;
    std::string cipher;
    std::string alpn;
    std::string leaf_sha256;
    std::string spki_sha256;
    std::string subject;
    std::string issuer;
    std::string not_before;
    std::string not_after;
    bool chain_valid{false};
    bool hostname_valid{false};
    std::string sha256;
};

struct Baseline {
    std::string target_host;
    std::uint16_t target_port{443};
    std::uint64_t rtt_median_us{0};
    std::uint64_t rttvar_median_us{0};
    std::string accepted_spki_sha256;
    std::string accepted_issuer;
    std::uint64_t sample_count{0};
    std::uint64_t created_ns{0};
    std::string sha256;
};

struct AggregateMetrics {
    std::uint64_t observed_rtt_us{0};
    std::uint64_t observed_rttvar_us{0};
    std::uint64_t retransmission_delta{0};
};

struct AssuranceVerdict {
    PerformanceState performance{PerformanceState::InsufficientEvidence};
    TrustState trust{TrustState::Unverified};
    std::string performance_hypothesis;
    std::string trust_hypothesis;
    double rule_confidence{0.0};
    std::string rule_set_version;
    std::string rule_set_hash;
    std::string baseline_hash;
    std::string input_hash;
};

struct ConnectionSummary {
    std::int64_t id{0};
    std::uint64_t first_seen_ns{0};
    std::uint64_t last_seen_ns{0};
    std::optional<std::uint64_t> captured_at_ns;
    ConnectionDirection direction{ConnectionDirection::Unknown};
    std::uint64_t socket_cookie{0};
    std::uint64_t socket_inode{0};
    std::optional<std::uint64_t> network_namespace_inode;
    ProcessIdentity process;
    std::string local_ip;
    std::uint16_t local_port{0};
    std::string remote_ip;
    std::uint16_t remote_port{0};
    std::string target_host;
    std::string lifecycle_state;
    PerformanceState performance{PerformanceState::InsufficientEvidence};
    TrustState trust{TrustState::Unverified};
};

std::string to_string(EvidenceFidelity value);
std::string to_string(PerformanceState value);
std::string to_string(TrustState value);
PerformanceState performance_state_from_string(const std::string& value);
TrustState trust_state_from_string(const std::string& value);

} // namespace neta
