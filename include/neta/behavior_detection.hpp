#pragma once

#include "neta/crypto.hpp"
#include "neta/model.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace neta {

struct PeriodicOutboundPolicy {
    std::size_t minimum_connections{8};
    std::uint64_t window_ns{90'000'000'000ULL};
    std::uint64_t minimum_interval_ns{3'000'000'000ULL};
    std::uint64_t maximum_interval_ns{15'000'000'000ULL};
    double interval_tolerance_ratio{0.20};
    double minimum_regular_fraction{0.80};
    std::size_t recent_connection_limit{512};
};

struct PeriodicOutboundFinding {
    std::string type{"PERIODIC_OUTBOUND_CONNECTION"};
    std::string severity{"LOW"};
    double confidence{0.0};
    std::string malicious_intent{"UNKNOWN"};
    std::string process_identity;
    std::string process_name;
    std::string host;
    std::uint16_t port{0};
    std::uint64_t first_seen_ns{0};
    std::uint64_t last_seen_ns{0};
    std::uint64_t median_interval_ns{0};
    double regular_interval_fraction{0.0};
    std::vector<std::int64_t> connection_ids;
    std::string finding_key;
    std::string finding_id;
    std::string evidence_root;
    std::string interpretation;
};

namespace periodic_outbound_detail {

inline std::string process_identity(const ConnectionSummary& connection) {
    if (!connection.process.executable_path.empty()) {
        return "exe=" + connection.process.executable_path;
    }
    if (!connection.process.comm.empty()) return "comm=" + connection.process.comm;
    return {};
}

inline std::string process_name(const ConnectionSummary& connection) {
    if (!connection.process.comm.empty()) return connection.process.comm;
    return connection.process.executable_path;
}

inline std::string remote_host(const ConnectionSummary& connection) {
    return !connection.target_host.empty() ? connection.target_host : connection.remote_ip;
}

inline std::uint64_t median(std::vector<std::uint64_t> values) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const auto midpoint = values.size() / 2;
    if ((values.size() % 2U) != 0U) return values[midpoint];
    return (values[midpoint - 1] + values[midpoint]) / 2U;
}

inline bool same_group(const ConnectionSummary& left, const ConnectionSummary& right) {
    return left.direction == ConnectionDirection::Outbound &&
           right.direction == ConnectionDirection::Outbound &&
           process_identity(left) == process_identity(right) &&
           !process_identity(left).empty() &&
           remote_host(left) == remote_host(right) &&
           !remote_host(left).empty() &&
           left.remote_port == right.remote_port && left.remote_port != 0;
}

} // namespace periodic_outbound_detail

inline std::optional<PeriodicOutboundFinding> detect_periodic_outbound(
    const std::vector<ConnectionSummary>& recent_connections,
    std::int64_t trigger_connection_id,
    const PeriodicOutboundPolicy& policy = {}) {
    if (policy.minimum_connections < 2 || policy.window_ns == 0 ||
        policy.minimum_interval_ns == 0 ||
        policy.minimum_interval_ns > policy.maximum_interval_ns ||
        policy.interval_tolerance_ratio < 0.0 ||
        policy.minimum_regular_fraction < 0.0 || policy.minimum_regular_fraction > 1.0) {
        return std::nullopt;
    }

    const auto trigger_it = std::find_if(
        recent_connections.begin(), recent_connections.end(),
        [trigger_connection_id](const ConnectionSummary& connection) {
            return connection.id == trigger_connection_id;
        });
    if (trigger_it == recent_connections.end() ||
        trigger_it->direction != ConnectionDirection::Outbound ||
        trigger_it->first_seen_ns == 0 || trigger_it->remote_port == 0 ||
        periodic_outbound_detail::process_identity(*trigger_it).empty() ||
        periodic_outbound_detail::remote_host(*trigger_it).empty()) {
        return std::nullopt;
    }

    std::vector<ConnectionSummary> group;
    group.reserve(recent_connections.size());
    for (const auto& connection : recent_connections) {
        if (connection.first_seen_ns == 0 ||
            !periodic_outbound_detail::same_group(connection, *trigger_it)) {
            continue;
        }
        if (connection.first_seen_ns > trigger_it->first_seen_ns) continue;
        if (trigger_it->first_seen_ns - connection.first_seen_ns > policy.window_ns) continue;
        group.push_back(connection);
    }
    if (group.size() < policy.minimum_connections) return std::nullopt;

    std::sort(group.begin(), group.end(), [](const auto& left, const auto& right) {
        if (left.first_seen_ns != right.first_seen_ns) return left.first_seen_ns < right.first_seen_ns;
        return left.id < right.id;
    });
    if (group.back().id != trigger_connection_id) return std::nullopt;

    std::vector<std::uint64_t> intervals;
    intervals.reserve(group.size() - 1);
    for (std::size_t index = 1; index < group.size(); ++index) {
        if (group[index].first_seen_ns <= group[index - 1].first_seen_ns) return std::nullopt;
        intervals.push_back(group[index].first_seen_ns - group[index - 1].first_seen_ns);
    }

    const auto median_interval = periodic_outbound_detail::median(intervals);
    if (median_interval < policy.minimum_interval_ns || median_interval > policy.maximum_interval_ns) {
        return std::nullopt;
    }

    const auto tolerance = static_cast<long double>(median_interval) *
                           static_cast<long double>(policy.interval_tolerance_ratio);
    std::size_t regular = 0;
    for (const auto interval : intervals) {
        const auto difference = interval > median_interval
            ? interval - median_interval : median_interval - interval;
        if (static_cast<long double>(difference) <= tolerance) ++regular;
    }
    const double regular_fraction = static_cast<double>(regular) /
                                    static_cast<double>(intervals.size());
    if (regular_fraction < policy.minimum_regular_fraction) return std::nullopt;

    PeriodicOutboundFinding finding;
    finding.confidence = regular_fraction;
    finding.process_identity = periodic_outbound_detail::process_identity(*trigger_it);
    finding.process_name = periodic_outbound_detail::process_name(*trigger_it);
    finding.host = periodic_outbound_detail::remote_host(*trigger_it);
    finding.port = trigger_it->remote_port;
    finding.first_seen_ns = group.front().first_seen_ns;
    finding.last_seen_ns = group.back().first_seen_ns;
    finding.median_interval_ns = median_interval;
    finding.regular_interval_fraction = regular_fraction;
    finding.connection_ids.reserve(group.size());

    std::ostringstream evidence;
    evidence << "type=" << finding.type
             << "|process=" << finding.process_identity
             << "|target=" << finding.host << ':' << finding.port;
    for (const auto& connection : group) {
        finding.connection_ids.push_back(connection.id);
        evidence << "|connection=" << connection.id << '@' << connection.first_seen_ns;
    }
    finding.evidence_root = "sha256:" + sha256_hex(evidence.str());
    finding.finding_key = "sha256:" + sha256_hex(
        finding.type + "|" + finding.process_identity + "|" + finding.host + ":" +
        std::to_string(finding.port));
    std::string suffix = finding.evidence_root.substr(7);
    if (suffix.size() > 12) suffix.resize(12);
    finding.finding_id = "FINDING-BEHAVIOR-" + suffix;
    finding.interpretation =
        "Repeated outbound connections exhibit a strongly periodic beacon-like communication "
        "pattern. Malicious intent is not established.";
    return finding;
}

} // namespace neta
