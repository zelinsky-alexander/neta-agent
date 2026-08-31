#include "neta/name_resolution.hpp"

#include <cassert>
#include <iostream>
#include <vector>

namespace {

neta::ConnectionSummary outbound_connection() {
    neta::ConnectionSummary connection;
    connection.id = 7;
    connection.first_seen_ns = 10'000'000'000ULL;
    connection.direction = neta::ConnectionDirection::Outbound;
    connection.process.pid = 4242;
    connection.process.start_ticks = 900;
    connection.remote_ip = "203.0.113.20";
    connection.network_namespace_inode = 77;
    return connection;
}

neta::NameResolutionObservation exact_lookup(std::uint64_t completed_ns) {
    neta::NameResolutionObservation observation;
    observation.started_ns = completed_ns - 1'000'000ULL;
    observation.completed_ns = completed_ns;
    observation.query_kind = neta::NameResolutionQueryKind::Forward;
    observation.mechanism = neta::NameResolutionMechanism::ApplicationResolverApi;
    observation.process.agent_visible.tgid = 4242;
    observation.process.start_ticks = 900;
    observation.network_namespace_inode = 77;
    observation.query_name = "api.example.test";
    observation.canonical_name = "edge.example.test";
    observation.addresses.push_back(
        {neta::NetworkAddressFamily::IPv4, "203.0.113.20"});
    observation.fidelity = neta::EvidenceFidelity::Exact;
    observation.source = "deterministic-test-resolver";
    return observation;
}

void unique_exact_lookup_is_strongly_correlated() {
    const auto connection = outbound_connection();
    const auto result = neta::correlate_name_resolution(
        connection, {exact_lookup(9'500'000'000ULL)});
    assert(result.status == neta::NameResolutionCorrelationStatus::Matched);
    assert(result.candidate_count == 1);
    assert(result.evidence);
    assert(result.evidence->relation ==
           neta::NameResolutionRelation::ResolvedAddressForOutboundConnection);
    assert(result.evidence->correlation_fidelity ==
           neta::EvidenceFidelity::StronglyCorrelated);
}

void ambiguous_lookup_is_not_guessed() {
    const auto connection = outbound_connection();
    const auto result = neta::correlate_name_resolution(
        connection,
        {exact_lookup(9'400'000'000ULL), exact_lookup(9'500'000'000ULL)});
    assert(result.status == neta::NameResolutionCorrelationStatus::Ambiguous);
    assert(result.candidate_count == 2);
    assert(!result.evidence);
}

void missing_durable_identity_downgrades_fidelity() {
    const auto connection = outbound_connection();
    auto observation = exact_lookup(9'500'000'000ULL);
    observation.process.start_ticks.reset();
    observation.network_namespace_inode.reset();
    const auto result = neta::correlate_name_resolution(connection, {observation});
    assert(result.status == neta::NameResolutionCorrelationStatus::Matched);
    assert(result.evidence);
    assert(result.evidence->correlation_fidelity == neta::EvidenceFidelity::Supporting);
}

void inbound_and_reverse_lookups_do_not_cross_correlate() {
    auto connection = outbound_connection();
    connection.direction = neta::ConnectionDirection::Inbound;
    auto result = neta::correlate_name_resolution(
        connection, {exact_lookup(9'500'000'000ULL)});
    assert(result.status == neta::NameResolutionCorrelationStatus::NoMatch);

    connection.direction = neta::ConnectionDirection::Outbound;
    auto reverse = exact_lookup(9'500'000'000ULL);
    reverse.query_kind = neta::NameResolutionQueryKind::Reverse;
    result = neta::correlate_name_resolution(connection, {reverse});
    assert(result.status == neta::NameResolutionCorrelationStatus::NoMatch);
}

void stale_or_wrong_process_lookup_is_rejected() {
    const auto connection = outbound_connection();
    auto stale = exact_lookup(4'000'000'000ULL);
    auto result = neta::correlate_name_resolution(connection, {stale});
    assert(result.status == neta::NameResolutionCorrelationStatus::NoMatch);

    auto wrong_process = exact_lookup(9'500'000'000ULL);
    wrong_process.process.agent_visible.tgid = 4243;
    result = neta::correlate_name_resolution(connection, {wrong_process});
    assert(result.status == neta::NameResolutionCorrelationStatus::NoMatch);
}

} // namespace

int main() {
    unique_exact_lookup_is_strongly_correlated();
    ambiguous_lookup_is_not_guessed();
    missing_durable_identity_downgrades_fidelity();
    inbound_and_reverse_lookups_do_not_cross_correlate();
    stale_or_wrong_process_lookup_is_rejected();
    std::cout << "Name-resolution correlation tests passed\n";
}
