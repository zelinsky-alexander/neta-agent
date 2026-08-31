#pragma once

#include "neta/crypto.hpp"
#include "neta/model.hpp"

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>

namespace neta {

struct HostNetworkEnvironmentEvidence {
    std::uint64_t captured_at_ns{0};
    EvidenceFidelity fidelity{EvidenceFidelity::StronglyCorrelated};
    std::string source{"linux:host-network-environment"};

    std::string host_id;
    std::string hostname;
    std::string boot_id;
    std::string os{"Linux"};
    std::string kernel_release;
    std::string architecture;
    std::string environment_class;

    std::optional<std::uint64_t> network_namespace_inode;
    std::optional<std::uint32_t> interface_index;
    std::string interface_name;
    std::string interface_mac;
    std::optional<std::uint32_t> interface_mtu;
    std::string local_address;
    std::string gateway;
    std::string preferred_source;
    std::optional<std::uint32_t> route_table;
    std::optional<std::uint32_t> route_metric;

    std::string environment_fingerprint;
};

// Canonical v2 fingerprint for the complete captured host/network context.
// Empty/absent values remain explicit empty markers; callers must never invent
// evidence merely to make the fingerprint complete.
inline std::string host_network_environment_fingerprint(
    const HostNetworkEnvironmentEvidence& evidence) {
    std::ostringstream canonical;
    canonical << "neta-env-v2|"
              << evidence.host_id << '|'
              << evidence.hostname << '|'
              << evidence.os << '|'
              << evidence.boot_id << '|'
              << evidence.kernel_release << '|'
              << evidence.architecture << '|'
              << evidence.environment_class << '|';
    if (evidence.network_namespace_inode) canonical << *evidence.network_namespace_inode;
    canonical << '|';
    if (evidence.interface_index) canonical << *evidence.interface_index;
    canonical << '|'
              << evidence.interface_name << '|'
              << evidence.interface_mac << '|';
    if (evidence.interface_mtu) canonical << *evidence.interface_mtu;
    canonical << '|'
              << evidence.local_address << '|'
              << evidence.gateway << '|'
              << evidence.preferred_source << '|';
    if (evidence.route_table) canonical << *evidence.route_table;
    canonical << '|';
    if (evidence.route_metric) canonical << *evidence.route_metric;
    return sha256_hex(canonical.str());
}

} // namespace neta
