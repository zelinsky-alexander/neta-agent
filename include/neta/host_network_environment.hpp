#pragma once

#include "neta/model.hpp"

#include <cstdint>
#include <optional>
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

} // namespace neta
