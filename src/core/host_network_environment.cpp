#include "neta/host_network_environment.hpp"

#include "neta/crypto.hpp"

#include <sstream>

namespace neta {
namespace {

void append_optional(std::ostringstream& canonical,
                     const std::optional<std::uint64_t>& value) {
    if (value) canonical << *value;
}

void append_optional(std::ostringstream& canonical,
                     const std::optional<std::uint32_t>& value) {
    if (value) canonical << *value;
}

} // namespace

std::string host_network_environment_fingerprint(
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
    append_optional(canonical, evidence.network_namespace_inode);
    canonical << '|';
    append_optional(canonical, evidence.interface_index);
    canonical << '|'
              << evidence.interface_name << '|'
              << evidence.interface_mac << '|';
    append_optional(canonical, evidence.interface_mtu);
    canonical << '|'
              << evidence.local_address << '|'
              << evidence.gateway << '|'
              << evidence.preferred_source << '|';
    append_optional(canonical, evidence.route_table);
    canonical << '|';
    append_optional(canonical, evidence.route_metric);
    return sha256_hex(canonical.str());
}

} // namespace neta
