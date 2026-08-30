#pragma once

#include <string>

namespace neta {

enum class ConnectionDirection { Outbound, Inbound, Unknown };

std::string to_string(ConnectionDirection direction);
ConnectionDirection connection_direction_from_string(const std::string& value);

} // namespace neta
