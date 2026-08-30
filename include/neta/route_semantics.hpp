#pragma once

#include <string>

namespace neta {

enum class RouteRelation { OutboundSelectedRoute, InboundResponseRoute, Unknown };

std::string to_string(RouteRelation relation);
RouteRelation route_relation_from_string(const std::string& value);

} // namespace neta
