#include "neta/route_semantics.hpp"

namespace neta {

std::string to_string(RouteRelation relation) {
    switch (relation) {
        case RouteRelation::OutboundSelectedRoute: return "OUTBOUND_SELECTED_ROUTE";
        case RouteRelation::InboundResponseRoute: return "INBOUND_RESPONSE_ROUTE";
        case RouteRelation::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

RouteRelation route_relation_from_string(const std::string& value) {
    if (value == "OUTBOUND_SELECTED_ROUTE") return RouteRelation::OutboundSelectedRoute;
    if (value == "INBOUND_RESPONSE_ROUTE") return RouteRelation::InboundResponseRoute;
    return RouteRelation::Unknown;
}

} // namespace neta
