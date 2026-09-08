#pragma once

#include <map>
#include <string>

namespace neta::rules {

class RuleDefinition {
public:
    std::string id;
    std::string name;
    std::string category;
    std::string severity;
    bool enabled{true};
    std::map<std::string, double> numeric_parameters;
};

} // namespace neta::rules
