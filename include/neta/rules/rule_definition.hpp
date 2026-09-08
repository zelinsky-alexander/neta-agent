#pragma once

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace neta::rules {

class RuleDefinition {
public:
    std::string id;
    std::string name;
    std::string category;
    std::string severity;
    bool enabled{true};
    std::map<std::string, double> numeric_parameters;
    std::map<std::string, bool> boolean_parameters;
    std::map<std::string, std::string> string_parameters;
    std::map<std::string, std::vector<std::string>> string_list_parameters;

    [[nodiscard]] double numeric(const std::string& name) const {
        const auto it = numeric_parameters.find(name);
        if (it == numeric_parameters.end()) throw std::runtime_error("missing numeric rule parameter: " + name);
        return it->second;
    }

    [[nodiscard]] bool boolean(const std::string& name) const {
        const auto it = boolean_parameters.find(name);
        if (it == boolean_parameters.end()) throw std::runtime_error("missing boolean rule parameter: " + name);
        return it->second;
    }

    [[nodiscard]] const std::string& string(const std::string& name) const {
        const auto it = string_parameters.find(name);
        if (it == string_parameters.end()) throw std::runtime_error("missing string rule parameter: " + name);
        return it->second;
    }

    [[nodiscard]] const std::vector<std::string>& string_list(const std::string& name) const {
        const auto it = string_list_parameters.find(name);
        if (it == string_list_parameters.end()) throw std::runtime_error("missing string-list rule parameter: " + name);
        return it->second;
    }
};

} // namespace neta::rules
