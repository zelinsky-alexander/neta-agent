#pragma once

#include "neta/rules/rule_set_loader.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

namespace neta::cli {

inline std::filesystem::path rules_file_arg(int argc, char** argv) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--file") return argv[i + 1];
    }
    return {};
}

inline RuleSet load_rules_for_command(int argc, char** argv) {
    const auto path = rules_file_arg(argc, argv);
    return path.empty() ? rules::RuleSetLoader::active() : rules::RuleSetLoader::load_file(path);
}

inline void print_rule_set_header(const RuleSet& set) {
    std::cout << "Rule set: " << set.id << "\n"
              << "Revision: " << set.revision << "\n"
              << "Schema:   " << set.schema_version << "\n"
              << "Version:  " << set.version << "\n";
}

inline void print_rule_parameters(const rules::RuleDefinition& rule) {
    if (rule.numeric_parameters.empty() && rule.boolean_parameters.empty() &&
        rule.string_parameters.empty() && rule.string_list_parameters.empty()) return;

    std::cout << "Parameters:\n";
    for (const auto& [name, value] : rule.numeric_parameters)
        std::cout << "  " << name << ": " << value << '\n';
    for (const auto& [name, value] : rule.boolean_parameters)
        std::cout << "  " << name << ": " << (value ? "true" : "false") << '\n';
    for (const auto& [name, value] : rule.string_parameters)
        std::cout << "  " << name << ": " << value << '\n';
    for (const auto& [name, values] : rule.string_list_parameters) {
        std::cout << "  " << name << ": [";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i != 0) std::cout << ", ";
            std::cout << values[i];
        }
        std::cout << "]\n";
    }
}

inline int run_rules_command(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "Usage:\n"
                  << "  neta-agent rules list [--file FILE]\n"
                  << "  neta-agent rules show RULE_ID [--file FILE]\n"
                  << "  neta-agent rules validate FILE\n"
                  << "  neta-agent rules active\n";
        return 1;
    }

    const std::string action = argv[2];
    if (action == "validate") {
        if (argc < 4) throw std::runtime_error("rules validate requires a file path");
        const auto set = rules::RuleSetLoader::load_file(argv[3]);
        print_rule_set_header(set);
        std::cout << "Rules:      " << set.definitions.size() << "\nValidation: OK\n";
        return 0;
    }

    const auto set = load_rules_for_command(argc, argv);
    if (action == "active") {
        print_rule_set_header(set);
        std::cout << "Rules:    " << set.definitions.size() << "\n";
        return 0;
    }

    if (action == "list") {
        print_rule_set_header(set);
        std::cout << "\nID                 CATEGORY      ENABLED  SEVERITY  NAME\n";
        for (const auto& rule : set.definitions) {
            std::cout << std::left << std::setw(19) << rule.id
                      << std::setw(14) << rule.category
                      << std::setw(9) << (rule.enabled ? "YES" : "NO")
                      << std::setw(10) << (rule.severity.empty() ? "-" : rule.severity)
                      << rule.name << '\n';
        }
        return 0;
    }

    if (action == "show") {
        if (argc < 4) throw std::runtime_error("rules show requires a rule id");
        const std::string id = argv[3];
        for (const auto& rule : set.definitions) {
            if (rule.id != id) continue;
            std::cout << "ID:       " << rule.id << "\n"
                      << "Name:     " << rule.name << "\n"
                      << "Category: " << rule.category << "\n"
                      << "Enabled:  " << (rule.enabled ? "YES" : "NO") << "\n"
                      << "Severity: " << (rule.severity.empty() ? "-" : rule.severity) << "\n"
                      << "Rule set: " << set.id << " / " << set.revision << "\n"
                      << "Version:  " << set.version << "\n";
            print_rule_parameters(rule);
            return 0;
        }
        throw std::runtime_error("unknown rule id: " + id);
    }

    throw std::runtime_error("unknown rules action: " + action);
}

} // namespace neta::cli
