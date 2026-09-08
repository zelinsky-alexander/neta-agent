#pragma once

#include "neta/rules/json_parser.hpp"
#include "neta/rules/rule_set.hpp"

#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>

namespace neta::rules {

class RuleSetLoader {
public:
    static RuleSet load_file(const std::filesystem::path& path) {
        std::ifstream input(path);
        if (!input) throw std::runtime_error("cannot open rule set file: " + path.string());
        std::ostringstream buffer;
        buffer << input.rdbuf();
        return load_text(buffer.str(), path.string());
    }

    static RuleSet load_text(const std::string& text, const std::string& source = "<memory>") {
        try {
            const JsonValue root = JsonParser(text).parse();
            return parse_root(root);
        } catch (const std::exception& error) {
            throw std::runtime_error("rule set validation failed for " + source + ": " + error.what());
        }
    }

    static RuleSet built_in() { return load_text(default_document(), "built-in default rules"); }

    static RuleSet active() {
        if (const char* configured = std::getenv("NETA_RULE_SET_FILE"); configured && *configured) {
            return load_file(configured);
        }
        const std::filesystem::path local_default{"rules/default-rules.json"};
        if (std::filesystem::exists(local_default)) return load_file(local_default);
        return built_in();
    }

private:
    static const std::string& require_string(const JsonValue& object, const std::string& key) {
        return object.at(key).as_string();
    }

    static std::uint64_t require_u64(const JsonValue& object, const std::string& key) {
        const double value = object.at(key).as_number();
        if (!std::isfinite(value) || value < 0.0 || std::floor(value) != value ||
            value > static_cast<double>(std::numeric_limits<std::uint64_t>::max())) {
            throw std::runtime_error(key + " must be a non-negative integer");
        }
        return static_cast<std::uint64_t>(value);
    }

    static bool optional_bool(const JsonValue& object, const std::string& key, bool fallback) {
        const auto* value = object.find(key);
        return value ? value->as_boolean() : fallback;
    }

    static std::string optional_string(const JsonValue& object, const std::string& key) {
        const auto* value = object.find(key);
        return value ? value->as_string() : std::string{};
    }

    static void ensure_keys(const JsonValue& object, std::initializer_list<const char*> allowed,
                            const std::string& context) {
        std::set<std::string> valid;
        for (const char* key : allowed) valid.emplace(key);
        for (const auto& [key, unused] : object.as_object()) {
            (void)unused;
            if (!valid.contains(key)) throw std::runtime_error(context + " contains unsupported field: " + key);
        }
    }

    static double require_parameter(const JsonValue& parameters, const std::string& key) {
        const double value = parameters.at(key).as_number();
        if (!std::isfinite(value)) throw std::runtime_error("parameter " + key + " must be finite");
        return value;
    }

    static RuleDefinition parse_definition(const JsonValue& value) {
        ensure_keys(value, {"id", "name", "category", "severity", "enabled", "parameters"}, "rule");
        RuleDefinition definition;
        definition.id = require_string(value, "id");
        definition.name = require_string(value, "name");
        definition.category = require_string(value, "category");
        definition.severity = optional_string(value, "severity");
        definition.enabled = optional_bool(value, "enabled", true);
        if (definition.id.empty() || definition.name.empty() || definition.category.empty()) {
            throw std::runtime_error("rule id, name, and category must be non-empty");
        }
        if (const auto* parameters = value.find("parameters")) {
            for (const auto& [key, parameter] : parameters->as_object()) {
                definition.numeric_parameters.emplace(key, parameter.as_number());
            }
        }
        return definition;
    }

    static RuleSet parse_root(const JsonValue& root) {
        ensure_keys(root, {"schema_version", "id", "revision", "version", "rules"}, "rule set");
        RuleSet set;
        set.schema_version = require_u64(root, "schema_version");
        set.id = require_string(root, "id");
        set.revision = require_u64(root, "revision");
        set.version = require_string(root, "version");
        if (set.schema_version != 1) throw std::runtime_error("unsupported rule schema version");
        if (set.id.empty() || set.revision == 0 || set.version.empty()) {
            throw std::runtime_error("rule set id/version must be non-empty and revision must be positive");
        }

        bool performance_seen = false;
        bool outbound_trust_seen = false;
        bool inbound_trust_seen = false;
        std::set<std::string> ids;

        for (const auto& item : root.at("rules").as_array()) {
            RuleDefinition definition = parse_definition(item);
            if (!ids.insert(definition.id).second) throw std::runtime_error("duplicate rule id: " + definition.id);

            if (definition.id == "NETA-PERF-001") {
                if (!definition.enabled) throw std::runtime_error("NETA-PERF-001 cannot be disabled in schema v1");
                if (definition.category != "performance") throw std::runtime_error("NETA-PERF-001 must use performance category");
                const auto& parameters = item.at("parameters");
                ensure_keys(parameters,
                            {"rtt_ratio", "rttvar_ratio", "retransmission_threshold", "rtt_weight",
                             "rttvar_weight", "retransmission_weight", "degraded_threshold"},
                            "NETA-PERF-001 parameters");
                set.rtt_ratio = require_parameter(parameters, "rtt_ratio");
                set.rttvar_ratio = require_parameter(parameters, "rttvar_ratio");
                const double retransmissions = require_parameter(parameters, "retransmission_threshold");
                if (retransmissions < 0.0 || std::floor(retransmissions) != retransmissions) {
                    throw std::runtime_error("retransmission_threshold must be a non-negative integer");
                }
                set.retransmission_threshold = static_cast<std::uint64_t>(retransmissions);
                set.rtt_weight = require_parameter(parameters, "rtt_weight");
                set.rttvar_weight = require_parameter(parameters, "rttvar_weight");
                set.retransmission_weight = require_parameter(parameters, "retransmission_weight");
                set.degraded_threshold = require_parameter(parameters, "degraded_threshold");
                if (set.rtt_ratio <= 0.0 || set.rttvar_ratio <= 0.0 || set.rtt_weight < 0.0 ||
                    set.rttvar_weight < 0.0 || set.retransmission_weight < 0.0 ||
                    set.degraded_threshold <= 0.0) {
                    throw std::runtime_error("performance ratios/weights/thresholds must be non-negative and thresholds positive");
                }
                performance_seen = true;
            } else if (definition.id == "NETA-TRUST-001") {
                if (definition.category != "trust") throw std::runtime_error("NETA-TRUST-001 must use trust category");
                if (!definition.enabled) throw std::runtime_error("NETA-TRUST-001 cannot be disabled in schema v1");
                if (const auto* parameters = item.find("parameters"); parameters && !parameters->as_object().empty()) {
                    throw std::runtime_error("NETA-TRUST-001 does not accept parameters in schema v1");
                }
                outbound_trust_seen = true;
            } else if (definition.id == "NETA-TRUST-002") {
                if (definition.category != "trust") throw std::runtime_error("NETA-TRUST-002 must use trust category");
                if (const auto* parameters = item.find("parameters"); parameters && !parameters->as_object().empty()) {
                    throw std::runtime_error("NETA-TRUST-002 does not accept parameters in schema v1");
                }
                set.inbound_authenticated_identity = definition.enabled;
                inbound_trust_seen = true;
            } else {
                throw std::runtime_error("unsupported rule id in schema v1: " + definition.id);
            }
            set.definitions.push_back(std::move(definition));
        }

        if (!performance_seen || !outbound_trust_seen || !inbound_trust_seen) {
            throw std::runtime_error("schema v1 requires NETA-PERF-001, NETA-TRUST-001, and NETA-TRUST-002");
        }
        return set;
    }

    static const char* default_document() {
        return R"JSON({
  "schema_version": 1,
  "id": "neta-default",
  "revision": 1,
  "version": "neta-rules/0.2.0",
  "rules": [
    {
      "id": "NETA-PERF-001",
      "name": "Network path degradation",
      "category": "performance",
      "severity": "medium",
      "enabled": true,
      "parameters": {
        "rtt_ratio": 2.0,
        "rttvar_ratio": 2.0,
        "retransmission_threshold": 2,
        "rtt_weight": 0.50,
        "rttvar_weight": 0.20,
        "retransmission_weight": 0.30,
        "degraded_threshold": 0.50
      }
    },
    {
      "id": "NETA-TRUST-001",
      "name": "Outbound TLS identity",
      "category": "trust",
      "severity": "high",
      "enabled": true,
      "parameters": {}
    },
    {
      "id": "NETA-TRUST-002",
      "name": "Inbound authenticated TLS identity",
      "category": "trust",
      "severity": "high",
      "enabled": true,
      "parameters": {}
    }
  ]
})JSON";
    }
};

} // namespace neta::rules
