#pragma once

#include "neta/rules/json_parser.hpp"
#include "neta/rules/rule_set.hpp"

#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

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
        try { return parse_root(JsonParser(text).parse()); }
        catch (const std::exception& error) {
            throw std::runtime_error("rule set validation failed for " + source + ": " + error.what());
        }
    }

    static RuleSet built_in() { return load_text(default_document(), "built-in RM2 default rules"); }
    static RuleSet rm1_built_in() { return load_text(rm1_document(), "built-in RM1 default rules"); }

    static std::filesystem::path centrally_managed_path() {
        if (const char* configured = std::getenv("NETA_RULE_STATE_DIR"); configured && *configured)
            return std::filesystem::path(configured) / "rules" / "active.json";
#ifdef _WIN32
        if (const char* program_data = std::getenv("ProgramData"); program_data && *program_data)
            return std::filesystem::path(program_data) / "NETA" / "identity" / "rules" / "active.json";
        return std::filesystem::path("C:/ProgramData/NETA/identity/rules/active.json");
#else
        return std::filesystem::path("/var/lib/neta/identity/rules/active.json");
#endif
    }

    static RuleSet active() {
        if (const char* configured = std::getenv("NETA_RULE_SET_FILE"); configured && *configured)
            return load_file(configured);
        const auto managed = centrally_managed_path();
        if (std::filesystem::exists(managed)) return load_file(managed);
        return built_in();
    }

private:
    static const std::set<std::string>& rm1_default_ids() {
        static const std::set<std::string> ids{
            "NETA-PERF-001", "NETA-TRUST-001", "NETA-TRUST-002",
            "NETA-PROC-001", "NETA-PROC-002", "NETA-PROC-003", "NETA-PROC-004", "NETA-PROC-005"};
        return ids;
    }

    static bool is_supported_custom_engine(const std::string& id) {
        static const std::set<std::string> engines{
            "NETA-PERF-001", "NETA-TRUST-001", "NETA-TRUST-002",
            "NETA-PROC-001", "NETA-PROC-002", "NETA-PROC-003", "NETA-PROC-004", "NETA-PROC-005",
            "NETA-BEH-001", "NETA-NET-001", "NETA-NET-002", "NETA-NET-003", "NETA-NET-004",
            "NETA-DNS-001", "NETA-DNS-002", "NETA-DNS-003",
            "NETA-TLS-001", "NETA-TLS-002", "NETA-ROUTE-001"};
        return engines.contains(id);
    }

    static const std::string& require_string(const JsonValue& object, const std::string& key) {
        return object.at(key).as_string();
    }

    static std::uint64_t require_u64(const JsonValue& object, const std::string& key) {
        const double value = object.at(key).as_number();
        if (!std::isfinite(value) || value < 0.0 || std::floor(value) != value ||
            value > static_cast<double>(std::numeric_limits<std::uint64_t>::max()))
            throw std::runtime_error(key + " must be a non-negative integer");
        return static_cast<std::uint64_t>(value);
    }

    static bool optional_bool(const JsonValue& object, const std::string& key, bool fallback) {
        const auto* value = object.find(key); return value ? value->as_boolean() : fallback;
    }
    static std::string optional_string(const JsonValue& object, const std::string& key) {
        const auto* value = object.find(key); return value ? value->as_string() : std::string{};
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

    static void ensure_parameter_keys(const RuleDefinition& definition,
                                      std::initializer_list<const char*> allowed) {
        std::set<std::string> valid;
        for (const char* key : allowed) valid.emplace(key);
        const auto check = [&](const auto& parameters) {
            for (const auto& [key, unused] : parameters) {
                (void)unused;
                if (!valid.contains(key))
                    throw std::runtime_error(definition.id + " contains unsupported parameter: " + key);
            }
        };
        check(definition.numeric_parameters); check(definition.boolean_parameters);
        check(definition.string_parameters); check(definition.string_list_parameters);
    }

    static std::vector<std::string> string_array(const JsonValue& value) {
        std::vector<std::string> result;
        for (const auto& item : value.as_array()) {
            const auto& text = item.as_string();
            if (text.empty()) throw std::runtime_error("string-list rule parameters may not contain empty values");
            result.push_back(text);
        }
        return result;
    }

    static RuleDefinition parse_definition(const JsonValue& value, std::uint64_t schema_version) {
        if (schema_version == 1)
            ensure_keys(value, {"id", "name", "category", "severity", "enabled", "parameters"}, "rule");
        else
            ensure_keys(value, {"id", "engine_rule_id", "name", "category", "severity", "enabled", "parameters"}, "rule");
        RuleDefinition definition;
        definition.id = require_string(value, "id");
        definition.engine_rule_id = optional_string(value, "engine_rule_id");
        if (definition.engine_rule_id.empty()) definition.engine_rule_id = definition.id;
        definition.name = require_string(value, "name");
        definition.category = require_string(value, "category");
        definition.severity = optional_string(value, "severity");
        definition.enabled = optional_bool(value, "enabled", true);
        if (definition.id.empty() || definition.engine_rule_id.empty() || definition.name.empty() || definition.category.empty())
            throw std::runtime_error("rule id, engine_rule_id, name, and category must be non-empty");
        if (const auto* parameters = value.find("parameters")) {
            for (const auto& [key, parameter] : parameters->as_object()) {
                if (parameter.is_number()) definition.numeric_parameters.emplace(key, parameter.as_number());
                else if (parameter.is_boolean()) definition.boolean_parameters.emplace(key, parameter.as_boolean());
                else if (parameter.is_string()) definition.string_parameters.emplace(key, parameter.as_string());
                else if (parameter.is_array()) definition.string_list_parameters.emplace(key, string_array(parameter));
                else throw std::runtime_error("unsupported parameter type for " + key);
            }
        }
        return definition;
    }

    static void require_category(const RuleDefinition& definition, const char* expected) {
        if (definition.category != expected)
            throw std::runtime_error(definition.id + " must use " + expected + " category");
    }
    static std::uint64_t positive_integer(const RuleDefinition& definition, const std::string& name) {
        const double value = definition.numeric(name);
        if (!std::isfinite(value) || value <= 0.0 || std::floor(value) != value ||
            value > static_cast<double>(std::numeric_limits<std::uint64_t>::max()))
            throw std::runtime_error(definition.id + " parameter " + name + " must be a positive integer");
        return static_cast<std::uint64_t>(value);
    }
    static void fraction(const RuleDefinition& definition, const std::string& name) {
        const auto value = definition.numeric(name);
        if (!std::isfinite(value) || value < 0.0 || value > 1.0)
            throw std::runtime_error(definition.id + " parameter " + name + " must be between 0 and 1");
    }
    static void validate_severity(const RuleDefinition& definition) {
        if (definition.severity != "low" && definition.severity != "medium" && definition.severity != "high")
            throw std::runtime_error(definition.id + " severity must be low, medium, or high");
    }

    static void validate_engine(RuleDefinition& definition, RuleSet& set) {
        const auto& engine = definition.engine_rule_id;
        if (engine == "NETA-PERF-001") {
            require_category(definition, "performance");
            ensure_parameter_keys(definition, {"rtt_ratio", "rttvar_ratio", "retransmission_threshold", "rtt_weight",
                                               "rttvar_weight", "retransmission_weight", "degraded_threshold"});
            (void)positive_integer(definition, "retransmission_threshold");
            if (definition.numeric("rtt_ratio") <= 0.0 || definition.numeric("rttvar_ratio") <= 0.0 ||
                definition.numeric("rtt_weight") < 0.0 || definition.numeric("rttvar_weight") < 0.0 ||
                definition.numeric("retransmission_weight") < 0.0 || definition.numeric("degraded_threshold") <= 0.0)
                throw std::runtime_error(definition.id + " has invalid performance ratios/weights/threshold");
            if (definition.id == engine) {
                set.performance_enabled = definition.enabled;
                set.rtt_ratio = definition.numeric("rtt_ratio"); set.rttvar_ratio = definition.numeric("rttvar_ratio");
                set.retransmission_threshold = positive_integer(definition, "retransmission_threshold");
                set.rtt_weight = definition.numeric("rtt_weight"); set.rttvar_weight = definition.numeric("rttvar_weight");
                set.retransmission_weight = definition.numeric("retransmission_weight");
                set.degraded_threshold = definition.numeric("degraded_threshold");
            }
        } else if (engine == "NETA-TRUST-001") {
            require_category(definition, "trust");
            ensure_parameter_keys(definition, {"require_chain_valid", "require_hostname_valid", "compare_spki"});
            (void)definition.boolean("require_chain_valid"); (void)definition.boolean("require_hostname_valid");
            (void)definition.boolean("compare_spki");
            if (definition.id == engine) {
                set.outbound_tls_identity = definition.enabled;
                set.outbound_require_chain_valid = definition.boolean("require_chain_valid");
                set.outbound_require_hostname_valid = definition.boolean("require_hostname_valid");
                set.outbound_compare_spki = definition.boolean("compare_spki");
            }
        } else if (engine == "NETA-TRUST-002") {
            require_category(definition, "trust");
            ensure_parameter_keys(definition, {"require_exact_evidence", "require_peer_certificate", "require_peer_authentication",
                                               "verification_failure_suspicious", "compare_spki", "compare_issuer"});
            (void)definition.boolean("require_exact_evidence"); (void)definition.boolean("require_peer_certificate");
            (void)definition.boolean("require_peer_authentication"); (void)definition.boolean("verification_failure_suspicious");
            (void)definition.boolean("compare_spki"); (void)definition.boolean("compare_issuer");
            if (definition.id == engine) {
                set.inbound_authenticated_identity = definition.enabled;
                set.inbound_require_exact_evidence = definition.boolean("require_exact_evidence");
                set.inbound_require_peer_certificate = definition.boolean("require_peer_certificate");
                set.inbound_require_peer_authentication = definition.boolean("require_peer_authentication");
                set.inbound_verification_failure_suspicious = definition.boolean("verification_failure_suspicious");
                set.inbound_compare_spki = definition.boolean("compare_spki");
                set.inbound_compare_issuer = definition.boolean("compare_issuer");
            }
        } else if (engine == "NETA-PROC-001") {
            require_category(definition, "process"); ensure_parameter_keys(definition, {"path_prefixes", "path_substrings"});
            (void)definition.string_list("path_prefixes"); (void)definition.string_list("path_substrings");
        } else if (engine == "NETA-PROC-002") {
            require_category(definition, "process"); ensure_parameter_keys(definition, {"shell_names", "expected_parent_names"});
            (void)definition.string_list("shell_names"); (void)definition.string_list("expected_parent_names");
        } else if (engine == "NETA-PROC-003") {
            require_category(definition, "process"); ensure_parameter_keys(definition, {"expected_parent_names"});
            (void)definition.string_list("expected_parent_names");
        } else if (engine == "NETA-PROC-004") {
            require_category(definition, "process"); ensure_parameter_keys(definition, {"child_count", "window_ms"});
            (void)positive_integer(definition, "child_count"); (void)positive_integer(definition, "window_ms");
        } else if (engine == "NETA-PROC-005") {
            require_category(definition, "process"); ensure_parameter_keys(definition, {"child_count", "max_lifetime_ms", "window_ms"});
            (void)positive_integer(definition, "child_count"); (void)positive_integer(definition, "max_lifetime_ms");
            (void)positive_integer(definition, "window_ms");
        } else if (engine == "NETA-BEH-001") {
            require_category(definition, "behavior");
            ensure_parameter_keys(definition, {"minimum_connections", "window_ms", "minimum_interval_ms", "maximum_interval_ms",
                                               "interval_tolerance_ratio", "minimum_regular_fraction", "recent_connection_limit"});
            (void)positive_integer(definition, "minimum_connections"); (void)positive_integer(definition, "window_ms");
            (void)positive_integer(definition, "minimum_interval_ms"); (void)positive_integer(definition, "maximum_interval_ms");
            (void)positive_integer(definition, "recent_connection_limit"); fraction(definition, "interval_tolerance_ratio");
            fraction(definition, "minimum_regular_fraction");
        } else if (engine == "NETA-NET-001") {
            require_category(definition, "network"); ensure_parameter_keys(definition, {"minimum_bytes_received"});
            (void)positive_integer(definition, "minimum_bytes_received");
        } else if (engine == "NETA-NET-002") {
            require_category(definition, "network"); ensure_parameter_keys(definition, {"retransmission_threshold"});
            (void)positive_integer(definition, "retransmission_threshold");
        } else if (engine == "NETA-NET-003") {
            require_category(definition, "network"); ensure_parameter_keys(definition, {"allowed_ports"});
            (void)definition.string_list("allowed_ports");
        } else if (engine == "NETA-NET-004") {
            require_category(definition, "network"); ensure_parameter_keys(definition, {"maximum_prevalence"});
            (void)positive_integer(definition, "maximum_prevalence");
        } else if (engine == "NETA-DNS-001") {
            require_category(definition, "dns"); ensure_parameter_keys(definition, {"minimum_failures"});
            (void)positive_integer(definition, "minimum_failures");
        } else if (engine == "NETA-DNS-002") {
            require_category(definition, "dns"); ensure_parameter_keys(definition, {"require_remote_ip_match"});
            (void)definition.boolean("require_remote_ip_match");
        } else if (engine == "NETA-DNS-003") {
            require_category(definition, "dns"); ensure_parameter_keys(definition, {"maximum_distinct_answers"});
            (void)positive_integer(definition, "maximum_distinct_answers");
        } else if (engine == "NETA-TLS-001") {
            require_category(definition, "tls"); ensure_parameter_keys(definition, {"require_peer_authentication", "verification_failure_match"});
            (void)definition.boolean("require_peer_authentication"); (void)definition.boolean("verification_failure_match");
        } else if (engine == "NETA-TLS-002") {
            require_category(definition, "tls"); ensure_parameter_keys(definition, {"compare_spki", "compare_issuer"});
            (void)definition.boolean("compare_spki"); (void)definition.boolean("compare_issuer");
        } else if (engine == "NETA-ROUTE-001") {
            require_category(definition, "route"); ensure_parameter_keys(definition, {"allowed_gateways", "allowed_interfaces"});
            (void)definition.string_list("allowed_gateways"); (void)definition.string_list("allowed_interfaces");
        } else {
            throw std::runtime_error("unsupported engine_rule_id: " + engine);
        }
    }

    static RuleSet parse_root(const JsonValue& root) {
        ensure_keys(root, {"schema_version", "id", "revision", "version", "rules"}, "rule set");
        RuleSet set;
        set.schema_version = require_u64(root, "schema_version"); set.id = require_string(root, "id");
        set.revision = require_u64(root, "revision"); set.version = require_string(root, "version");
        if (set.schema_version != 1 && set.schema_version != 2) throw std::runtime_error("unsupported rule schema version");
        if (set.id.empty() || set.revision == 0 || set.version.empty())
            throw std::runtime_error("rule set id/version must be non-empty and revision must be positive");

        std::set<std::string> ids;
        for (const auto& item : root.at("rules").as_array()) {
            RuleDefinition definition = parse_definition(item, set.schema_version);
            if (!ids.insert(definition.id).second) throw std::runtime_error("duplicate rule id: " + definition.id);
            validate_severity(definition);
            if (set.schema_version == 1 && definition.engine_rule_id != definition.id)
                throw std::runtime_error("schema v1 does not support a distinct engine_rule_id");
            if (definition.id != definition.engine_rule_id && !is_supported_custom_engine(definition.engine_rule_id))
                throw std::runtime_error("unsupported custom trusted engine: " + definition.engine_rule_id);
            if (definition.id != definition.engine_rule_id && !definition.id.starts_with("CUS-"))
                throw std::runtime_error("custom centrally managed rule ids must start with CUS-");
            validate_engine(definition, set);
            set.definitions.push_back(std::move(definition));
        }
        for (const auto& required : rm1_default_ids()) {
            if (!ids.contains(required)) throw std::runtime_error("rule set is missing required default rule: " + required);
        }
        if (set.schema_version == 1 && ids != rm1_default_ids())
            throw std::runtime_error("schema v1 permits only the RM1 default rule catalog");
        return set;
    }

    static const char* rm1_document() {
        return R"JSON({
  "schema_version":1,"id":"neta-default","revision":2,"version":"neta-rules/0.3.0","rules":[
    {"id":"NETA-PERF-001","name":"Network path degradation","category":"performance","severity":"medium","enabled":true,"parameters":{"rtt_ratio":2.0,"rttvar_ratio":2.0,"retransmission_threshold":2,"rtt_weight":0.50,"rttvar_weight":0.20,"retransmission_weight":0.30,"degraded_threshold":0.50}},
    {"id":"NETA-TRUST-001","name":"Outbound TLS identity","category":"trust","severity":"high","enabled":true,"parameters":{"require_chain_valid":true,"require_hostname_valid":true,"compare_spki":true}},
    {"id":"NETA-TRUST-002","name":"Inbound authenticated TLS identity","category":"trust","severity":"high","enabled":true,"parameters":{"require_exact_evidence":true,"require_peer_certificate":true,"require_peer_authentication":true,"verification_failure_suspicious":true,"compare_spki":true,"compare_issuer":true}},
    {"id":"NETA-PROC-001","name":"Execution from transient path","category":"process","severity":"medium","enabled":true,"parameters":{"path_prefixes":["/tmp/","/var/tmp/","/dev/shm/"],"path_substrings":["/appdata/local/temp/","/windows/temp/"]}},
    {"id":"NETA-PROC-002","name":"Shell from unexpected parent","category":"process","severity":"medium","enabled":true,"parameters":{"shell_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe"],"expected_parent_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe","sshd","sudo","su","login","systemd","init","tmux","screen","gnome-terminal-server","konsole","windowsterminal.exe","wt.exe","conhost.exe","explorer.exe","winlogon.exe"]}},
    {"id":"NETA-PROC-003","name":"Unexpected elevation","category":"process","severity":"medium","enabled":true,"parameters":{"expected_parent_names":["sudo","su","pkexec","doas","consent.exe"]}},
    {"id":"NETA-PROC-004","name":"Rapid child process fanout","category":"process","severity":"medium","enabled":true,"parameters":{"child_count":6,"window_ms":10000}},
    {"id":"NETA-PROC-005","name":"Short-lived process burst","category":"process","severity":"medium","enabled":true,"parameters":{"child_count":6,"max_lifetime_ms":2000,"window_ms":15000}}
  ]})JSON";
    }

    static const char* default_document() {
        return R"JSON({
  "schema_version":2,"id":"neta-default","revision":3,"version":"neta-rules/0.4.0","rules":[
    {"id":"NETA-PERF-001","engine_rule_id":"NETA-PERF-001","name":"Network path degradation","category":"performance","severity":"medium","enabled":true,"parameters":{"rtt_ratio":2.0,"rttvar_ratio":2.0,"retransmission_threshold":2,"rtt_weight":0.50,"rttvar_weight":0.20,"retransmission_weight":0.30,"degraded_threshold":0.50}},
    {"id":"NETA-TRUST-001","engine_rule_id":"NETA-TRUST-001","name":"Outbound TLS identity","category":"trust","severity":"high","enabled":true,"parameters":{"require_chain_valid":true,"require_hostname_valid":true,"compare_spki":true}},
    {"id":"NETA-TRUST-002","engine_rule_id":"NETA-TRUST-002","name":"Inbound authenticated TLS identity","category":"trust","severity":"high","enabled":true,"parameters":{"require_exact_evidence":true,"require_peer_certificate":true,"require_peer_authentication":true,"verification_failure_suspicious":true,"compare_spki":true,"compare_issuer":true}},
    {"id":"NETA-PROC-001","engine_rule_id":"NETA-PROC-001","name":"Execution from transient path","category":"process","severity":"medium","enabled":true,"parameters":{"path_prefixes":["/tmp/","/var/tmp/","/dev/shm/"],"path_substrings":["/appdata/local/temp/","/windows/temp/"]}},
    {"id":"NETA-PROC-002","engine_rule_id":"NETA-PROC-002","name":"Shell from unexpected parent","category":"process","severity":"medium","enabled":true,"parameters":{"shell_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe"],"expected_parent_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe","sshd","sudo","su","login","systemd","init","tmux","screen","gnome-terminal-server","konsole","windowsterminal.exe","wt.exe","conhost.exe","explorer.exe","winlogon.exe"]}},
    {"id":"NETA-PROC-003","engine_rule_id":"NETA-PROC-003","name":"Unexpected elevation","category":"process","severity":"medium","enabled":true,"parameters":{"expected_parent_names":["sudo","su","pkexec","doas","consent.exe"]}},
    {"id":"NETA-PROC-004","engine_rule_id":"NETA-PROC-004","name":"Rapid child process fanout","category":"process","severity":"medium","enabled":true,"parameters":{"child_count":6,"window_ms":10000}},
    {"id":"NETA-PROC-005","engine_rule_id":"NETA-PROC-005","name":"Short-lived process burst","category":"process","severity":"medium","enabled":true,"parameters":{"child_count":6,"max_lifetime_ms":2000,"window_ms":15000}},
    {"id":"NETA-BEH-001","engine_rule_id":"NETA-BEH-001","name":"Periodic outbound connection pattern","category":"behavior","severity":"medium","enabled":true,"parameters":{"minimum_connections":8,"window_ms":90000,"minimum_interval_ms":3000,"maximum_interval_ms":15000,"interval_tolerance_ratio":0.20,"minimum_regular_fraction":0.80,"recent_connection_limit":512}},
    {"id":"NETA-NET-001","engine_rule_id":"NETA-NET-001","name":"Large ingress transfer","category":"network","severity":"low","enabled":true,"parameters":{"minimum_bytes_received":268435456}},
    {"id":"NETA-NET-002","engine_rule_id":"NETA-NET-002","name":"TCP retransmission spike","category":"network","severity":"medium","enabled":true,"parameters":{"retransmission_threshold":5}},
    {"id":"NETA-NET-003","engine_rule_id":"NETA-NET-003","name":"Unusual outbound destination port","category":"network","severity":"low","enabled":false,"parameters":{"allowed_ports":["22","25","53","80","110","123","143","443","465","587","853","993","995","3389"]}},
    {"id":"NETA-NET-004","engine_rule_id":"NETA-NET-004","name":"Rare outbound destination","category":"network","severity":"medium","enabled":false,"parameters":{"maximum_prevalence":2}},
    {"id":"NETA-DNS-001","engine_rule_id":"NETA-DNS-001","name":"Repeated DNS resolution failures","category":"dns","severity":"medium","enabled":true,"parameters":{"minimum_failures":3}},
    {"id":"NETA-DNS-002","engine_rule_id":"NETA-DNS-002","name":"DNS answer and connection mismatch","category":"dns","severity":"medium","enabled":true,"parameters":{"require_remote_ip_match":true}},
    {"id":"NETA-DNS-003","engine_rule_id":"NETA-DNS-003","name":"DNS answer churn","category":"dns","severity":"low","enabled":false,"parameters":{"maximum_distinct_answers":12}},
    {"id":"NETA-TLS-001","engine_rule_id":"NETA-TLS-001","name":"Application TLS validation failure","category":"tls","severity":"high","enabled":true,"parameters":{"require_peer_authentication":true,"verification_failure_match":true}},
    {"id":"NETA-TLS-002","engine_rule_id":"NETA-TLS-002","name":"TLS peer identity change","category":"tls","severity":"high","enabled":true,"parameters":{"compare_spki":true,"compare_issuer":true}},
    {"id":"NETA-ROUTE-001","engine_rule_id":"NETA-ROUTE-001","name":"Unexpected route gateway or interface","category":"route","severity":"medium","enabled":false,"parameters":{"allowed_gateways":[],"allowed_interfaces":[]}}
  ]})JSON";
    }
};

} // namespace neta::rules
