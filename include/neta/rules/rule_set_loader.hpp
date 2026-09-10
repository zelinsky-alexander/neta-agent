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
        std::ostringstream buffer; buffer << input.rdbuf();
        return load_text(buffer.str(), path.string());
    }
    static RuleSet load_text(const std::string& text, const std::string& source = "<memory>") {
        try { return parse_root(JsonParser(text).parse()); }
        catch (const std::exception& error) {
            throw std::runtime_error("rule set validation failed for " + source + ": " + error.what());
        }
    }
    static RuleSet built_in() { return load_text(default_document(), "built-in default rules"); }
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
    static std::string canonical_id(std::string id) {
        if (id.rfind("NETA-", 0) == 0) id.erase(0, 5);
        if (id.rfind("CUS-", 0) == 0) id = "CST-" + id.substr(4);
        return id;
    }

    static const std::set<std::string>& rm1_default_ids() {
        static const std::set<std::string> ids{
            "PERF-001","TRUST-001","TRUST-002","PROC-001",
            "PROC-002","PROC-003","PROC-004","PROC-005"};
        return ids;
    }
    static bool is_supported_custom_engine(const std::string& id) {
        static const std::set<std::string> engines{
            "PERF-001","TRUST-001","TRUST-002",
            "PROC-001","PROC-002","PROC-003","PROC-004","PROC-005",
            "BEH-001","NET-001","NET-002","NET-003","NET-004",
            "DNS-001","DNS-002","DNS-003","TLS-001","TLS-002","ROUTE-001"};
        return engines.contains(id);
    }
    static const std::string& require_string(const JsonValue& object, const std::string& key) { return object.at(key).as_string(); }
    static std::uint64_t require_u64(const JsonValue& object, const std::string& key) {
        const double value = object.at(key).as_number();
        if (!std::isfinite(value) || value < 0 || std::floor(value) != value ||
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
    static void ensure_keys(const JsonValue& object, std::initializer_list<const char*> allowed, const std::string& context) {
        std::set<std::string> valid; for (const char* key : allowed) valid.emplace(key);
        for (const auto& [key, unused] : object.as_object()) {
            (void)unused; if (!valid.contains(key)) throw std::runtime_error(context + " contains unsupported field: " + key);
        }
    }
    static void ensure_parameter_keys(const RuleDefinition& definition, std::initializer_list<const char*> allowed) {
        std::set<std::string> valid; for (const char* key : allowed) valid.emplace(key);
        const auto check = [&](const auto& parameters) {
            for (const auto& [key, unused] : parameters) { (void)unused;
                if (!valid.contains(key)) throw std::runtime_error(definition.id + " contains unsupported parameter: " + key);
            }
        };
        check(definition.numeric_parameters); check(definition.boolean_parameters);
        check(definition.string_parameters); check(definition.string_list_parameters);
    }
    static std::vector<std::string> string_array(const JsonValue& value) {
        std::vector<std::string> result;
        for (const auto& item : value.as_array()) {
            const auto& text = item.as_string();
            if (text.empty()) throw std::runtime_error("string-list values may not be empty");
            result.push_back(text);
        }
        return result;
    }
    static RuleExclusion parse_exclusion(const JsonValue& value) {
        ensure_keys(value,{"process_names","executable_paths","process_path_prefixes","parent_process_names","users",
                           "remote_hosts","remote_ips","remote_ports","local_ports","domains","directions"},"rule exclusion");
        RuleExclusion out;
        const auto read = [&](const char* key, std::vector<std::string>& target) {
            if (const auto* item = value.find(key)) target = string_array(*item);
        };
        read("process_names",out.process_names); read("executable_paths",out.executable_paths);
        read("process_path_prefixes",out.process_path_prefixes); read("parent_process_names",out.parent_process_names);
        read("users",out.users); read("remote_hosts",out.remote_hosts); read("remote_ips",out.remote_ips);
        read("remote_ports",out.remote_ports); read("local_ports",out.local_ports); read("domains",out.domains);
        read("directions",out.directions);
        for (const auto& direction : out.directions) {
            const auto normalized = exclusion_normalized(direction);
            if (normalized != "inbound" && normalized != "outbound" && normalized != "unknown")
                throw std::runtime_error("exclude.directions accepts inbound, outbound, or unknown");
        }
        return out;
    }
    static RuleDefinition parse_definition(const JsonValue& value, std::uint64_t schema_version) {
        if (schema_version == 1)
            ensure_keys(value,{"id","name","category","severity","enabled","parameters"},"rule");
        else
            ensure_keys(value,{"id","engine_rule_id","name","category","severity","enabled","parameters","exclude"},"rule");
        RuleDefinition d;
        d.id=canonical_id(require_string(value,"id"));
        d.engine_rule_id=canonical_id(optional_string(value,"engine_rule_id"));
        if (d.engine_rule_id.empty()) d.engine_rule_id=d.id;
        d.name=require_string(value,"name"); d.category=require_string(value,"category");
        d.severity=optional_string(value,"severity"); d.enabled=optional_bool(value,"enabled",true);
        if (d.id.empty()||d.engine_rule_id.empty()||d.name.empty()||d.category.empty())
            throw std::runtime_error("rule id, engine_rule_id, name, and category must be non-empty");
        if (const auto* parameters=value.find("parameters")) {
            for (const auto& [key,p] : parameters->as_object()) {
                if (p.is_number()) d.numeric_parameters.emplace(key,p.as_number());
                else if (p.is_boolean()) d.boolean_parameters.emplace(key,p.as_boolean());
                else if (p.is_string()) d.string_parameters.emplace(key,p.as_string());
                else if (p.is_array()) d.string_list_parameters.emplace(key,string_array(p));
                else throw std::runtime_error("unsupported parameter type for " + key);
            }
        }
        if (schema_version >= 2) if (const auto* exclusion=value.find("exclude")) d.exclude=parse_exclusion(*exclusion);
        return d;
    }
    static void require_category(const RuleDefinition& d,const char* expected) {
        if (d.category!=expected) throw std::runtime_error(d.id + " must use " + expected + " category");
    }
    static std::uint64_t positive_integer(const RuleDefinition& d,const std::string& name) {
        const double value=d.numeric(name);
        if (!std::isfinite(value)||value<=0||std::floor(value)!=value||value>static_cast<double>(std::numeric_limits<std::uint64_t>::max()))
            throw std::runtime_error(d.id + " parameter " + name + " must be a positive integer");
        return static_cast<std::uint64_t>(value);
    }
    static void fraction(const RuleDefinition& d,const std::string& name) {
        const auto value=d.numeric(name); if (!std::isfinite(value)||value<0||value>1)
            throw std::runtime_error(d.id + " parameter " + name + " must be between 0 and 1");
    }
    static void validate_severity(const RuleDefinition& d) {
        if (d.severity!="low"&&d.severity!="medium"&&d.severity!="high")
            throw std::runtime_error(d.id + " severity must be low, medium, or high");
    }
    static void validate_engine(RuleDefinition& d,RuleSet& set) {
        const auto& e=d.engine_rule_id;
        if (e=="PERF-001") {
            require_category(d,"performance"); ensure_parameter_keys(d,{"rtt_ratio","rttvar_ratio","retransmission_threshold","rtt_weight","rttvar_weight","retransmission_weight","degraded_threshold"});
            (void)positive_integer(d,"retransmission_threshold");
            if (d.numeric("rtt_ratio")<=0||d.numeric("rttvar_ratio")<=0||d.numeric("rtt_weight")<0||d.numeric("rttvar_weight")<0||d.numeric("retransmission_weight")<0||d.numeric("degraded_threshold")<=0)
                throw std::runtime_error(d.id + " has invalid performance ratios/weights/threshold");
            if (d.id==e) { set.performance_enabled=d.enabled; set.rtt_ratio=d.numeric("rtt_ratio"); set.rttvar_ratio=d.numeric("rttvar_ratio"); set.retransmission_threshold=positive_integer(d,"retransmission_threshold"); set.rtt_weight=d.numeric("rtt_weight"); set.rttvar_weight=d.numeric("rttvar_weight"); set.retransmission_weight=d.numeric("retransmission_weight"); set.degraded_threshold=d.numeric("degraded_threshold"); }
        } else if (e=="TRUST-001") {
            require_category(d,"trust"); ensure_parameter_keys(d,{"require_chain_valid","require_hostname_valid","compare_spki"});
            (void)d.boolean("require_chain_valid"); (void)d.boolean("require_hostname_valid"); (void)d.boolean("compare_spki");
            if (d.id==e) { set.outbound_tls_identity=d.enabled; set.outbound_require_chain_valid=d.boolean("require_chain_valid"); set.outbound_require_hostname_valid=d.boolean("require_hostname_valid"); set.outbound_compare_spki=d.boolean("compare_spki"); }
        } else if (e=="TRUST-002") {
            require_category(d,"trust"); ensure_parameter_keys(d,{"require_exact_evidence","require_peer_certificate","require_peer_authentication","verification_failure_suspicious","compare_spki","compare_issuer"});
            (void)d.boolean("require_exact_evidence"); (void)d.boolean("require_peer_certificate"); (void)d.boolean("require_peer_authentication"); (void)d.boolean("verification_failure_suspicious"); (void)d.boolean("compare_spki"); (void)d.boolean("compare_issuer");
            if (d.id==e) { set.inbound_authenticated_identity=d.enabled; set.inbound_require_exact_evidence=d.boolean("require_exact_evidence"); set.inbound_require_peer_certificate=d.boolean("require_peer_certificate"); set.inbound_require_peer_authentication=d.boolean("require_peer_authentication"); set.inbound_verification_failure_suspicious=d.boolean("verification_failure_suspicious"); set.inbound_compare_spki=d.boolean("compare_spki"); set.inbound_compare_issuer=d.boolean("compare_issuer"); }
        } else if (e=="PROC-001") { require_category(d,"process"); ensure_parameter_keys(d,{"path_prefixes","path_substrings"}); (void)d.string_list("path_prefixes"); (void)d.string_list("path_substrings"); }
        else if (e=="PROC-002") { require_category(d,"process"); ensure_parameter_keys(d,{"shell_names","expected_parent_names"}); (void)d.string_list("shell_names"); (void)d.string_list("expected_parent_names"); }
        else if (e=="PROC-003") { require_category(d,"process"); ensure_parameter_keys(d,{"expected_parent_names"}); (void)d.string_list("expected_parent_names"); }
        else if (e=="PROC-004") { require_category(d,"process"); ensure_parameter_keys(d,{"child_count","window_ms"}); (void)positive_integer(d,"child_count"); (void)positive_integer(d,"window_ms"); }
        else if (e=="PROC-005") { require_category(d,"process"); ensure_parameter_keys(d,{"child_count","max_lifetime_ms","window_ms"}); (void)positive_integer(d,"child_count"); (void)positive_integer(d,"max_lifetime_ms"); (void)positive_integer(d,"window_ms"); }
        else if (e=="BEH-001") { require_category(d,"behavior"); ensure_parameter_keys(d,{"minimum_connections","window_ms","minimum_interval_ms","maximum_interval_ms","interval_tolerance_ratio","minimum_regular_fraction","recent_connection_limit"}); (void)positive_integer(d,"minimum_connections"); (void)positive_integer(d,"window_ms"); (void)positive_integer(d,"minimum_interval_ms"); (void)positive_integer(d,"maximum_interval_ms"); (void)positive_integer(d,"recent_connection_limit"); fraction(d,"interval_tolerance_ratio"); fraction(d,"minimum_regular_fraction"); }
        else if (e=="NET-001") { require_category(d,"network"); ensure_parameter_keys(d,{"minimum_bytes_received"}); (void)positive_integer(d,"minimum_bytes_received"); }
        else if (e=="NET-002") { require_category(d,"network"); ensure_parameter_keys(d,{"retransmission_threshold"}); (void)positive_integer(d,"retransmission_threshold"); }
        else if (e=="NET-003") { require_category(d,"network"); ensure_parameter_keys(d,{"allowed_ports"}); (void)d.string_list("allowed_ports"); }
        else if (e=="NET-004") { require_category(d,"network"); ensure_parameter_keys(d,{"maximum_prevalence"}); (void)positive_integer(d,"maximum_prevalence"); }
        else if (e=="DNS-001") { require_category(d,"dns"); ensure_parameter_keys(d,{"minimum_failures"}); (void)positive_integer(d,"minimum_failures"); }
        else if (e=="DNS-002") { require_category(d,"dns"); ensure_parameter_keys(d,{"require_remote_ip_match"}); (void)d.boolean("require_remote_ip_match"); }
        else if (e=="DNS-003") { require_category(d,"dns"); ensure_parameter_keys(d,{"maximum_distinct_answers"}); (void)positive_integer(d,"maximum_distinct_answers"); }
        else if (e=="TLS-001") { require_category(d,"tls"); ensure_parameter_keys(d,{"require_peer_authentication","verification_failure_match"}); (void)d.boolean("require_peer_authentication"); (void)d.boolean("verification_failure_match"); }
        else if (e=="TLS-002") { require_category(d,"tls"); ensure_parameter_keys(d,{"compare_spki","compare_issuer"}); (void)d.boolean("compare_spki"); (void)d.boolean("compare_issuer"); }
        else if (e=="ROUTE-001") { require_category(d,"route"); ensure_parameter_keys(d,{"allowed_gateways","allowed_interfaces"}); (void)d.string_list("allowed_gateways"); (void)d.string_list("allowed_interfaces"); }
        else throw std::runtime_error("unsupported engine_rule_id: " + e);
    }
    static RuleSet parse_root(const JsonValue& root) {
        ensure_keys(root,{"schema_version","id","revision","version","rules"},"rule set");
        RuleSet set; set.schema_version=require_u64(root,"schema_version"); set.id=require_string(root,"id"); set.revision=require_u64(root,"revision"); set.version=require_string(root,"version");
        if (set.schema_version!=1&&set.schema_version!=2) throw std::runtime_error("unsupported rule schema version");
        if (set.id.empty()||set.revision==0||set.version.empty()) throw std::runtime_error("rule set id/version must be non-empty and revision must be positive");
        std::set<std::string> ids;
        for (const auto& item : root.at("rules").as_array()) {
            RuleDefinition d=parse_definition(item,set.schema_version);
            if (!ids.insert(d.id).second) throw std::runtime_error("duplicate rule id: " + d.id);
            validate_severity(d);
            if (set.schema_version==1&&d.engine_rule_id!=d.id) throw std::runtime_error("schema v1 does not support a distinct engine_rule_id");
            if (d.id!=d.engine_rule_id&&!is_supported_custom_engine(d.engine_rule_id)) throw std::runtime_error("unsupported custom trusted engine: " + d.engine_rule_id);
            if (d.id!=d.engine_rule_id&&!d.id.starts_with("CST-")) throw std::runtime_error("custom centrally managed rule ids must start with CST-");
            validate_engine(d,set); set.definitions.push_back(std::move(d));
        }
        for (const auto& required : rm1_default_ids()) if (!ids.contains(required)) throw std::runtime_error("rule set is missing required default rule: " + required);
        if (set.schema_version==1&&ids!=rm1_default_ids()) throw std::runtime_error("schema v1 permits only the RM1 default rule catalog");
        return set;
    }

    static const char* rm1_document() { return R"JSON({"schema_version":1,"id":"neta-default","revision":2,"version":"neta-rules/0.3.0","rules":[
{"id":"PERF-001","name":"Network path degradation","category":"performance","severity":"medium","enabled":true,"parameters":{"rtt_ratio":2.0,"rttvar_ratio":2.0,"retransmission_threshold":2,"rtt_weight":0.5,"rttvar_weight":0.2,"retransmission_weight":0.3,"degraded_threshold":0.5}},
{"id":"TRUST-001","name":"Outbound TLS identity","category":"trust","severity":"high","enabled":true,"parameters":{"require_chain_valid":true,"require_hostname_valid":true,"compare_spki":true}},
{"id":"TRUST-002","name":"Inbound authenticated TLS identity","category":"trust","severity":"high","enabled":true,"parameters":{"require_exact_evidence":true,"require_peer_certificate":true,"require_peer_authentication":true,"verification_failure_suspicious":true,"compare_spki":true,"compare_issuer":true}},
{"id":"PROC-001","name":"Execution from transient path","category":"process","severity":"medium","enabled":true,"parameters":{"path_prefixes":["/tmp/","/var/tmp/","/dev/shm/"],"path_substrings":["/appdata/local/temp/","/windows/temp/"]}},
{"id":"PROC-002","name":"Shell from unexpected parent","category":"process","severity":"medium","enabled":true,"parameters":{"shell_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe"],"expected_parent_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe","sshd","sudo","su","login","systemd","init","tmux","screen","gnome-terminal-server","konsole","windowsterminal.exe","wt.exe","conhost.exe","explorer.exe","winlogon.exe"]}},
{"id":"PROC-003","name":"Unexpected elevation","category":"process","severity":"medium","enabled":true,"parameters":{"expected_parent_names":["sudo","su","pkexec","doas","consent.exe"]}},
{"id":"PROC-004","name":"Rapid child process fanout","category":"process","severity":"medium","enabled":true,"parameters":{"child_count":6,"window_ms":10000}},
{"id":"PROC-005","name":"Short-lived process burst","category":"process","severity":"medium","enabled":true,"parameters":{"child_count":6,"max_lifetime_ms":2000,"window_ms":15000}}]})JSON"; }

    static const char* default_document() { return R"JSON({"schema_version":2,"id":"neta-default","revision":5,"version":"neta-rules/0.5.0","rules":[
{"id":"PERF-001","engine_rule_id":"PERF-001","name":"Network path degradation","category":"performance","severity":"medium","enabled":true,"parameters":{"rtt_ratio":2.0,"rttvar_ratio":2.0,"retransmission_threshold":2,"rtt_weight":0.5,"rttvar_weight":0.2,"retransmission_weight":0.3,"degraded_threshold":0.5}},
{"id":"TRUST-001","engine_rule_id":"TRUST-001","name":"Outbound TLS identity","category":"trust","severity":"high","enabled":true,"parameters":{"require_chain_valid":true,"require_hostname_valid":true,"compare_spki":true}},
{"id":"TRUST-002","engine_rule_id":"TRUST-002","name":"Inbound authenticated TLS identity","category":"trust","severity":"high","enabled":true,"parameters":{"require_exact_evidence":true,"require_peer_certificate":true,"require_peer_authentication":true,"verification_failure_suspicious":true,"compare_spki":true,"compare_issuer":true}},
{"id":"PROC-001","engine_rule_id":"PROC-001","name":"Execution from transient path","category":"process","severity":"medium","enabled":true,"parameters":{"path_prefixes":["/tmp/","/var/tmp/","/dev/shm/"],"path_substrings":["/appdata/local/temp/","/windows/temp/"]}},
{"id":"PROC-002","engine_rule_id":"PROC-002","name":"Shell from unexpected parent","category":"process","severity":"medium","enabled":true,"parameters":{"shell_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe"],"expected_parent_names":["sh","bash","dash","zsh","ksh","fish","powershell","powershell.exe","pwsh","pwsh.exe","cmd","cmd.exe","sshd","sudo","su","login","systemd","init","tmux","screen","gnome-terminal-server","konsole","windowsterminal.exe","wt.exe","conhost.exe","explorer.exe","winlogon.exe"]}},
{"id":"PROC-003","engine_rule_id":"PROC-003","name":"Unexpected elevation","category":"process","severity":"medium","enabled":true,"parameters":{"expected_parent_names":["sudo","su","pkexec","doas","consent.exe"]}},
{"id":"PROC-004","engine_rule_id":"PROC-004","name":"Rapid child process fanout","category":"process","severity":"medium","enabled":true,"parameters":{"child_count":6,"window_ms":10000}},
{"id":"PROC-005","engine_rule_id":"PROC-005","name":"Short-lived process burst","category":"process","severity":"medium","enabled":true,"parameters":{"child_count":6,"max_lifetime_ms":2000,"window_ms":15000}},
{"id":"BEH-001","engine_rule_id":"BEH-001","name":"Periodic outbound connection pattern","category":"behavior","severity":"medium","enabled":true,"parameters":{"minimum_connections":8,"window_ms":90000,"minimum_interval_ms":3000,"maximum_interval_ms":15000,"interval_tolerance_ratio":0.2,"minimum_regular_fraction":0.8,"recent_connection_limit":512}},
{"id":"NET-001","engine_rule_id":"NET-001","name":"Large ingress transfer","category":"network","severity":"low","enabled":true,"parameters":{"minimum_bytes_received":268435456}},
{"id":"NET-002","engine_rule_id":"NET-002","name":"TCP retransmission spike","category":"network","severity":"medium","enabled":true,"parameters":{"retransmission_threshold":5}},
{"id":"NET-003","engine_rule_id":"NET-003","name":"Unusual outbound destination port","category":"network","severity":"low","enabled":false,"parameters":{"allowed_ports":["22","25","53","80","110","123","143","443","465","587","853","993","995","3389"]}},
{"id":"NET-004","engine_rule_id":"NET-004","name":"Rare outbound destination","category":"network","severity":"medium","enabled":false,"parameters":{"maximum_prevalence":2}},
{"id":"DNS-001","engine_rule_id":"DNS-001","name":"Repeated DNS resolution failures","category":"dns","severity":"medium","enabled":true,"parameters":{"minimum_failures":3}},
{"id":"DNS-002","engine_rule_id":"DNS-002","name":"DNS answer and connection mismatch","category":"dns","severity":"medium","enabled":true,"parameters":{"require_remote_ip_match":true}},
{"id":"DNS-003","engine_rule_id":"DNS-003","name":"DNS answer churn","category":"dns","severity":"low","enabled":false,"parameters":{"maximum_distinct_answers":12}},
{"id":"TLS-001","engine_rule_id":"TLS-001","name":"Application TLS validation failure","category":"tls","severity":"high","enabled":true,"parameters":{"require_peer_authentication":true,"verification_failure_match":true}},
{"id":"TLS-002","engine_rule_id":"TLS-002","name":"TLS peer identity change","category":"tls","severity":"high","enabled":true,"parameters":{"compare_spki":true,"compare_issuer":true}},
{"id":"ROUTE-001","engine_rule_id":"ROUTE-001","name":"Unexpected route gateway or interface","category":"route","severity":"medium","enabled":false,"parameters":{"allowed_gateways":[],"allowed_interfaces":[]}}]})JSON"; }
};

} // namespace neta::rules
