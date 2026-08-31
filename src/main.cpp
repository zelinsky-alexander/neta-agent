#include "neta/crypto.hpp"
#include "neta/cli/observation_command.hpp"
#include "neta/cli/observation_options.hpp"
#include "neta/history_store.hpp"
#include "neta/platform.hpp"
#include "neta/tls_probe.hpp"
#include "neta/tls_session.hpp"
#include "neta/verdict.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace neta;

std::filesystem::path default_db_path() { return "neta.db"; }

std::uint64_t wall_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::tm local_time(std::time_t timestamp) {
    std::tm result{};
    localtime_r(&timestamp, &result);
    return result;
}

std::string format_capture_time(const std::optional<std::uint64_t>& timestamp_ns,
                                bool include_timezone) {
    if (!timestamp_ns) return include_timezone ? "UNKNOWN" : "-";
    const auto timestamp = static_cast<std::time_t>(*timestamp_ns / 1'000'000'000ULL);
    const auto local = local_time(timestamp);
    std::ostringstream out;
    out << std::put_time(&local, include_timezone ? "%Y-%m-%dT%H:%M:%S%z"
                                                  : "%Y-%m-%d %H:%M:%S");
    auto formatted = out.str();
    if (include_timezone && formatted.size() >= 5) formatted.insert(formatted.size() - 2, ":");
    return formatted;
}

std::string arg_value(int argc, char** argv, const std::string& key,
                      const std::string& fallback = {}) {
    for (int i = 0; i + 1 < argc; ++i) if (argv[i] == key) return argv[i + 1];
    return fallback;
}

bool has_arg(int argc, char** argv, const std::string& key) {
    for (int i = 0; i < argc; ++i) if (argv[i] == key) return true;
    return false;
}

std::uint64_t median(std::vector<std::uint64_t> values) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const auto mid = values.size() / 2;
    return values.size() % 2 ? values[mid] : (values[mid - 1] + values[mid]) / 2;
}

std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c) << std::dec;
                } else out << static_cast<char>(c);
        }
    }
    return out.str();
}

std::string json_string_value(const std::string& text, const std::string& key) {
    const std::string needle = "\"" + key + "\":\"";
    auto pos = text.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    std::string out;
    bool escaped = false;
    for (; pos < text.size(); ++pos) {
        const char c = text[pos];
        if (escaped) { out.push_back(c); escaped = false; }
        else if (c == '\\') escaped = true;
        else if (c == '"') break;
        else out.push_back(c);
    }
    return out;
}

std::uint64_t json_u64_value(const std::string& text, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    auto pos = text.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
    return std::stoull(text.substr(pos));
}

bool json_bool_value(const std::string& text, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    auto pos = text.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
    return text.compare(pos, 4, "true") == 0;
}

std::vector<std::string> evidence_hashes_for_kind(const std::string& text,
                                                   const std::string& kind) {
    std::vector<std::string> hashes;
    const std::string kind_needle = "\"kind\":\"" + kind + "\"";
    std::size_t pos = 0;
    while ((pos = text.find(kind_needle, pos)) != std::string::npos) {
        const auto end = text.find('}', pos);
        if (end == std::string::npos) break;
        const auto hash_key = text.find("\"sha256\":\"", pos);
        if (hash_key != std::string::npos && hash_key < end) {
            const auto value_begin = hash_key + std::string("\"sha256\":\"").size();
            const auto value_end = text.find('"', value_begin);
            if (value_end != std::string::npos && value_end <= end) {
                hashes.push_back(text.substr(value_begin, value_end - value_begin));
            }
        }
        pos = end + 1;
    }
    return hashes;
}

std::string evidence_hash_set_hash(std::vector<std::string> hashes) {
    if (hashes.empty()) return {};
    std::sort(hashes.begin(), hashes.end());
    std::string material;
    for (const auto& hash : hashes) {
        if (!material.empty()) material.push_back('|');
        material += hash;
    }
    return sha256_hex(material);
}

std::string name_resolution_addresses(const NameResolutionEvidence& evidence) {
    std::ostringstream out;
    for (std::size_t i = 0; i < evidence.observation.addresses.size(); ++i) {
        if (i) out << ';';
        out << evidence.observation.addresses[i].address;
    }
    return out.str();
}

void print_usage() {
    std::cout << R"USAGE(neta-agent Milestone 3

Usage:
  neta-agent capabilities
  neta-agent observe --target host:port [--duration 30] [--poll-ms interval] [--db neta.db] [--ca file] [--max-db-mb 200]
  neta-agent observe --outbound|--inbound|--all [--local-port port] [--remote-port port] [--process name] [--exclude-process name] [--duration 30] [--db neta.db]
  neta-agent run [--outbound|--inbound|--all] [filters] [--db neta.db] [--max-db-mb 200]
  neta-agent history [--limit 50] [--db neta.db] [--json]
  neta-agent history show ID [--db neta.db] [--json]
  neta-agent baseline capture --target host:port [--db neta.db] [--ca file]
  neta-agent baseline show --target host:port [--db neta.db]
  neta-agent evidence ID [--db neta.db]
  neta-agent explain ID [--db neta.db]
  neta-agent export ID [--db neta.db]
  neta-agent replay FILE
  neta-agent storage status [--db neta.db] [--max-db-mb 200]
  neta-agent storage prune [--db neta.db] [--max-db-mb 200]
)USAGE";
}

void cmd_capabilities() {
    const auto env = platform::host_environment();
    const auto capabilities = platform::capabilities();
    std::cout << "Platform: Linux " << env.kernel_release << (env.is_wsl ? " (WSL2/WSL)" : "") << "\n\n"
              << "Connection discovery       " << (capabilities.connection_discovery ? "YES" : "NO") << "\n"
              << "Process attribution        " << (capabilities.process_attribution ? "YES" : "NO") << "\n"
              << "TCP RTT                    " << (capabilities.tcp_rtt ? "YES" : "NO") << "\n"
              << "TCP RTT variance           " << (capabilities.tcp_rtt_variance ? "YES" : "NO") << "\n"
              << "TCP retransmissions        " << (capabilities.tcp_retransmissions ? "YES" : "NO") << "\n"
              << "TCP cwnd                   " << (capabilities.tcp_cwnd ? "YES" : "NO") << "\n"
              << "Route observation          " << (capabilities.route_observation ? "YES" : "NO") << "\n"
              << "eBPF lifecycle built in    " << (capabilities.ebpf_built_in ? "YES" : "NO") << "\n"
              << "BTF/CO-RE runtime          " << (capabilities.btf_core_runtime ? "YES" : "NO") << "\n"
              << "eBPF lifecycle             " << (capabilities.connection_lifecycle_events ? "YES" : "NO") << "\n"
              << "TCP connect events         " << (capabilities.ebpf_connect_events ? "YES" : "NO") << "\n"
              << "TCP accept events          " << (capabilities.ebpf_accept_events ? "YES" : "NO") << "\n"
              << "TCP close events           " << (capabilities.ebpf_close_events ? "YES" : "NO") << "\n"
              << "Exact lifecycle direction " << (capabilities.exact_lifecycle_direction ? "YES" : "NO") << "\n"
              << "Lifecycle loss counter    " << (capabilities.lifecycle_drop_counter ? "YES" : "NO") << "\n"
              << "Lifecycle dropped events  " << (capabilities.lifecycle_dropped_events
                  ? std::to_string(*capabilities.lifecycle_dropped_events) : "UNAVAILABLE") << "\n"
              << "Application resolver API  " << (capabilities.application_name_resolution_events ? "YES" : "NO") << "\n"
              << "Resolver event source     " << (capabilities.name_resolution_source.empty()
                  ? "UNAVAILABLE" : capabilities.name_resolution_source) << "\n"
              << "Resolver loss counter     " << (capabilities.name_resolution_drop_counter ? "YES" : "NO") << "\n"
              << "Resolver dropped events   " << (capabilities.name_resolution_dropped_events
                  ? std::to_string(*capabilities.name_resolution_dropped_events) : "UNAVAILABLE") << "\n"
              << "Application TLS sessions  " << (capabilities.application_tls_session_events ? "YES" : "NO") << "\n"
              << "TLS session source        " << (capabilities.tls_session_source.empty()
                  ? "UNAVAILABLE" : capabilities.tls_session_source) << "\n"
              << "TLS context endpoint      " << (capabilities.tls_session_endpoint.empty()
                  ? "UNAVAILABLE" : capabilities.tls_session_endpoint) << "\n"
              << "TLS sender credentials    " << (capabilities.tls_session_sender_credentials_verified ? "VERIFIED" : "UNAVAILABLE") << "\n"
              << "TLS dropped events        " << (capabilities.tls_session_dropped_events
                  ? std::to_string(*capabilities.tls_session_dropped_events) : "UNAVAILABLE") << "\n"
              << "TLS rejected events       " << capabilities.tls_session_rejected_events << "\n"
              << "Exact TLS identity         " << (capabilities.exact_tls_observation
                  ? "YES (instrumented OpenSSL sessions only)"
                  : "NO (active probe remains SUPPORTING)") << "\n"
              << "Exact DNS transaction      " << (capabilities.exact_dns_observation ? "YES" : "NO (resolver API event is not a DNS packet claim)") << "\n";
    if (!capabilities.connection_lifecycle_events) {
        const bool outbound_lifecycle = capabilities.ebpf_connect_events && capabilities.ebpf_close_events;
        std::cout << "Lifecycle mode             " << (outbound_lifecycle ? "OUTBOUND eBPF (partial)" : "POLLING") << "\n"
                  << "Lifecycle unavailable      " << capabilities.lifecycle_unavailable_reason << "\n";
    }
    if (!capabilities.application_name_resolution_events) {
        std::cout << "Resolver unavailable       " << capabilities.name_resolution_unavailable_reason << "\n";
    }
    if (!capabilities.application_tls_session_events) {
        std::cout << "TLS session unavailable    " << capabilities.tls_session_unavailable_reason << "\n";
    }
}

void cmd_history(int argc, char** argv) {
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));
    const auto limit = static_cast<std::size_t>(std::stoull(arg_value(argc, argv, "--limit", "50")));
    if (argc >= 3 && std::string(argv[2]) == "show") {
        if (argc < 4) throw std::runtime_error("history show requires ID");
        auto connection = store.connection(std::stoll(argv[3]));
        if (!connection) throw std::runtime_error("connection not found");
        if (has_arg(argc, argv, "--json")) {
            std::cout << "{\"id\":" << connection->id << ",\"process\":\"" << json_escape(connection->process.comm)
                      << "\",\"local\":\"" << json_escape(connection->local_ip) << ':' << connection->local_port
                      << "\",\"remote\":\"" << json_escape(connection->remote_ip) << ':' << connection->remote_port
                      << "\",\"target\":\"" << json_escape(connection->target_host) << "\",\"captured_at\":\""
                      << format_capture_time(connection->captured_at_ns, true) << "\",\"direction\":\""
                      << to_string(connection->direction) << "\",\"performance\":\"" << to_string(connection->performance)
                      << "\",\"trust\":\"" << to_string(connection->trust) << "\"}\n";
        } else {
            std::cout << "CONN-" << connection->id << "  " << connection->process.comm << '[' << connection->process.pid << "]  "
                      << connection->local_ip << ':' << connection->local_port << " -> " << connection->remote_ip << ':'
                      << connection->remote_port << "  " << to_string(connection->direction) << "  "
                      << to_string(connection->performance) << " / " << to_string(connection->trust)
                      << "\nCaptured: " << format_capture_time(connection->captured_at_ns, false) << "\n";
        }
        return;
    }
    const auto rows = store.recent_connections(limit);
    if (has_arg(argc, argv, "--json")) {
        std::cout << '[';
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (i) std::cout << ',';
            const auto& connection = rows[i];
            std::cout << "{\"id\":" << connection.id << ",\"process\":\"" << json_escape(connection.process.comm)
                      << "\",\"remote\":\"" << json_escape(connection.remote_ip) << ':' << connection.remote_port
                      << "\",\"captured_at\":\"" << format_capture_time(connection.captured_at_ns, true)
                      << "\",\"direction\":\"" << to_string(connection.direction) << "\",\"performance\":\""
                      << to_string(connection.performance) << "\",\"trust\":\"" << to_string(connection.trust) << "\"}";
        }
        std::cout << "]\n";
    } else {
        std::cout << "ID       PROCESS          CAPTURED             DIRECTION  REMOTE                         PERF                  TRUST\n";
        for (const auto& connection : rows) {
            std::cout << "CONN-" << std::left << std::setw(6) << connection.id << std::setw(17) << connection.process.comm
                      << std::setw(21) << format_capture_time(connection.captured_at_ns, false) << std::setw(11)
                      << to_string(connection.direction) << std::setw(31)
                      << (connection.remote_ip + ':' + std::to_string(connection.remote_port)) << std::setw(22)
                      << to_string(connection.performance) << to_string(connection.trust) << "\n";
        }
    }
}

void cmd_baseline(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("baseline requires capture or show");
    const auto target = cli::resolve_observation_target(arg_value(argc, argv, "--target"));
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));
    if (std::string(argv[2]) == "show") {
        auto baseline = store.baseline_for(target.host, target.port);
        if (!baseline) throw std::runtime_error("baseline not found");
        std::cout << "Target: " << baseline->target_host << ':' << baseline->target_port
                  << "\nRTT median: " << static_cast<double>(baseline->rtt_median_us) / 1000.0
                  << " ms\nRTT var median: " << static_cast<double>(baseline->rttvar_median_us) / 1000.0
                  << " ms\nSamples: " << baseline->sample_count << "\nAccepted SPKI: " << baseline->accepted_spki_sha256
                  << "\nHash: " << baseline->sha256 << "\n";
        return;
    }
    if (std::string(argv[2]) != "capture") throw std::runtime_error("unknown baseline action");
    const auto samples = store.recent_samples_for_target(target.host, target.port, 200);
    if (samples.size() < 5) throw std::runtime_error("need at least 5 persisted target samples; run observe first (20+ recommended)");
    std::vector<std::uint64_t> rtts;
    std::vector<std::uint64_t> rttvars;
    for (const auto& sample : samples) if (sample.rtt_us) {
        rtts.push_back(sample.rtt_us);
        if (sample.rtt_variance_us) rttvars.push_back(sample.rtt_variance_us);
    }
    if (rtts.empty()) throw std::runtime_error("samples contain no RTT evidence");
    const auto tls = TlsProbe{}.probe(target.host, target.port, arg_value(argc, argv, "--ca"));
    if (!tls.chain_valid || !tls.hostname_valid) throw std::runtime_error("refusing to accept baseline from invalid TLS identity");
    store.add_tls(tls);
    Baseline baseline;
    baseline.target_host = target.host;
    baseline.target_port = target.port;
    baseline.rtt_median_us = median(rtts);
    baseline.rttvar_median_us = median(rttvars);
    baseline.accepted_spki_sha256 = tls.spki_sha256;
    baseline.accepted_issuer = tls.issuer;
    baseline.sample_count = samples.size();
    baseline.created_ns = wall_now_ns();
    baseline.sha256 = sha256_hex(baseline.target_host + ':' + std::to_string(baseline.target_port) + '|'
                                 + std::to_string(baseline.rtt_median_us) + '|' + std::to_string(baseline.rttvar_median_us)
                                 + '|' + baseline.accepted_spki_sha256 + '|' + std::to_string(baseline.sample_count));
    store.save_baseline(baseline);
    std::cout << "Captured baseline for " << target.host << ':' << target.port << " from " << samples.size()
              << " samples. Hash " << baseline.sha256 << "\n";
}

void cmd_evidence(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("evidence requires connection ID");
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));
    const auto id = std::stoll(argv[2]);
    const auto data = store.export_data(id);
    const auto names = store.name_resolution_evidence_for_connection(id);
    const auto tls_sessions = store.tls_session_evidence_for_connection(id);
    std::cout << "Connection CONN-" << id << "\n  Process: "
              << (data.connection.process.comm.empty() ? "<unattributed>" : data.connection.process.comm) << '['
              << data.connection.process.pid << "]\n  Path: " << data.connection.local_ip << ':' << data.connection.local_port
              << " -> " << data.connection.remote_ip << ':' << data.connection.remote_port << "\n  Direction: "
              << to_string(data.connection.direction) << "\n  Network namespace: "
              << (data.connection.network_namespace_inode ? std::to_string(*data.connection.network_namespace_inode) : "<unavailable>")
              << "\n  Lifecycle: " << data.connection.lifecycle_state << "\n\n";
    std::cout << "Lifecycle observations (eBPF observation, not verdict): " << data.lifecycle_events.size() << "\n";
    for (const auto& event : data.lifecycle_events) {
        std::cout << "  " << to_string(event.type) << " ns=" << event.timestamp_ns << " provenance=" << to_string(event.provenance)
                  << " agent_tgid=" << (event.process.agent_visible.tgid ? std::to_string(*event.process.agent_visible.tgid) : "<unavailable>")
                  << " kernel_tgid=" << (event.process.kernel.tgid ? std::to_string(*event.process.kernel.tgid) : "<unavailable>")
                  << " cookie=" << (event.socket_cookie ? std::to_string(*event.socket_cookie) : "<unavailable>") << '\n';
    }
    std::cout << "\nName-resolution evidence: " << names.size() << "\n";
    for (const auto& evidence : names) {
        std::cout << "  Query: " << evidence.observation.query_name << " source=" << evidence.observation.source
                  << " result=" << (evidence.observation.result_code ? std::to_string(*evidence.observation.result_code) : "<unavailable>")
                  << " observation=" << to_string(evidence.observation.fidelity)
                  << " correlation=" << to_string(evidence.correlation_fidelity)
                  << " relation=" << to_string(evidence.relation) << " addresses=" << name_resolution_addresses(evidence) << '\n';
    }
    std::cout << "\nApplication TLS session evidence: " << tls_sessions.size() << "\n";
    for (const auto& evidence : tls_sessions) {
        const auto& tls = evidence.observation;
        std::cout << "  Role: " << to_string(tls.local_role)
                  << " relation=" << to_string(evidence.relation)
                  << " observation=" << to_string(tls.fidelity)
                  << " correlation=" << to_string(evidence.correlation_fidelity)
                  << " source=" << tls.source << '\n'
                  << "    Version: " << tls.tls_version
                  << " cipher=" << tls.cipher
                  << " ALPN=" << (tls.alpn.empty() ? "<none>" : tls.alpn)
                  << " SNI=" << (tls.sni.empty() ? "<none>" : tls.sni) << '\n'
                  << "    Peer cert: " << (tls.peer_certificate_present ? "yes" : "no")
                  << " authenticated=" << (tls.peer_authenticated ? "yes" : "no")
                  << " verify=" << (tls.verify_result ? std::to_string(*tls.verify_result) : "<unavailable>") << '\n'
                  << "    Expected name: " << tls.expected_peer_name.value_or("<unavailable>")
                  << " matched name: " << tls.matched_peer_name.value_or("<unavailable>") << '\n'
                  << "    Leaf SHA-256: " << (tls.leaf_sha256.empty() ? "<unavailable>" : tls.leaf_sha256)
                  << "\n    SPKI SHA-256: " << (tls.spki_sha256.empty() ? "<unavailable>" : tls.spki_sha256) << '\n';
    }
    std::cout << "\nTCP samples (EXACT): " << data.samples.size() << "\n";
    if (data.route) {
        const auto& route = *data.route;
        std::cout << "\nRoute (STRONGLY_CORRELATED)\n  Relation:    " << to_string(route.relation)
                  << "\n  Destination: " << route.destination << "\n  Source:      " << route.source
                  << "\n  Gateway:     " << (route.gateway.empty() ? "<direct>" : route.gateway)
                  << "\n  Interface:   " << route.interface_name << " (index " << route.interface_index << ")\n";
    }
    if (data.tls) {
        const auto& tls = *data.tls;
        std::cout << "\nTLS active probe (SUPPORTING)\n"
                  << "  Relation:       separate connection\n"
                  << "  Target:         " << tls.target_host << ':' << tls.target_port << '\n'
                  << "  Version:        " << tls.tls_version << '\n'
                  << "  Cipher:         " << tls.cipher << '\n'
                  << "  ALPN:           " << (tls.alpn.empty() ? "<none>" : tls.alpn) << '\n'
                  << "  Chain valid:    " << (tls.chain_valid ? "yes" : "no") << '\n'
                  << "  Hostname valid: " << (tls.hostname_valid ? "yes" : "no") << '\n'
                  << "  Leaf SHA-256:   " << tls.leaf_sha256 << '\n'
                  << "  SPKI SHA-256:   " << tls.spki_sha256 << '\n'
                  << "  Subject:        " << tls.subject << '\n'
                  << "  Issuer:         " << tls.issuer << '\n'
                  << "  Not before:     " << tls.not_before << '\n'
                  << "  Not after:      " << tls.not_after << '\n'
                  << "  Observed ns:    " << tls.observed_ns << '\n'
                  << "  SHA-256:        " << tls.sha256 << '\n';
    }
}

void cmd_explain(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("explain requires connection ID");
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));
    const auto id = std::stoll(argv[2]);
    auto data = store.export_data(id);
    if (!data.verdict) throw std::runtime_error("no verdict for connection (capture a baseline, then observe again)");
    const auto metrics = aggregate_metrics(data.samples);
    const auto tls_sessions = store.tls_session_evidence_for_connection(id);
    const auto exact_sessions = std::count_if(tls_sessions.begin(), tls_sessions.end(), [](const auto& evidence) {
        return evidence.correlation_fidelity == EvidenceFidelity::Exact;
    });
    std::cout << "Connection Assurance\n--------------------\nCONN-" << id << "  " << data.connection.process.comm << '['
              << data.connection.process.pid << "]\n" << data.connection.local_ip << ':' << data.connection.local_port << " -> "
              << data.connection.remote_ip << ':' << data.connection.remote_port << "\nDirection: " << to_string(data.connection.direction)
              << "\n\nPerformance: " << to_string(data.verdict->performance) << "\nHypothesis: "
              << (data.verdict->performance_hypothesis.empty() ? "none" : data.verdict->performance_hypothesis)
              << "\nObserved RTT: " << static_cast<double>(metrics.observed_rtt_us) / 1000.0 << " ms\nObserved RTT var: "
              << static_cast<double>(metrics.observed_rttvar_us) / 1000.0 << " ms\nRetransmission delta: "
              << metrics.retransmission_delta << "\nRule confidence: " << data.verdict->rule_confidence << "\n\nTrust: "
              << to_string(data.verdict->trust) << "\nHypothesis: "
              << (data.verdict->trust_hypothesis.empty() ? "none" : data.verdict->trust_hypothesis)
              << "\nActual application TLS sessions: " << tls_sessions.size()
              << " (EXACT links: " << exact_sessions << ')'
              << "\nCurrent Trust rule input: SUPPORTING independent active probe"
              << "\nMS3.2 exact-session evidence is retained separately and does not silently change the versioned Trust rule"
              << "\n\nCausality: performance/trust causal relation NOT ESTABLISHED"
              << "\nRule set: " << data.verdict->rule_set_version << "\nRule hash: " << data.verdict->rule_set_hash
              << "\nInput hash: " << data.verdict->input_hash << "\n";
}

void cmd_export(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("export requires connection ID");
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));
    const auto id = std::stoll(argv[2]);
    const auto data = store.export_data(id);
    const auto names = store.name_resolution_evidence_for_connection(id);
    const auto tls_sessions = store.tls_session_evidence_for_connection(id);
    if (!data.baseline || !data.verdict) throw std::runtime_error("export requires baseline and verdict");
    const auto metrics = aggregate_metrics(data.samples);
    const auto name_hash = name_resolution_evidence_set_hash(names);
    const auto tls_session_hash = tls_session_evidence_set_hash(tls_sessions);
    std::cout << "{\n  \"schema_version\":4,\n  \"connection_id\":" << id
              << ",\n  \"direction\":\"" << to_string(data.connection.direction) << "\""
              << ",\n  \"target_host\":\"" << json_escape(data.connection.target_host) << "\",\n  \"target_port\":" << data.connection.remote_port
              << ",\n  \"performance\":\"" << to_string(data.verdict->performance) << "\",\n  \"trust\":\"" << to_string(data.verdict->trust)
              << "\",\n  \"rule_set_version\":\"" << data.verdict->rule_set_version << "\",\n  \"rule_set_hash\":\""
              << data.verdict->rule_set_hash << "\",\n  \"input_hash\":\"" << data.verdict->input_hash << "\",\n  \"baseline_hash\":\""
              << data.baseline->sha256 << "\",\n  \"baseline_rtt_median_us\":" << data.baseline->rtt_median_us
              << ",\n  \"baseline_rttvar_median_us\":" << data.baseline->rttvar_median_us
              << ",\n  \"baseline_sample_count\":" << data.baseline->sample_count << ",\n  \"baseline_spki\":\""
              << data.baseline->accepted_spki_sha256 << "\",\n  \"observed_rtt_us\":" << metrics.observed_rtt_us
              << ",\n  \"observed_rttvar_us\":" << metrics.observed_rttvar_us
              << ",\n  \"retransmission_delta\":" << metrics.retransmission_delta
              << ",\n  \"tls_present\":" << (data.tls ? "true" : "false")
              << ",\n  \"tls_spki\":\"" << (data.tls ? data.tls->spki_sha256 : "")
              << "\",\n  \"tls_chain_valid\":" << (data.tls && data.tls->chain_valid ? "true" : "false")
              << ",\n  \"tls_hostname_valid\":" << (data.tls && data.tls->hostname_valid ? "true" : "false")
              << ",\n  \"tls_hash\":\"" << (data.tls ? data.tls->sha256 : "")
              << "\",\n  \"name_resolution_count\":" << names.size()
              << ",\n  \"name_resolution_hash\":\"" << name_hash
              << "\",\n  \"tls_session_count\":" << tls_sessions.size()
              << ",\n  \"tls_session_hash\":\"" << tls_session_hash << "\",\n  \"evidence\":[\n";
    bool first = true;
    for (const auto& sample : data.samples) {
        const auto hash = sha256_hex(std::to_string(sample.observed_ns) + '|' + std::to_string(sample.state) + '|'
                                     + std::to_string(sample.rtt_us) + '|' + std::to_string(sample.rtt_variance_us) + '|'
                                     + std::to_string(sample.total_retrans) + '|' + std::to_string(sample.lost) + '|'
                                     + std::to_string(sample.unacked) + '|' + std::to_string(sample.snd_cwnd) + '|'
                                     + std::to_string(sample.snd_ssthresh) + '|' + std::to_string(sample.snd_mss) + '|'
                                     + std::to_string(sample.rcv_mss) + '|' + std::to_string(sample.send_queue_bytes) + '|'
                                     + std::to_string(sample.recv_queue_bytes));
        if (!first) std::cout << ",\n";
        first = false;
        std::cout << "    {\"kind\":\"TCP_SNAPSHOT\",\"fidelity\":\"EXACT\",\"sha256\":\"" << hash << "\"}";
    }
    for (const auto& evidence : names) {
        if (!first) std::cout << ",\n";
        first = false;
        std::cout << "    {\"kind\":\"NAME_RESOLUTION\",\"fidelity\":\""
                  << to_string(evidence.correlation_fidelity) << "\",\"observation_fidelity\":\""
                  << to_string(evidence.observation.fidelity) << "\",\"relation\":\"" << to_string(evidence.relation)
                  << "\",\"mechanism\":\"" << to_string(evidence.observation.mechanism) << "\",\"query\":\""
                  << json_escape(evidence.observation.query_name) << "\",\"canonical\":\""
                  << json_escape(evidence.observation.canonical_name.value_or("")) << "\",\"source\":\""
                  << json_escape(evidence.observation.source) << "\",\"addresses\":\""
                  << json_escape(name_resolution_addresses(evidence)) << "\",\"sha256\":\""
                  << name_resolution_evidence_hash(evidence) << "\"}";
    }
    for (const auto& evidence : tls_sessions) {
        if (!first) std::cout << ",\n";
        first = false;
        const auto& tls = evidence.observation;
        std::cout << "    {\"kind\":\"TLS_SESSION\",\"fidelity\":\""
                  << to_string(evidence.correlation_fidelity) << "\",\"observation_fidelity\":\""
                  << to_string(tls.fidelity) << "\",\"role\":\"" << to_string(tls.local_role)
                  << "\",\"relation\":\"" << to_string(evidence.relation)
                  << "\",\"source\":\"" << json_escape(tls.source)
                  << "\",\"tls_version\":\"" << json_escape(tls.tls_version)
                  << "\",\"cipher\":\"" << json_escape(tls.cipher)
                  << "\",\"alpn\":\"" << json_escape(tls.alpn)
                  << "\",\"sni\":\"" << json_escape(tls.sni)
                  << "\",\"leaf_sha256\":\"" << tls.leaf_sha256
                  << "\",\"spki_sha256\":\"" << tls.spki_sha256
                  << "\",\"peer_authenticated\":" << (tls.peer_authenticated ? "true" : "false")
                  << ",\"sha256\":\"" << tls_session_evidence_hash(evidence) << "\"}";
    }
    std::cout << "\n  ]\n}\n";
}

void cmd_replay(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("replay requires bundle file");
    std::ifstream in(argv[2]);
    if (!in) throw std::runtime_error("cannot open bundle");
    const std::string text((std::istreambuf_iterator<char>(in)), {});
    const auto schema_version = json_u64_value(text, "schema_version");
    if (schema_version > 4) throw std::runtime_error("unsupported export schema version");
    Baseline baseline;
    baseline.target_host = json_string_value(text, "target_host");
    baseline.target_port = static_cast<std::uint16_t>(json_u64_value(text, "target_port"));
    baseline.rtt_median_us = json_u64_value(text, "baseline_rtt_median_us");
    baseline.rttvar_median_us = json_u64_value(text, "baseline_rttvar_median_us");
    baseline.sample_count = json_u64_value(text, "baseline_sample_count");
    baseline.accepted_spki_sha256 = json_string_value(text, "baseline_spki");
    baseline.sha256 = json_string_value(text, "baseline_hash");
    AggregateMetrics metrics;
    metrics.observed_rtt_us = json_u64_value(text, "observed_rtt_us");
    metrics.observed_rttvar_us = json_u64_value(text, "observed_rttvar_us");
    metrics.retransmission_delta = json_u64_value(text, "retransmission_delta");
    std::optional<TlsObservation> tls;
    if (json_bool_value(text, "tls_present")) {
        TlsObservation observation;
        observation.spki_sha256 = json_string_value(text, "tls_spki");
        observation.chain_valid = json_bool_value(text, "tls_chain_valid");
        observation.hostname_valid = json_bool_value(text, "tls_hostname_valid");
        observation.sha256 = json_string_value(text, "tls_hash");
        tls = observation;
    }
    const auto replay = evaluate(baseline, metrics, tls);
    const auto original_performance = json_string_value(text, "performance");
    const auto original_trust = json_string_value(text, "trust");
    const auto original_rule_hash = json_string_value(text, "rule_set_hash");
    const auto original_input_hash = json_string_value(text, "input_hash");
    const auto direction = connection_direction_from_string(json_string_value(text, "direction"));
    std::string name_result = "NOT PRESENT (schema <3)";
    if (schema_version >= 3) {
        const auto expected_count = json_u64_value(text, "name_resolution_count");
        const auto expected_hash = json_string_value(text, "name_resolution_hash");
        const auto hashes = evidence_hashes_for_kind(text, "NAME_RESOLUTION");
        name_result = hashes.size() == expected_count && evidence_hash_set_hash(hashes) == expected_hash
            ? "MATCH" : "MISMATCH";
    }
    std::string tls_session_result = "NOT PRESENT (schema <4)";
    if (schema_version >= 4) {
        const auto expected_count = json_u64_value(text, "tls_session_count");
        const auto expected_hash = json_string_value(text, "tls_session_hash");
        const auto hashes = evidence_hashes_for_kind(text, "TLS_SESSION");
        tls_session_result = hashes.size() == expected_count && evidence_hash_set_hash(hashes) == expected_hash
            ? "MATCH" : "MISMATCH";
    }
    std::cout << "Connection direction:       " << to_string(direction)
              << "\nOriginal Performance/Trust: " << original_performance << " / " << original_trust
              << "\nReplay Performance/Trust:   " << to_string(replay.performance) << " / " << to_string(replay.trust)
              << "\nEvidence input hash:        " << (replay.input_hash == original_input_hash ? "MATCH" : "MISMATCH")
              << "\nName-resolution evidence:   " << name_result
              << "\nTLS application sessions:    " << tls_session_result
              << "\nRule set:                   " << (replay.rule_set_hash == original_rule_hash ? "MATCH" : "MISMATCH")
              << "\nVerdict:                    " << ((to_string(replay.performance) == original_performance &&
                   to_string(replay.trust) == original_trust) ? "MATCH" : "MISMATCH") << "\n";
}

void cmd_storage(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("storage requires status or prune");
    const auto db = arg_value(argc, argv, "--db", default_db_path().string());
    const auto max_bytes = std::stoull(arg_value(argc, argv, "--max-db-mb", "200")) * 1024ULL * 1024ULL;
    HistoryStore store(db);
    if (std::string(argv[2]) == "prune") store.prune_to_budget(max_bytes);
    const auto status = store.status(max_bytes);
    std::cout << "Database: " << status.path << "\nSize: " << std::fixed << std::setprecision(2)
              << static_cast<double>(status.bytes) / (1024.0 * 1024.0) << " MB\nConfigured cap: "
              << static_cast<double>(status.max_bytes) / (1024.0 * 1024.0) << " MB\nConnections: "
              << status.connection_count << "\nTransport samples: " << status.sample_count << "\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) { print_usage(); return 1; }
        const std::string command = argv[1];
        if (command == "capabilities") cmd_capabilities();
        else if (command == "observe") cli::run_observation_command(argc, argv, false);
        else if (command == "run") cli::run_observation_command(argc, argv, true);
        else if (command == "history") cmd_history(argc, argv);
        else if (command == "baseline") cmd_baseline(argc, argv);
        else if (command == "evidence") cmd_evidence(argc, argv);
        else if (command == "explain") cmd_explain(argc, argv);
        else if (command == "export") cmd_export(argc, argv);
        else if (command == "replay") cmd_replay(argc, argv);
        else if (command == "storage") cmd_storage(argc, argv);
        else { print_usage(); return 1; }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "neta-agent: " << error.what() << "\n";
        return 2;
    }
}
