#include "neta/crypto.hpp"
#include "neta/history_store.hpp"
#include "neta/platform.hpp"
#include "neta/tls_probe.hpp"
#include "neta/verdict.hpp"

#include <arpa/inet.h>
#include <netdb.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <csignal>

namespace {

using namespace neta;

volatile std::sig_atomic_t g_stop_requested = 0;
void handle_stop_signal(int) { g_stop_requested = 1; }

struct Target {
    std::string host;
    std::uint16_t port{443};
    std::set<std::string> ips;
};

struct Tracked {
    std::int64_t db_id;
    TcpSnapshot last_seen;
    TcpSnapshot last_persisted;
    std::uint64_t last_persist_ns;
    bool present;
};

void finalize_observe_cmd(const std::unordered_map<std::string, Tracked>& tracked,
                        HistoryStore& store,
                        const std::optional<Baseline>& baseline,
                        const std::optional<TlsObservation>& tls,
                        std::optional<std::int64_t> tls_id);

std::filesystem::path default_db_path() { return "neta.db"; }

std::uint64_t wall_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string arg_value(int argc, char** argv, const std::string& key,
                      const std::string& fallback = {}) {
    for (int i = 0; i + 1 < argc; ++i) {
        if (argv[i] == key) return argv[i + 1];
    }
    return fallback;
}

bool has_arg(int argc, char** argv, const std::string& key) {
    for (int i = 0; i < argc; ++i) {
        if (argv[i] == key) return true;
    }
    return false;
}

Target parse_target(const std::string& value) {
    if (value.empty()) throw std::runtime_error("--target host:port is required");
    Target target;
    const auto pos = value.rfind(':');
    if (pos == std::string::npos) {
        target.host = value;
        target.port = 443;
    } else {
        target.host = value.substr(0, pos);
        target.port = static_cast<std::uint16_t>(std::stoul(value.substr(pos + 1)));
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    const auto service = std::to_string(target.port);
    const int rc = getaddrinfo(target.host.c_str(), service.c_str(), &hints, &result);
    if (rc != 0) {
        throw std::runtime_error("target resolution failed: " + std::string(gai_strerror(rc)));
    }

    for (auto* ai = result; ai; ai = ai->ai_next) {
        char buffer[INET6_ADDRSTRLEN]{};
        const void* address = nullptr;
        if (ai->ai_family == AF_INET) {
            address = &reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            address = &reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr;
        }
        if (address && inet_ntop(ai->ai_family, address, buffer, sizeof(buffer))) {
            target.ips.insert(buffer);
        }
    }
    freeaddrinfo(result);
    return target;
}

std::string key_for(const SocketObservation& socket) {
    if (socket.socket_cookie != 0 && socket.socket_cookie != 0xFFFFFFFFFFFFFFFFULL) {
        return "c:" + std::to_string(socket.socket_cookie);
    }
    return "i:" + std::to_string(socket.socket_inode) + "|" + socket.local_ip + ":" +
           std::to_string(socket.local_port) + "->" + socket.remote_ip + ":" +
           std::to_string(socket.remote_port);
}

bool meaningful_change(const TcpSnapshot& previous, const TcpSnapshot& current,
                       std::uint64_t last_persist_ns) {
    if (current.total_retrans != previous.total_retrans || current.lost != previous.lost) return true;
    if (current.state != previous.state) return true;

    const auto material = [](std::uint32_t a, std::uint32_t b, double ratio,
                             std::uint32_t floor) {
        const auto diff = a > b ? a - b : b - a;
        return diff >= floor && (a == 0 || static_cast<double>(diff) / static_cast<double>(a) >= ratio);
    };
    if (material(previous.rtt_us, current.rtt_us, 0.25, 2000)) return true;
    if (material(previous.rtt_variance_us, current.rtt_variance_us, 0.50, 2000)) return true;
    return current.observed_ns - last_persist_ns >= 1'000'000'000ULL;
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
                } else {
                    out << static_cast<char>(c);
                }
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
        if (escaped) {
            out.push_back(c);
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"') {
            break;
        } else {
            out.push_back(c);
        }
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

void print_usage() {
    std::cout << R"USAGE(neta-agent POC1

Usage:
  neta-agent capabilities
  neta-agent observe --target host:port [--duration 30] [--poll-ms 100] [--db neta.db] [--ca file] [--max-db-mb 200]
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
              << "Connection lifecycle       " << (capabilities.connection_lifecycle_events ? "YES" : "NO (POC polling)") << "\n"
              << "Exact TLS identity         " << (capabilities.exact_tls_observation ? "YES" : "NO (active probe is SUPPORTING)") << "\n"
              << "Exact DNS attribution      " << (capabilities.exact_dns_observation ? "YES" : "NO") << "\n";
}

void cmd_observe(int argc, char** argv) {
    g_stop_requested = 0;
    const auto previous_sigint = std::signal(SIGINT, handle_stop_signal);
    const auto previous_sigterm = std::signal(SIGTERM, handle_stop_signal);
    const auto db = arg_value(argc, argv, "--db", default_db_path().string());
    const auto target = parse_target(arg_value(argc, argv, "--target"));
    const auto ca = arg_value(argc, argv, "--ca");
    const int duration = std::stoi(arg_value(argc, argv, "--duration", "30"));
    const int poll_ms = std::stoi(arg_value(argc, argv, "--poll-ms", "100"));
    const auto max_db_mb = std::stoull(arg_value(argc, argv, "--max-db-mb", "200"));

    HistoryStore store(db);
    store.prune_to_budget(max_db_mb * 1024ULL * 1024ULL);
    auto observer = platform::make_connection_observer();
    auto resolver = platform::make_process_resolver();
    auto route = platform::make_route_observer();

    std::optional<TlsObservation> tls;
    std::optional<std::int64_t> tls_id;
    try {
        tls = TlsProbe{}.probe(target.host, target.port, ca);
        tls_id = store.add_tls(*tls);
    } catch (const std::exception& error) {
        std::cerr << "TLS supporting probe unavailable: " << error.what() << "\n";
    }
    const auto baseline = store.baseline_for(target.host, target.port);

    std::unordered_map<std::string, Tracked> tracked;
    
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(duration);
    std::size_t observed = 0;

    while (std::chrono::steady_clock::now() < deadline && !g_stop_requested)
    {
        for (auto& [unused, tracked_connection] : tracked) {
            static_cast<void>(unused);
            tracked_connection.present = false;
        }

        for (const auto& socket : observer->snapshot()) {
            if (socket.remote_port != target.port || !target.ips.contains(socket.remote_ip)) continue;
            const auto key = key_for(socket);
            auto it = tracked.find(key);
            if (it == tracked.end()) {
                if (!platform::eligible_for_new_connection(socket)) continue;

                const auto process = resolver->resolve(socket.socket_inode);
                if (!process) {
                    // Do not create misleading anonymous history.
                    // Retry naturally on the next SOCK_DIAG poll.
                    continue;
                }

                const auto id = store.begin_connection(socket, process, target.host, socket.transport.observed_ns);

                store.add_tcp_sample(id, socket.transport);
                if (auto route_observation = route->route_to(socket.remote_ip)) {
                    store.add_route(id, *route_observation);
                }
                tracked.emplace(key, Tracked{id, socket.transport, socket.transport, socket.transport.observed_ns, true});
                ++observed;
            } 
            else {
                it->second.present = true;
                it->second.last_seen = socket.transport;
                store.touch_connection(it->second.db_id, socket.transport.observed_ns, "ACTIVE");
                if (meaningful_change(it->second.last_persisted, socket.transport,
                                      it->second.last_persist_ns)) {
                    store.add_tcp_sample(it->second.db_id, socket.transport);
                    it->second.last_persisted = socket.transport;
                    it->second.last_persist_ns = socket.transport.observed_ns;
                }
            }
        }

        for (auto& [unused, tracked_connection] : tracked) {
            static_cast<void>(unused);
            if (!tracked_connection.present) {
                store.touch_connection(tracked_connection.db_id,
                                       tracked_connection.last_seen.observed_ns,
                                       "DISAPPEARED");
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }

    finalize_observe_cmd(tracked, store, baseline, tls, tls_id);

    store.prune_to_budget(max_db_mb * 1024ULL * 1024ULL);

    std::signal(SIGINT, previous_sigint);
    std::signal(SIGTERM, previous_sigterm);

    std::cout << "Observed " << observed << " matching connection(s). History: " << db << "\n";
}

void finalize_observe_cmd(const std::unordered_map<std::string, Tracked>& tracked,
                        HistoryStore& store,
                        const std::optional<Baseline>& baseline,
                        const std::optional<TlsObservation>& tls,
                        std::optional<std::int64_t> tls_id)
{
    for (auto& [unused, tracked_connection] : tracked)
    {
        static_cast<void>(unused);
        const char* final_state =
            tracked_connection.present
                ? "OBSERVATION_ENDED"
                : "DISAPPEARED";

        store.touch_connection(
            tracked_connection.db_id,
            tracked_connection.last_seen.observed_ns,
            final_state);

        if (baseline) {
            const auto samples =
                store.samples_for_connection(
                    tracked_connection.db_id);

            const auto verdict =
                evaluate(
                    *baseline,
                    aggregate_metrics(samples),
                    tls);

            store.save_verdict(
                tracked_connection.db_id,
                verdict,
                tls_id);
        }
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
            std::cout << "{\"id\":" << connection->id << ",\"process\":\""
                      << json_escape(connection->process.comm) << "\",\"local\":\""
                      << json_escape(connection->local_ip) << ':' << connection->local_port
                      << "\",\"remote\":\"" << json_escape(connection->remote_ip) << ':'
                      << connection->remote_port << "\",\"target\":\""
                      << json_escape(connection->target_host) << "\",\"performance\":\""
                      << to_string(connection->performance) << "\",\"trust\":\""
                      << to_string(connection->trust) << "\"}\n";
        } else {
            std::cout << "CONN-" << connection->id << "  " << connection->process.comm << '['
                      << connection->process.pid << "]  " << connection->local_ip << ':'
                      << connection->local_port << " -> " << connection->remote_ip << ':'
                      << connection->remote_port << "  " << to_string(connection->performance)
                      << " / " << to_string(connection->trust) << "\n";
        }
        return;
    }

    const auto rows = store.recent_connections(limit);
    if (has_arg(argc, argv, "--json")) {
        std::cout << '[';
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (i) std::cout << ',';
            const auto& connection = rows[i];
            std::cout << "{\"id\":" << connection.id << ",\"process\":\""
                      << json_escape(connection.process.comm) << "\",\"remote\":\""
                      << json_escape(connection.remote_ip) << ':' << connection.remote_port
                      << "\",\"performance\":\"" << to_string(connection.performance)
                      << "\",\"trust\":\"" << to_string(connection.trust) << "\"}";
        }
        std::cout << "]\n";
    } else {
        std::cout << "ID       PROCESS          REMOTE                         PERF                  TRUST\n";
        for (const auto& connection : rows) {
            std::cout << "CONN-" << std::left << std::setw(6) << connection.id
                      << std::setw(17) << connection.process.comm
                      << std::setw(31) << (connection.remote_ip + ':' + std::to_string(connection.remote_port))
                      << std::setw(22) << to_string(connection.performance)
                      << to_string(connection.trust) << "\n";
        }
    }
}

void cmd_baseline(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("baseline requires capture or show");
    const auto target = parse_target(arg_value(argc, argv, "--target"));
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));

    if (std::string(argv[2]) == "show") {
        auto baseline = store.baseline_for(target.host, target.port);
        if (!baseline) throw std::runtime_error("baseline not found");
        std::cout << "Target: " << baseline->target_host << ':' << baseline->target_port
                  << "\nRTT median: " << static_cast<double>(baseline->rtt_median_us) / 1000.0
                  << " ms\nRTT var median: " << static_cast<double>(baseline->rttvar_median_us) / 1000.0
                  << " ms\nSamples: " << baseline->sample_count
                  << "\nAccepted SPKI: " << baseline->accepted_spki_sha256
                  << "\nHash: " << baseline->sha256 << "\n";
        return;
    }
    if (std::string(argv[2]) != "capture") throw std::runtime_error("unknown baseline action");

    const auto samples = store.recent_samples_for_target(target.host, target.port, 200);
    if (samples.size() < 5) {
        throw std::runtime_error("need at least 5 persisted target samples; run observe first (20+ recommended)");
    }

    std::vector<std::uint64_t> rtts;
    std::vector<std::uint64_t> rttvars;
    for (const auto& sample : samples) {
        if (sample.rtt_us) rtts.push_back(sample.rtt_us);
        if (sample.rtt_variance_us) rttvars.push_back(sample.rtt_variance_us);
    }
    if (rtts.empty()) throw std::runtime_error("samples contain no RTT evidence");

    const auto tls = TlsProbe{}.probe(target.host, target.port, arg_value(argc, argv, "--ca"));
    if (!tls.chain_valid || !tls.hostname_valid) {
        throw std::runtime_error("refusing to accept baseline from invalid TLS identity");
    }
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
    baseline.sha256 = sha256_hex(baseline.target_host + ':' + std::to_string(baseline.target_port) +
                                 '|' + std::to_string(baseline.rtt_median_us) + '|' +
                                 std::to_string(baseline.rttvar_median_us) + '|' +
                                 baseline.accepted_spki_sha256 + '|' +
                                 std::to_string(baseline.sample_count));
    store.save_baseline(baseline);
    std::cout << "Captured baseline for " << target.host << ':' << target.port << " from "
              << samples.size() << " samples. Hash " << baseline.sha256 << "\n";
}

void cmd_evidence(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("evidence requires connection ID");
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));
    const auto id = std::stoll(argv[2]);
    const auto data = store.export_data(id);

    std::cout << "Connection CONN-" << id << "\n"
              << "  Process: "
              << (data.connection.process.comm.empty() ? "<unattributed>" : data.connection.process.comm)
              << '[' << data.connection.process.pid << "]\n"
              << "  Path: " << data.connection.local_ip << ':' << data.connection.local_port
              << " -> " << data.connection.remote_ip << ':' << data.connection.remote_port << "\n"
              << "  Lifecycle: " << data.connection.lifecycle_state << "\n\n"
              << "TCP samples (EXACT): " << data.samples.size() << "\n";

    if (!data.samples.empty()) {
        const auto start_ns = data.samples.front().observed_ns;
        std::cout << std::right
                  << std::setw(10) << "offset_ms"
                  << std::setw(8) << "state"
                  << std::setw(11) << "rtt_ms"
                  << std::setw(12) << "rttvar_ms"
                  << std::setw(10) << "retrans"
                  << std::setw(8) << "lost"
                  << std::setw(10) << "unacked"
                  << std::setw(8) << "cwnd"
                  << std::setw(12) << "ssthresh"
                  << std::setw(10) << "snd_mss"
                  << std::setw(10) << "rcv_mss"
                  << std::setw(12) << "send_q"
                  << std::setw(12) << "recv_q" << '\n';

        for (const auto& sample : data.samples) {
            const auto offset_ms = (sample.observed_ns - start_ns) / 1'000'000ULL;
            std::cout << std::right
                      << std::setw(10) << offset_ms
                      << std::setw(8) << static_cast<unsigned>(sample.state)
                      << std::setw(11) << std::fixed << std::setprecision(3)
                      << static_cast<double>(sample.rtt_us) / 1000.0
                      << std::setw(12) << static_cast<double>(sample.rtt_variance_us) / 1000.0
                      << std::setw(10) << sample.total_retrans
                      << std::setw(8) << sample.lost
                      << std::setw(10) << sample.unacked
                      << std::setw(8) << sample.snd_cwnd
                      << std::setw(12) << sample.snd_ssthresh
                      << std::setw(10) << sample.snd_mss
                      << std::setw(10) << sample.rcv_mss
                      << std::setw(12) << sample.send_queue_bytes
                      << std::setw(12) << sample.recv_queue_bytes << '\n';
        }
    }

    if (data.route) {
        const auto& route = *data.route;
        std::cout << "\nRoute (STRONGLY_CORRELATED)\n"
                  << "  Destination: " << route.destination << '\n'
                  << "  Source:      " << route.source << '\n'
                  << "  Gateway:     " << (route.gateway.empty() ? "<direct>" : route.gateway) << '\n'
                  << "  Interface:   " << route.interface_name << " (index "
                  << route.interface_index << ")\n"
                  << "  Observed ns: " << route.observed_ns << '\n'
                  << "  SHA-256:     " << route.sha256 << '\n';
    }

    if (data.tls) {
        const auto& tls = *data.tls;
        std::cout << "\nTLS active probe (SUPPORTING)\n"
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
                  << "  Evidence hash:  " << tls.sha256 << '\n';
    }
}

void cmd_explain(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("explain requires connection ID");
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));
    const auto id = std::stoll(argv[2]);
    auto data = store.export_data(id);
    if (!data.verdict) {
        throw std::runtime_error("no verdict for connection (capture a baseline, then observe again)");
    }
    const auto metrics = aggregate_metrics(data.samples);
    std::cout << "Connection Assurance\n--------------------\nCONN-" << id << "  "
              << data.connection.process.comm << '[' << data.connection.process.pid << "]\n"
              << data.connection.local_ip << ':' << data.connection.local_port << " -> "
              << data.connection.remote_ip << ':' << data.connection.remote_port
              << "\n\nPerformance: " << to_string(data.verdict->performance)
              << "\nHypothesis: "
              << (data.verdict->performance_hypothesis.empty() ? "none" : data.verdict->performance_hypothesis)
              << "\nObserved RTT: " << static_cast<double>(metrics.observed_rtt_us) / 1000.0
              << " ms\nObserved RTT var: " << static_cast<double>(metrics.observed_rttvar_us) / 1000.0
              << " ms\nRetransmission delta: " << metrics.retransmission_delta
              << "\nRule confidence: " << data.verdict->rule_confidence
              << "\n\nTrust: " << to_string(data.verdict->trust)
              << "\nHypothesis: "
              << (data.verdict->trust_hypothesis.empty() ? "none" : data.verdict->trust_hypothesis)
              << "\nTLS evidence fidelity: SUPPORTING (independent active probe)"
              << "\n\nCausality: performance/trust causal relation NOT ESTABLISHED"
              << "\nRule set: " << data.verdict->rule_set_version
              << "\nRule hash: " << data.verdict->rule_set_hash
              << "\nInput hash: " << data.verdict->input_hash << "\n";
}

void cmd_export(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("export requires connection ID");
    HistoryStore store(arg_value(argc, argv, "--db", default_db_path().string()));
    const auto id = std::stoll(argv[2]);
    const auto data = store.export_data(id);
    if (!data.baseline || !data.verdict) {
        throw std::runtime_error("export requires baseline and verdict");
    }
    const auto metrics = aggregate_metrics(data.samples);

    std::cout << "{\n  \"schema_version\":1,\n  \"connection_id\":" << id
              << ",\n  \"target_host\":\"" << json_escape(data.connection.target_host)
              << "\",\n  \"target_port\":" << data.connection.remote_port
              << ",\n  \"performance\":\"" << to_string(data.verdict->performance)
              << "\",\n  \"trust\":\"" << to_string(data.verdict->trust)
              << "\",\n  \"rule_set_version\":\"" << data.verdict->rule_set_version
              << "\",\n  \"rule_set_hash\":\"" << data.verdict->rule_set_hash
              << "\",\n  \"input_hash\":\"" << data.verdict->input_hash
              << "\",\n  \"baseline_hash\":\"" << data.baseline->sha256
              << "\",\n  \"baseline_rtt_median_us\":" << data.baseline->rtt_median_us
              << ",\n  \"baseline_rttvar_median_us\":" << data.baseline->rttvar_median_us
              << ",\n  \"baseline_sample_count\":" << data.baseline->sample_count
              << ",\n  \"baseline_spki\":\"" << data.baseline->accepted_spki_sha256
              << "\",\n  \"observed_rtt_us\":" << metrics.observed_rtt_us
              << ",\n  \"observed_rttvar_us\":" << metrics.observed_rttvar_us
              << ",\n  \"retransmission_delta\":" << metrics.retransmission_delta
              << ",\n  \"tls_present\":" << (data.tls ? "true" : "false")
              << ",\n  \"tls_spki\":\"" << (data.tls ? data.tls->spki_sha256 : "")
              << "\",\n  \"tls_chain_valid\":" << (data.tls && data.tls->chain_valid ? "true" : "false")
              << ",\n  \"tls_hostname_valid\":" << (data.tls && data.tls->hostname_valid ? "true" : "false")
              << ",\n  \"tls_hash\":\"" << (data.tls ? data.tls->sha256 : "")
              << "\",\n  \"evidence\":[\n";

    for (std::size_t i = 0; i < data.samples.size(); ++i) {
        const auto& sample = data.samples[i];
        const auto hash = sha256_hex(std::to_string(sample.observed_ns) + '|' +
                                     std::to_string(sample.state) + '|' +
                                     std::to_string(sample.rtt_us) + '|' +
                                     std::to_string(sample.rtt_variance_us) + '|' +
                                     std::to_string(sample.total_retrans) + '|' +
                                     std::to_string(sample.lost) + '|' +
                                     std::to_string(sample.unacked) + '|' +
                                     std::to_string(sample.snd_cwnd) + '|' +
                                     std::to_string(sample.snd_ssthresh) + '|' +
                                     std::to_string(sample.snd_mss) + '|' +
                                     std::to_string(sample.rcv_mss) + '|' +
                                     std::to_string(sample.send_queue_bytes) + '|' +
                                     std::to_string(sample.recv_queue_bytes));
        std::cout << "    {\"kind\":\"TCP_SNAPSHOT\",\"fidelity\":\"EXACT\",\"sha256\":\""
                  << hash << "\"}" << (i + 1 < data.samples.size() ? "," : "") << "\n";
    }
    std::cout << "  ]\n}\n";
}

void cmd_replay(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("replay requires bundle file");
    std::ifstream in(argv[2]);
    if (!in) throw std::runtime_error("cannot open bundle");
    const std::string text((std::istreambuf_iterator<char>(in)), {});

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

    std::cout << "Original Performance/Trust: " << original_performance << " / " << original_trust
              << "\nReplay Performance/Trust:   " << to_string(replay.performance) << " / "
              << to_string(replay.trust)
              << "\nEvidence input hash:        "
              << (replay.input_hash == original_input_hash ? "MATCH" : "MISMATCH")
              << "\nRule set:                   "
              << (replay.rule_set_hash == original_rule_hash ? "MATCH" : "MISMATCH")
              << "\nVerdict:                    "
              << ((to_string(replay.performance) == original_performance &&
                   to_string(replay.trust) == original_trust) ? "MATCH" : "MISMATCH")
              << "\n";
}

void cmd_storage(int argc, char** argv) {
    if (argc < 3) throw std::runtime_error("storage requires status or prune");
    const auto db = arg_value(argc, argv, "--db", default_db_path().string());
    const auto max_bytes = std::stoull(arg_value(argc, argv, "--max-db-mb", "200")) *
                           1024ULL * 1024ULL;
    HistoryStore store(db);
    if (std::string(argv[2]) == "prune") store.prune_to_budget(max_bytes);
    const auto status = store.status(max_bytes);
    std::cout << "Database: " << status.path
              << "\nSize: " << std::fixed << std::setprecision(2)
              << static_cast<double>(status.bytes) / (1024.0 * 1024.0) << " MB"
              << "\nConfigured cap: " << static_cast<double>(status.max_bytes) / (1024.0 * 1024.0)
              << " MB\nConnections: " << status.connection_count
              << "\nTransport samples: " << status.sample_count << "\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            print_usage();
            return 1;
        }
        const std::string command = argv[1];
        if (command == "capabilities") cmd_capabilities();
        else if (command == "observe") cmd_observe(argc, argv);
        else if (command == "history") cmd_history(argc, argv);
        else if (command == "baseline") cmd_baseline(argc, argv);
        else if (command == "evidence") cmd_evidence(argc, argv);
        else if (command == "explain") cmd_explain(argc, argv);
        else if (command == "export") cmd_export(argc, argv);
        else if (command == "replay") cmd_replay(argc, argv);
        else if (command == "storage") cmd_storage(argc, argv);
        else {
            print_usage();
            return 1;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "neta-agent: " << error.what() << "\n";
        return 2;
    }
}