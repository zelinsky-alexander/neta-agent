#pragma once

#include "neta/crypto.hpp"
#include "neta/fleet_client.hpp"
#include "neta/fleet_reporting.hpp"
#include "neta/history_store.hpp"
#include "neta/platform.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace neta {

struct ConnectionTransferEvidence {
    std::int64_t connection_id{0};
    std::uint64_t observed_ns{0};
    std::uint64_t bytes_sent{0};
    std::uint64_t bytes_received{0};
    std::string source;
    EvidenceFidelity fidelity{EvidenceFidelity::Contextual};
};

class TransferEvidenceStore {
public:
    explicit TransferEvidenceStore(const std::filesystem::path& database_path) {
#ifdef _WIN32
        const auto value = database_path.u8string();
        const std::string path(reinterpret_cast<const char*>(value.data()), value.size());
#else
        const std::string path = database_path.string();
#endif
        if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                             SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
            throw std::runtime_error("failed to open transfer evidence database");
        }
        sqlite3_busy_timeout(db_, 5000);
        exec("PRAGMA foreign_keys=ON;");
        exec(R"SQL(
CREATE TABLE IF NOT EXISTS connection_transfer_evidence(
 connection_id INTEGER PRIMARY KEY,
 observed_ns INTEGER NOT NULL,
 bytes_sent INTEGER NOT NULL,
 bytes_received INTEGER NOT NULL,
 source TEXT NOT NULL,
 fidelity TEXT NOT NULL,
 FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
);
)SQL");
    }

    ~TransferEvidenceStore() { if (db_) sqlite3_close(db_); }
    TransferEvidenceStore(const TransferEvidenceStore&) = delete;
    TransferEvidenceStore& operator=(const TransferEvidenceStore&) = delete;

    void observe(std::int64_t connection_id, const TcpSnapshot& sample) {
        if (!sample.bytes_sent || !sample.bytes_received || sample.transfer_source.empty()) return;
        sqlite3_stmt* stmt = nullptr;
        const char* sql = R"SQL(
INSERT INTO connection_transfer_evidence(
 connection_id,observed_ns,bytes_sent,bytes_received,source,fidelity)
VALUES(?,?,?,?,?,?)
ON CONFLICT(connection_id) DO UPDATE SET
 observed_ns=CASE WHEN excluded.observed_ns>observed_ns THEN excluded.observed_ns ELSE observed_ns END,
 bytes_sent=CASE WHEN excluded.bytes_sent>bytes_sent THEN excluded.bytes_sent ELSE bytes_sent END,
 bytes_received=CASE WHEN excluded.bytes_received>bytes_received THEN excluded.bytes_received ELSE bytes_received END,
 source=excluded.source,
 fidelity=excluded.fidelity;
)SQL";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db_));
        }
        sqlite3_bind_int64(stmt, 1, connection_id);
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(sample.observed_ns));
        sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(*sample.bytes_sent));
        sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(*sample.bytes_received));
        sqlite3_bind_text(stmt, 5, sample.transfer_source.c_str(), -1, SQLITE_TRANSIENT);
        const auto fidelity = to_string(sample.transfer_fidelity);
        sqlite3_bind_text(stmt, 6, fidelity.c_str(), -1, SQLITE_TRANSIENT);
        const auto rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(db_));
    }

    std::optional<ConnectionTransferEvidence> latest(std::int64_t connection_id) const {
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT observed_ns,bytes_sent,bytes_received,source,fidelity "
                          "FROM connection_transfer_evidence WHERE connection_id=?;";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db_));
        }
        sqlite3_bind_int64(stmt, 1, connection_id);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return std::nullopt;
        }
        ConnectionTransferEvidence result;
        result.connection_id = connection_id;
        result.observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 0));
        result.bytes_sent = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 1));
        result.bytes_received = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 2));
        if (const auto* text = sqlite3_column_text(stmt, 3)) {
            result.source = reinterpret_cast<const char*>(text);
        }
        std::string fidelity;
        if (const auto* text = sqlite3_column_text(stmt, 4)) {
            fidelity = reinterpret_cast<const char*>(text);
        }
        result.fidelity = fidelity == "EXACT" ? EvidenceFidelity::Exact :
                          fidelity == "STRONGLY_CORRELATED" ? EvidenceFidelity::StronglyCorrelated :
                          fidelity == "SUPPORTING" ? EvidenceFidelity::Supporting :
                                                     EvidenceFidelity::Contextual;
        sqlite3_finalize(stmt);
        return result;
    }

private:
    void exec(const char* sql) {
        char* error = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
            const std::string message = error ? error : "SQLite transfer evidence error";
            sqlite3_free(error);
            throw std::runtime_error(message);
        }
    }

    sqlite3* db_{nullptr};
};

class TransferSampler {
public:
    explicit TransferSampler(TransferEvidenceStore& transfer_store,
                             std::chrono::milliseconds minimum_interval =
                                 std::chrono::milliseconds(100))
        : transfer_store_(transfer_store), minimum_interval_(minimum_interval) {}

    void capture(platform::ConnectionObserver& observer, HistoryStore& history, bool force = false) {
        const auto now = std::chrono::steady_clock::now();
        if (!force && last_capture_ && now - *last_capture_ < minimum_interval_) return;
        last_capture_ = now;

        const auto recent = history.recent_connections(1024);
        for (const auto& socket : observer.snapshot()) {
            if (!socket.transport.bytes_sent || !socket.transport.bytes_received) continue;
            if (socket.endpoint_kind != TcpEndpointKind::Connection) continue;

            const ConnectionSummary* match = nullptr;
            for (const auto& connection : recent) {
                if (connection.local_ip != socket.local_ip ||
                    connection.local_port != socket.local_port ||
                    connection.remote_ip != socket.remote_ip ||
                    connection.remote_port != socket.remote_port) {
                    continue;
                }
                if (!match || connection.first_seen_ns > match->first_seen_ns) match = &connection;
            }
            if (match) transfer_store_.observe(match->id, socket.transport);
        }
    }

private:
    TransferEvidenceStore& transfer_store_;
    std::chrono::milliseconds minimum_interval_;
    std::optional<std::chrono::steady_clock::time_point> last_capture_;
};

struct LargeIngressPolicy {
    std::uint64_t minimum_bytes_received{32ULL * 1024ULL * 1024ULL};
};

struct LargeIngressFinding {
    std::string type{"LARGE_INGRESS_TRANSFER"};
    std::string severity{"LOW"};
    double confidence{1.0};
    std::string malicious_intent{"UNKNOWN"};
    std::int64_t connection_id{0};
    std::string process_name;
    std::string process_identity;
    std::string host;
    std::uint16_t port{0};
    std::uint64_t bytes_sent{0};
    std::uint64_t bytes_received{0};
    std::string source;
    EvidenceFidelity fidelity{EvidenceFidelity::Contextual};
    std::string finding_key;
    std::string finding_id;
    std::string evidence_root;
    std::string interpretation;
};

inline std::optional<LargeIngressFinding> detect_large_ingress(
    HistoryStore& history, const TransferEvidenceStore& transfer_store,
    std::int64_t connection_id, const LargeIngressPolicy& policy = {}) {
    if (policy.minimum_bytes_received == 0) return std::nullopt;
    const auto connection = history.connection(connection_id);
    if (!connection || connection->direction != ConnectionDirection::Outbound) return std::nullopt;
    const auto transfer = transfer_store.latest(connection_id);
    if (!transfer || transfer->bytes_received < policy.minimum_bytes_received) return std::nullopt;

    LargeIngressFinding finding;
    finding.connection_id = connection_id;
    finding.process_name = !connection->process.comm.empty()
        ? connection->process.comm : connection->process.executable_path;
    finding.process_identity = !connection->process.executable_path.empty()
        ? "exe=" + connection->process.executable_path
        : !connection->process.comm.empty() ? "comm=" + connection->process.comm : "unknown";
    finding.host = !connection->target_host.empty() ? connection->target_host : connection->remote_ip;
    finding.port = connection->remote_port;
    finding.bytes_sent = transfer->bytes_sent;
    finding.bytes_received = transfer->bytes_received;
    finding.source = transfer->source;
    finding.fidelity = transfer->fidelity;
    finding.confidence = transfer->fidelity == EvidenceFidelity::Exact ? 1.0 :
                         transfer->fidelity == EvidenceFidelity::StronglyCorrelated ? 0.9 : 0.7;

    const auto evidence = finding.type + "|connection=" + std::to_string(connection_id) +
        "|received=" + std::to_string(finding.bytes_received) +
        "|sent=" + std::to_string(finding.bytes_sent) + "|source=" + finding.source;
    finding.evidence_root = "sha256:" + sha256_hex(evidence);
    finding.finding_key = "sha256:" + sha256_hex(
        finding.type + "|" + finding.process_identity + "|" + finding.host + ":" +
        std::to_string(finding.port));
    auto suffix = finding.evidence_root.substr(7);
    if (suffix.size() > 12) suffix.resize(12);
    finding.finding_id = "FINDING-TRANSFER-" + suffix;
    finding.interpretation =
        "A process received a large volume of TCP data from a remote endpoint during a single "
        "connection. Malicious intent is not established.";
    return finding;
}

struct TransferReportingResult {
    std::size_t considered{0};
    std::size_t detected{0};
    std::size_t persisted{0};
    std::size_t announced{0};
    std::size_t suppressed_policy{0};
    std::size_t suppressed_cooldown{0};
    std::size_t failed{0};
};

namespace transfer_detail {

inline std::filesystem::path suffix(std::filesystem::path path, const char* value) {
    path += value;
    return path;
}

inline std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << static_cast<char>(c); break;
        }
    }
    return out.str();
}

inline std::unordered_map<std::string, std::int64_t> load_cooldowns(
    const std::filesystem::path& path) {
    std::unordered_map<std::string, std::int64_t> result;
    std::ifstream input(path);
    std::string key;
    std::int64_t epoch = 0;
    while (input >> key >> epoch) result[key] = epoch;
    return result;
}

inline void save_cooldowns(const std::filesystem::path& path,
                           const std::unordered_map<std::string, std::int64_t>& cooldowns) {
    const auto temp = suffix(path, ".tmp");
    std::ofstream output(temp, std::ios::trunc);
    if (!output) throw std::runtime_error("cannot write transfer cooldown state");
    for (const auto& [key, epoch] : cooldowns) output << key << ' ' << epoch << '\n';
    output.close();
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::rename(temp, path);
}

inline void persist(const std::filesystem::path& path, const LargeIngressFinding& finding,
                    std::int64_t created_epoch) {
    std::ofstream output(path, std::ios::app);
    if (!output) throw std::runtime_error("cannot persist transfer finding");
    output << '{'
           << "\"finding_id\":\"" << json_escape(finding.finding_id) << "\","
           << "\"finding_key\":\"" << json_escape(finding.finding_key) << "\","
           << "\"type\":\"" << finding.type << "\","
           << "\"severity\":\"" << finding.severity << "\","
           << "\"confidence\":" << finding.confidence << ','
           << "\"malicious_intent\":\"" << finding.malicious_intent << "\","
           << "\"process\":\"" << json_escape(finding.process_name) << "\","
           << "\"host\":\"" << json_escape(finding.host) << "\","
           << "\"port\":" << finding.port << ','
           << "\"connection_id\":" << finding.connection_id << ','
           << "\"bytes_sent\":" << finding.bytes_sent << ','
           << "\"bytes_received\":" << finding.bytes_received << ','
           << "\"transfer_source\":\"" << json_escape(finding.source) << "\","
           << "\"transfer_fidelity\":\"" << to_string(finding.fidelity) << "\","
           << "\"evidence_root\":\"" << finding.evidence_root << "\","
           << "\"interpretation\":\"" << json_escape(finding.interpretation) << "\","
           << "\"created_epoch\":" << created_epoch << "}\n";
    if (!output) throw std::runtime_error("cannot flush transfer finding");
}

inline FindingAnnouncementInput announcement(const LargeIngressFinding& finding) {
    FindingAnnouncementInput input;
    input.finding_id = finding.finding_id;
    input.finding_key = finding.finding_key;
    input.host = finding.host;
    input.port = finding.port;
    input.transport = "tcp";
    input.performance_verdict = "INSUFFICIENT_EVIDENCE";
    input.trust_verdict = "UNVERIFIED";
    input.evidence_root = finding.evidence_root;
    input.changes.emplace_back("Finding type: " + finding.type);
    input.changes.emplace_back("Severity: " + finding.severity);
    input.changes.emplace_back("Process: " + finding.process_name);
    input.changes.emplace_back("Connection: CONN-" + std::to_string(finding.connection_id));
    input.changes.emplace_back("Bytes received: " + std::to_string(finding.bytes_received));
    input.changes.emplace_back("Bytes sent: " + std::to_string(finding.bytes_sent));
    input.changes.emplace_back("Transfer source: " + finding.source);
    input.changes.emplace_back("Transfer fidelity: " + to_string(finding.fidelity));
    input.changes.emplace_back(finding.interpretation);
    return input;
}

} // namespace transfer_detail

inline TransferReportingResult auto_report_large_ingress(
    HistoryStore& history, TransferEvidenceStore& transfer_store,
    std::int64_t connection_id, const FleetReportingPolicy& reporting_policy,
    const LargeIngressPolicy& detector_policy = {}) {
    TransferReportingResult result;
    ++result.considered;
    try {
        const auto finding = detect_large_ingress(
            history, transfer_store, connection_id, detector_policy);
        if (!finding) return result;
        ++result.detected;
        const auto now_epoch = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const auto state_path = transfer_detail::suffix(history.path(), ".transfer.state");
        auto cooldowns = transfer_detail::load_cooldowns(state_path);
        const auto previous = cooldowns.find(finding->finding_key);
        if (previous != cooldowns.end() &&
            now_epoch - previous->second < reporting_policy.cooldown.count()) {
            ++result.suppressed_cooldown;
            return result;
        }

        transfer_detail::persist(
            transfer_detail::suffix(history.path(), ".findings.jsonl"), *finding, now_epoch);
        ++result.persisted;
        cooldowns[finding->finding_key] = now_epoch;
        transfer_detail::save_cooldowns(state_path, cooldowns);

        if (reporting_policy.mode == FleetReportingMode::Off ||
            finding->confidence < reporting_policy.minimum_confidence ||
            !std::filesystem::exists(reporting_policy.state_dir / "identity.conf")) {
            ++result.suppressed_policy;
            return result;
        }
        FleetClient::send_finding(reporting_policy.state_dir,
                                  transfer_detail::announcement(*finding));
        ++result.announced;
    } catch (const std::exception& error) {
        ++result.failed;
        std::cerr << "Large ingress reporting failed for CONN-" << connection_id
                  << ": " << error.what() << '\n';
    }
    return result;
}

} // namespace neta
