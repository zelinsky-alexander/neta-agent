#include "neta/history_store.hpp"
#include "neta/crypto.hpp"
#include "neta/verdict.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace neta {
namespace {

class Statement {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db));
    }
    ~Statement() { sqlite3_finalize(stmt_); }
    sqlite3_stmt* get() const { return stmt_; }
    void step_done() {
        if (sqlite3_step(stmt_) != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(db_));
    }
private:
    sqlite3* db_;
    sqlite3_stmt* stmt_{nullptr};
};

std::string text_col(sqlite3_stmt* stmt, int col) {
    const auto* value = sqlite3_column_text(stmt, col);
    return value ? reinterpret_cast<const char*>(value) : std::string{};
}

std::uint64_t file_size_or_zero(const std::filesystem::path& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    return ec ? 0 : static_cast<std::uint64_t>(size);
}

std::uint64_t sqlite_total_size(const std::filesystem::path& path) {
    return file_size_or_zero(path) + file_size_or_zero(path.string() + "-wal");
}

std::string tcp_sample_hash(const TcpSnapshot& s) {
    return sha256_hex(std::to_string(s.observed_ns) + "|" + std::to_string(s.state) + "|" +
                      std::to_string(s.rtt_us) + "|" + std::to_string(s.rtt_variance_us) + "|" +
                      std::to_string(s.total_retrans) + "|" + std::to_string(s.lost) + "|" +
                      std::to_string(s.unacked) + "|" + std::to_string(s.snd_cwnd) + "|" +
                      std::to_string(s.snd_ssthresh) + "|" + std::to_string(s.snd_mss) + "|" +
                      std::to_string(s.rcv_mss) + "|" + std::to_string(s.send_queue_bytes) + "|" +
                      std::to_string(s.recv_queue_bytes));
}

TcpSnapshot sample_from_row(sqlite3_stmt* stmt) {
    TcpSnapshot s;
    s.observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 0));
    s.state = static_cast<std::uint8_t>(sqlite3_column_int(stmt, 1));
    s.rtt_us = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 2));
    s.rtt_variance_us = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 3));
    s.total_retrans = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 4));
    s.lost = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 5));
    s.unacked = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 6));
    s.snd_cwnd = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 7));
    s.snd_ssthresh = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 8));
    s.snd_mss = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 9));
    s.rcv_mss = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 10));
    s.send_queue_bytes = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 11));
    s.recv_queue_bytes = static_cast<std::uint32_t>(sqlite3_column_int64(stmt, 12));
    return s;
}

void prune_orphans(sqlite3* db) {
    {
        Statement stmt(db, R"SQL(
DELETE FROM processes
WHERE NOT EXISTS (
    SELECT 1 FROM connections WHERE connections.process_id = processes.id
);
)SQL");
        stmt.step_done();
    }

    {
        Statement stmt(db, R"SQL(
DELETE FROM tls_observations
WHERE NOT EXISTS (
    SELECT 1 FROM verdicts WHERE verdicts.tls_observation_id = tls_observations.id
);
)SQL");
        stmt.step_done();
    }

    // Keep every baseline referenced by retained verdict evidence, plus the newest
    // baseline for each target even if no verdict references it yet. Older,
    // unreferenced baselines are obsolete history and may be reclaimed.
    {
        Statement stmt(db, R"SQL(
DELETE FROM baselines AS candidate
WHERE NOT EXISTS (
    SELECT 1 FROM verdicts WHERE verdicts.baseline_hash = candidate.sha256
)
AND EXISTS (
    SELECT 1
    FROM baselines AS newer
    WHERE newer.target_host = candidate.target_host
      AND newer.target_port = candidate.target_port
      AND (
          newer.created_ns > candidate.created_ns
          OR (newer.created_ns = candidate.created_ns AND newer.id > candidate.id)
      )
);
)SQL");
        stmt.step_done();
    }
}

} // namespace

HistoryStore::HistoryStore(std::filesystem::path path) : path_(std::move(path)) {
    if (!path_.parent_path().empty()) std::filesystem::create_directories(path_.parent_path());
    if (sqlite3_open_v2(path_.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK)
        throw std::runtime_error("failed to open SQLite DB: " + std::string(sqlite3_errmsg(db_)));
    sqlite3_busy_timeout(db_, 5000);
    exec("PRAGMA foreign_keys=ON;");
    exec("PRAGMA journal_mode=WAL;");
    exec("PRAGMA synchronous=NORMAL;");
    exec("PRAGMA temp_store=MEMORY;");
    exec("PRAGMA auto_vacuum=INCREMENTAL;");
    initialize_schema();
}

HistoryStore::~HistoryStore() { if (db_) sqlite3_close(db_); }

void HistoryStore::exec(const char* sql) const {
    char* error = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "SQLite error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

void HistoryStore::initialize_schema() {
    exec(R"SQL(
CREATE TABLE IF NOT EXISTS processes(
 id INTEGER PRIMARY KEY,
 pid INTEGER NOT NULL,
 uid INTEGER NOT NULL,
 start_ticks INTEGER NOT NULL,
 comm TEXT NOT NULL,
 executable_path TEXT NOT NULL,
 UNIQUE(pid,start_ticks)
);
CREATE TABLE IF NOT EXISTS connections(
 id INTEGER PRIMARY KEY,
 socket_cookie INTEGER NOT NULL,
 socket_inode INTEGER NOT NULL,
 process_id INTEGER,
 local_ip TEXT NOT NULL,
 local_port INTEGER NOT NULL,
 remote_ip TEXT NOT NULL,
 remote_port INTEGER NOT NULL,
 target_host TEXT NOT NULL DEFAULT '',
 lifecycle_state TEXT NOT NULL,
 first_seen_ns INTEGER NOT NULL,
 last_seen_ns INTEGER NOT NULL,
 performance_state TEXT NOT NULL DEFAULT 'INSUFFICIENT_EVIDENCE',
 trust_state TEXT NOT NULL DEFAULT 'UNVERIFIED',
 FOREIGN KEY(process_id) REFERENCES processes(id)
);
CREATE INDEX IF NOT EXISTS idx_connections_recent ON connections(first_seen_ns DESC);
CREATE INDEX IF NOT EXISTS idx_connections_target ON connections(target_host,remote_port,first_seen_ns DESC);
CREATE TABLE IF NOT EXISTS transport_samples(
 id INTEGER PRIMARY KEY,
 connection_id INTEGER NOT NULL,
 observed_ns INTEGER NOT NULL,
 tcp_state INTEGER NOT NULL,
 rtt_us INTEGER NOT NULL,
 rttvar_us INTEGER NOT NULL,
 total_retrans INTEGER NOT NULL,
 lost INTEGER NOT NULL,
 unacked INTEGER NOT NULL,
 snd_cwnd INTEGER NOT NULL,
 snd_ssthresh INTEGER NOT NULL,
 snd_mss INTEGER NOT NULL,
 rcv_mss INTEGER NOT NULL,
 send_queue_bytes INTEGER NOT NULL,
 recv_queue_bytes INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_samples_connection ON transport_samples(connection_id,observed_ns);
CREATE TABLE IF NOT EXISTS routes(
 id INTEGER PRIMARY KEY,
 connection_id INTEGER NOT NULL UNIQUE,
 observed_ns INTEGER NOT NULL,
 destination TEXT NOT NULL,
 source TEXT NOT NULL,
 gateway TEXT NOT NULL,
 interface_name TEXT NOT NULL,
 interface_index INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tls_observations(
 id INTEGER PRIMARY KEY,
 target_host TEXT NOT NULL,
 target_port INTEGER NOT NULL,
 observed_ns INTEGER NOT NULL,
 tls_version TEXT NOT NULL,
 cipher TEXT NOT NULL,
 alpn TEXT NOT NULL,
 leaf_sha256 TEXT NOT NULL,
 spki_sha256 TEXT NOT NULL,
 subject TEXT NOT NULL,
 issuer TEXT NOT NULL,
 not_before TEXT NOT NULL,
 not_after TEXT NOT NULL,
 chain_valid INTEGER NOT NULL,
 hostname_valid INTEGER NOT NULL,
 sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tls_target ON tls_observations(target_host,target_port,observed_ns DESC);
CREATE TABLE IF NOT EXISTS baselines(
 id INTEGER PRIMARY KEY,
 target_host TEXT NOT NULL,
 target_port INTEGER NOT NULL,
 rtt_median_us INTEGER NOT NULL,
 rttvar_median_us INTEGER NOT NULL,
 accepted_spki_sha256 TEXT NOT NULL,
 accepted_issuer TEXT NOT NULL,
 sample_count INTEGER NOT NULL,
 created_ns INTEGER NOT NULL,
 sha256 TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_baselines_target ON baselines(target_host,target_port,created_ns DESC);
CREATE TABLE IF NOT EXISTS verdicts(
 connection_id INTEGER PRIMARY KEY,
 performance_state TEXT NOT NULL,
 trust_state TEXT NOT NULL,
 performance_hypothesis TEXT NOT NULL,
 trust_hypothesis TEXT NOT NULL,
 rule_confidence REAL NOT NULL,
 rule_set_version TEXT NOT NULL,
 rule_set_hash TEXT NOT NULL,
 baseline_hash TEXT NOT NULL,
 input_hash TEXT NOT NULL,
 tls_observation_id INTEGER,
 FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE,
 FOREIGN KEY(tls_observation_id) REFERENCES tls_observations(id)
);
)SQL");
}

std::int64_t HistoryStore::upsert_process(const ProcessIdentity& p) {
    Statement ins(db_, "INSERT INTO processes(pid,uid,start_ticks,comm,executable_path) VALUES(?,?,?,?,?) ON CONFLICT(pid,start_ticks) DO UPDATE SET uid=excluded.uid,comm=excluded.comm,executable_path=excluded.executable_path RETURNING id;");
    sqlite3_bind_int64(ins.get(), 1, p.pid);
    sqlite3_bind_int(ins.get(), 2, static_cast<int>(p.uid));
    sqlite3_bind_int64(ins.get(), 3, static_cast<sqlite3_int64>(p.start_ticks));
    sqlite3_bind_text(ins.get(), 4, p.comm.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins.get(), 5, p.executable_path.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(ins.get()) != SQLITE_ROW) throw std::runtime_error(sqlite3_errmsg(db_));
    return sqlite3_column_int64(ins.get(), 0);
}

std::int64_t HistoryStore::begin_connection(const SocketObservation& s,
                                            const std::optional<ProcessIdentity>& process,
                                            const std::string& target_host,
                                            std::uint64_t first_seen_ns) {
    std::optional<std::int64_t> process_id;
    if (process) process_id = upsert_process(*process);
    Statement stmt(db_, "INSERT INTO connections(socket_cookie,socket_inode,process_id,local_ip,local_port,remote_ip,remote_port,target_host,lifecycle_state,first_seen_ns,last_seen_ns) VALUES(?,?,?,?,?,?,?,?,?,?,?);");
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(s.socket_cookie));
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(s.socket_inode));
    if (process_id) sqlite3_bind_int64(stmt.get(), 3, *process_id); else sqlite3_bind_null(stmt.get(), 3);
    sqlite3_bind_text(stmt.get(), 4, s.local_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 5, s.local_port);
    sqlite3_bind_text(stmt.get(), 6, s.remote_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 7, s.remote_port);
    sqlite3_bind_text(stmt.get(), 8, target_host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 9, "ACTIVE", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 10, static_cast<sqlite3_int64>(first_seen_ns));
    sqlite3_bind_int64(stmt.get(), 11, static_cast<sqlite3_int64>(first_seen_ns));
    stmt.step_done();
    return sqlite3_last_insert_rowid(db_);
}

void HistoryStore::touch_connection(std::int64_t id, std::uint64_t last_seen_ns, const std::string& lifecycle_state) {
    Statement stmt(db_, "UPDATE connections SET last_seen_ns=?,lifecycle_state=? WHERE id=?;");
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(last_seen_ns));
    sqlite3_bind_text(stmt.get(), 2, lifecycle_state.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, id);
    stmt.step_done();
}

std::int64_t HistoryStore::add_tcp_sample(std::int64_t id, const TcpSnapshot& s) {
    const auto hash = tcp_sample_hash(s);
    Statement stmt(db_, "INSERT INTO transport_samples(connection_id,observed_ns,tcp_state,rtt_us,rttvar_us,total_retrans,lost,unacked,snd_cwnd,snd_ssthresh,snd_mss,rcv_mss,send_queue_bytes,recv_queue_bytes,sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
    int i = 1;
    sqlite3_bind_int64(stmt.get(), i++, id);
    sqlite3_bind_int64(stmt.get(), i++, static_cast<sqlite3_int64>(s.observed_ns));
    sqlite3_bind_int(stmt.get(), i++, s.state);
    sqlite3_bind_int64(stmt.get(), i++, s.rtt_us);
    sqlite3_bind_int64(stmt.get(), i++, s.rtt_variance_us);
    sqlite3_bind_int64(stmt.get(), i++, s.total_retrans);
    sqlite3_bind_int64(stmt.get(), i++, s.lost);
    sqlite3_bind_int64(stmt.get(), i++, s.unacked);
    sqlite3_bind_int64(stmt.get(), i++, s.snd_cwnd);
    sqlite3_bind_int64(stmt.get(), i++, s.snd_ssthresh);
    sqlite3_bind_int64(stmt.get(), i++, s.snd_mss);
    sqlite3_bind_int64(stmt.get(), i++, s.rcv_mss);
    sqlite3_bind_int64(stmt.get(), i++, s.send_queue_bytes);
    sqlite3_bind_int64(stmt.get(), i++, s.recv_queue_bytes);
    sqlite3_bind_text(stmt.get(), i, hash.c_str(), -1, SQLITE_TRANSIENT);
    stmt.step_done();
    return sqlite3_last_insert_rowid(db_);
}

std::int64_t HistoryStore::add_route(std::int64_t connection_id, const RouteObservation& r) {
    Statement stmt(db_, "INSERT OR REPLACE INTO routes(connection_id,observed_ns,destination,source,gateway,interface_name,interface_index,sha256) VALUES(?,?,?,?,?,?,?,?);");
    sqlite3_bind_int64(stmt.get(), 1, connection_id);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(r.observed_ns));
    sqlite3_bind_text(stmt.get(), 3, r.destination.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, r.source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, r.gateway.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, r.interface_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 7, r.interface_index);
    sqlite3_bind_text(stmt.get(), 8, r.sha256.c_str(), -1, SQLITE_TRANSIENT);
    stmt.step_done();
    return sqlite3_last_insert_rowid(db_);
}

std::int64_t HistoryStore::add_tls(const TlsObservation& t) {
    Statement stmt(db_, "INSERT INTO tls_observations(target_host,target_port,observed_ns,tls_version,cipher,alpn,leaf_sha256,spki_sha256,subject,issuer,not_before,not_after,chain_valid,hostname_valid,sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
    int i = 1;
    sqlite3_bind_text(stmt.get(), i++, t.target_host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), i++, t.target_port);
    sqlite3_bind_int64(stmt.get(), i++, static_cast<sqlite3_int64>(t.observed_ns));
    sqlite3_bind_text(stmt.get(), i++, t.tls_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), i++, t.cipher.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), i++, t.alpn.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), i++, t.leaf_sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), i++, t.spki_sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), i++, t.subject.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), i++, t.issuer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), i++, t.not_before.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), i++, t.not_after.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), i++, t.chain_valid ? 1 : 0);
    sqlite3_bind_int(stmt.get(), i++, t.hostname_valid ? 1 : 0);
    sqlite3_bind_text(stmt.get(), i, t.sha256.c_str(), -1, SQLITE_TRANSIENT);
    stmt.step_done();
    return sqlite3_last_insert_rowid(db_);
}

void HistoryStore::save_baseline(const Baseline& b) {
    Statement stmt(db_, "INSERT OR IGNORE INTO baselines(target_host,target_port,rtt_median_us,rttvar_median_us,accepted_spki_sha256,accepted_issuer,sample_count,created_ns,sha256) VALUES(?,?,?,?,?,?,?,?,?);");
    sqlite3_bind_text(stmt.get(), 1, b.target_host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 2, b.target_port);
    sqlite3_bind_int64(stmt.get(), 3, static_cast<sqlite3_int64>(b.rtt_median_us));
    sqlite3_bind_int64(stmt.get(), 4, static_cast<sqlite3_int64>(b.rttvar_median_us));
    sqlite3_bind_text(stmt.get(), 5, b.accepted_spki_sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, b.accepted_issuer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 7, static_cast<sqlite3_int64>(b.sample_count));
    sqlite3_bind_int64(stmt.get(), 8, static_cast<sqlite3_int64>(b.created_ns));
    sqlite3_bind_text(stmt.get(), 9, b.sha256.c_str(), -1, SQLITE_TRANSIENT);
    stmt.step_done();
}

std::optional<Baseline> HistoryStore::baseline_for(const std::string& host, std::uint16_t port) const {
    Statement stmt(db_, "SELECT target_host,target_port,rtt_median_us,rttvar_median_us,accepted_spki_sha256,accepted_issuer,sample_count,created_ns,sha256 FROM baselines WHERE target_host=? AND target_port=? ORDER BY created_ns DESC,id DESC LIMIT 1;");
    sqlite3_bind_text(stmt.get(), 1, host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 2, port);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    Baseline b;
    b.target_host = text_col(stmt.get(), 0);
    b.target_port = static_cast<std::uint16_t>(sqlite3_column_int(stmt.get(), 1));
    b.rtt_median_us = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 2));
    b.rttvar_median_us = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 3));
    b.accepted_spki_sha256 = text_col(stmt.get(), 4);
    b.accepted_issuer = text_col(stmt.get(), 5);
    b.sample_count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 6));
    b.created_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 7));
    b.sha256 = text_col(stmt.get(), 8);
    return b;
}

void HistoryStore::save_verdict(std::int64_t connection_id, const AssuranceVerdict& v,
                                std::optional<std::int64_t> tls_id) {
    Statement stmt(db_, "INSERT INTO verdicts(connection_id,performance_state,trust_state,performance_hypothesis,trust_hypothesis,rule_confidence,rule_set_version,rule_set_hash,baseline_hash,input_hash,tls_observation_id) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(connection_id) DO UPDATE SET performance_state=excluded.performance_state,trust_state=excluded.trust_state,performance_hypothesis=excluded.performance_hypothesis,trust_hypothesis=excluded.trust_hypothesis,rule_confidence=excluded.rule_confidence,rule_set_version=excluded.rule_set_version,rule_set_hash=excluded.rule_set_hash,baseline_hash=excluded.baseline_hash,input_hash=excluded.input_hash,tls_observation_id=excluded.tls_observation_id;");
    sqlite3_bind_int64(stmt.get(), 1, connection_id);
    const auto perf = to_string(v.performance);
    const auto trust = to_string(v.trust);
    sqlite3_bind_text(stmt.get(), 2, perf.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, trust.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, v.performance_hypothesis.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, v.trust_hypothesis.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt.get(), 6, v.rule_confidence);
    sqlite3_bind_text(stmt.get(), 7, v.rule_set_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 8, v.rule_set_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 9, v.baseline_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 10, v.input_hash.c_str(), -1, SQLITE_TRANSIENT);
    if (tls_id) sqlite3_bind_int64(stmt.get(), 11, *tls_id); else sqlite3_bind_null(stmt.get(), 11);
    stmt.step_done();

    Statement update(db_, "UPDATE connections SET performance_state=?,trust_state=? WHERE id=?;");
    sqlite3_bind_text(update.get(), 1, perf.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(update.get(), 2, trust.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(update.get(), 3, connection_id);
    update.step_done();
}

std::vector<ConnectionSummary> HistoryStore::recent_connections(std::size_t limit) const {
    Statement stmt(db_, R"SQL(SELECT c.id,c.first_seen_ns,c.last_seen_ns,COALESCE(p.pid,-1),COALESCE(p.uid,0),COALESCE(p.start_ticks,0),COALESCE(p.comm,''),COALESCE(p.executable_path,''),c.local_ip,c.local_port,c.remote_ip,c.remote_port,c.target_host,c.lifecycle_state,c.performance_state,c.trust_state FROM connections c LEFT JOIN processes p ON p.id=c.process_id ORDER BY c.first_seen_ns DESC LIMIT ?;)SQL");
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(limit));
    std::vector<ConnectionSummary> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        ConnectionSummary c;
        c.id = sqlite3_column_int64(stmt.get(), 0);
        c.first_seen_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 1));
        c.last_seen_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 2));
        c.process.pid = sqlite3_column_int64(stmt.get(), 3);
        c.process.uid = static_cast<std::uint32_t>(sqlite3_column_int(stmt.get(), 4));
        c.process.start_ticks = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 5));
        c.process.comm = text_col(stmt.get(), 6);
        c.process.executable_path = text_col(stmt.get(), 7);
        c.local_ip = text_col(stmt.get(), 8);
        c.local_port = static_cast<std::uint16_t>(sqlite3_column_int(stmt.get(), 9));
        c.remote_ip = text_col(stmt.get(), 10);
        c.remote_port = static_cast<std::uint16_t>(sqlite3_column_int(stmt.get(), 11));
        c.target_host = text_col(stmt.get(), 12);
        c.lifecycle_state = text_col(stmt.get(), 13);
        c.performance = performance_state_from_string(text_col(stmt.get(), 14));
        c.trust = trust_state_from_string(text_col(stmt.get(), 15));
        out.push_back(std::move(c));
    }
    return out;
}

std::optional<ConnectionSummary> HistoryStore::connection(std::int64_t id) const {
    Statement stmt(db_, R"SQL(SELECT c.id,c.first_seen_ns,c.last_seen_ns,COALESCE(p.pid,-1),COALESCE(p.uid,0),COALESCE(p.start_ticks,0),COALESCE(p.comm,''),COALESCE(p.executable_path,''),c.local_ip,c.local_port,c.remote_ip,c.remote_port,c.target_host,c.lifecycle_state,c.performance_state,c.trust_state FROM connections c LEFT JOIN processes p ON p.id=c.process_id WHERE c.id=?;)SQL");
    sqlite3_bind_int64(stmt.get(), 1, id);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    ConnectionSummary c;
    c.id = sqlite3_column_int64(stmt.get(), 0);
    c.first_seen_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 1));
    c.last_seen_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 2));
    c.process.pid = sqlite3_column_int64(stmt.get(), 3);
    c.process.uid = static_cast<std::uint32_t>(sqlite3_column_int(stmt.get(), 4));
    c.process.start_ticks = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 5));
    c.process.comm = text_col(stmt.get(), 6);
    c.process.executable_path = text_col(stmt.get(), 7);
    c.local_ip = text_col(stmt.get(), 8);
    c.local_port = static_cast<std::uint16_t>(sqlite3_column_int(stmt.get(), 9));
    c.remote_ip = text_col(stmt.get(), 10);
    c.remote_port = static_cast<std::uint16_t>(sqlite3_column_int(stmt.get(), 11));
    c.target_host = text_col(stmt.get(), 12);
    c.lifecycle_state = text_col(stmt.get(), 13);
    c.performance = performance_state_from_string(text_col(stmt.get(), 14));
    c.trust = trust_state_from_string(text_col(stmt.get(), 15));
    return c;
}

std::vector<TcpSnapshot> HistoryStore::samples_for_connection(std::int64_t id) const {
    Statement stmt(db_, "SELECT observed_ns,tcp_state,rtt_us,rttvar_us,total_retrans,lost,unacked,snd_cwnd,snd_ssthresh,snd_mss,rcv_mss,send_queue_bytes,recv_queue_bytes FROM transport_samples WHERE connection_id=? ORDER BY observed_ns;");
    sqlite3_bind_int64(stmt.get(), 1, id);
    std::vector<TcpSnapshot> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) out.push_back(sample_from_row(stmt.get()));
    return out;
}

std::vector<TcpSnapshot> HistoryStore::recent_samples_for_target(const std::string& host, std::uint16_t port, std::size_t limit) const {
    Statement stmt(db_, "SELECT s.observed_ns,s.tcp_state,s.rtt_us,s.rttvar_us,s.total_retrans,s.lost,s.unacked,s.snd_cwnd,s.snd_ssthresh,s.snd_mss,s.rcv_mss,s.send_queue_bytes,s.recv_queue_bytes FROM transport_samples s JOIN connections c ON c.id=s.connection_id WHERE c.target_host=? AND c.remote_port=? ORDER BY s.observed_ns DESC LIMIT ?;");
    sqlite3_bind_text(stmt.get(), 1, host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 2, port);
    sqlite3_bind_int64(stmt.get(), 3, static_cast<sqlite3_int64>(limit));
    std::vector<TcpSnapshot> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) out.push_back(sample_from_row(stmt.get()));
    std::reverse(out.begin(), out.end());
    return out;
}

std::optional<RouteObservation> HistoryStore::route_for_connection(std::int64_t id) const {
    Statement stmt(db_, "SELECT observed_ns,destination,source,gateway,interface_name,interface_index,sha256 FROM routes WHERE connection_id=?;");
    sqlite3_bind_int64(stmt.get(), 1, id);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    RouteObservation r;
    r.observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 0));
    r.destination = text_col(stmt.get(), 1);
    r.source = text_col(stmt.get(), 2);
    r.gateway = text_col(stmt.get(), 3);
    r.interface_name = text_col(stmt.get(), 4);
    r.interface_index = static_cast<std::uint32_t>(sqlite3_column_int64(stmt.get(), 5));
    r.sha256 = text_col(stmt.get(), 6);
    return r;
}

std::optional<TlsObservation> HistoryStore::latest_tls_for_target(const std::string& host, std::uint16_t port) const {
    Statement stmt(db_, "SELECT target_host,target_port,observed_ns,tls_version,cipher,alpn,leaf_sha256,spki_sha256,subject,issuer,not_before,not_after,chain_valid,hostname_valid,sha256 FROM tls_observations WHERE target_host=? AND target_port=? ORDER BY observed_ns DESC LIMIT 1;");
    sqlite3_bind_text(stmt.get(), 1, host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 2, port);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    TlsObservation t;
    t.target_host = text_col(stmt.get(), 0);
    t.target_port = static_cast<std::uint16_t>(sqlite3_column_int(stmt.get(), 1));
    t.observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 2));
    t.tls_version = text_col(stmt.get(), 3);
    t.cipher = text_col(stmt.get(), 4);
    t.alpn = text_col(stmt.get(), 5);
    t.leaf_sha256 = text_col(stmt.get(), 6);
    t.spki_sha256 = text_col(stmt.get(), 7);
    t.subject = text_col(stmt.get(), 8);
    t.issuer = text_col(stmt.get(), 9);
    t.not_before = text_col(stmt.get(), 10);
    t.not_after = text_col(stmt.get(), 11);
    t.chain_valid = sqlite3_column_int(stmt.get(), 12) != 0;
    t.hostname_valid = sqlite3_column_int(stmt.get(), 13) != 0;
    t.sha256 = text_col(stmt.get(), 14);
    return t;
}

std::optional<AssuranceVerdict> HistoryStore::verdict_for_connection(std::int64_t id) const {
    Statement stmt(db_, "SELECT performance_state,trust_state,performance_hypothesis,trust_hypothesis,rule_confidence,rule_set_version,rule_set_hash,baseline_hash,input_hash FROM verdicts WHERE connection_id=?;");
    sqlite3_bind_int64(stmt.get(), 1, id);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;
    AssuranceVerdict v;
    v.performance = performance_state_from_string(text_col(stmt.get(), 0));
    v.trust = trust_state_from_string(text_col(stmt.get(), 1));
    v.performance_hypothesis = text_col(stmt.get(), 2);
    v.trust_hypothesis = text_col(stmt.get(), 3);
    v.rule_confidence = sqlite3_column_double(stmt.get(), 4);
    v.rule_set_version = text_col(stmt.get(), 5);
    v.rule_set_hash = text_col(stmt.get(), 6);
    v.baseline_hash = text_col(stmt.get(), 7);
    v.input_hash = text_col(stmt.get(), 8);
    return v;
}

ExportData HistoryStore::export_data(std::int64_t id) const {
    ExportData data;
    auto c = connection(id);
    if (!c) throw std::runtime_error("connection not found");
    data.connection = *c;
    data.samples = samples_for_connection(id);
    data.route = route_for_connection(id);
    data.verdict = verdict_for_connection(id);

    if (data.verdict && !data.verdict->baseline_hash.empty()) {
        Statement b(db_, "SELECT target_host,target_port,rtt_median_us,rttvar_median_us,accepted_spki_sha256,accepted_issuer,sample_count,created_ns,sha256 FROM baselines WHERE sha256=? LIMIT 1;");
        sqlite3_bind_text(b.get(), 1, data.verdict->baseline_hash.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(b.get()) == SQLITE_ROW) {
            Baseline baseline;
            baseline.target_host = text_col(b.get(), 0);
            baseline.target_port = static_cast<std::uint16_t>(sqlite3_column_int(b.get(), 1));
            baseline.rtt_median_us = static_cast<std::uint64_t>(sqlite3_column_int64(b.get(), 2));
            baseline.rttvar_median_us = static_cast<std::uint64_t>(sqlite3_column_int64(b.get(), 3));
            baseline.accepted_spki_sha256 = text_col(b.get(), 4);
            baseline.accepted_issuer = text_col(b.get(), 5);
            baseline.sample_count = static_cast<std::uint64_t>(sqlite3_column_int64(b.get(), 6));
            baseline.created_ns = static_cast<std::uint64_t>(sqlite3_column_int64(b.get(), 7));
            baseline.sha256 = text_col(b.get(), 8);
            data.baseline = baseline;
        }
    }

    Statement link(db_, "SELECT tls_observation_id FROM verdicts WHERE connection_id=?;");
    sqlite3_bind_int64(link.get(), 1, id);
    if (sqlite3_step(link.get()) == SQLITE_ROW && sqlite3_column_type(link.get(), 0) != SQLITE_NULL) {
        const auto tls_id = sqlite3_column_int64(link.get(), 0);
        Statement t(db_, "SELECT target_host,target_port,observed_ns,tls_version,cipher,alpn,leaf_sha256,spki_sha256,subject,issuer,not_before,not_after,chain_valid,hostname_valid,sha256 FROM tls_observations WHERE id=?;");
        sqlite3_bind_int64(t.get(), 1, tls_id);
        if (sqlite3_step(t.get()) == SQLITE_ROW) {
            TlsObservation tls;
            tls.target_host = text_col(t.get(), 0);
            tls.target_port = static_cast<std::uint16_t>(sqlite3_column_int(t.get(), 1));
            tls.observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(t.get(), 2));
            tls.tls_version = text_col(t.get(), 3);
            tls.cipher = text_col(t.get(), 4);
            tls.alpn = text_col(t.get(), 5);
            tls.leaf_sha256 = text_col(t.get(), 6);
            tls.spki_sha256 = text_col(t.get(), 7);
            tls.subject = text_col(t.get(), 8);
            tls.issuer = text_col(t.get(), 9);
            tls.not_before = text_col(t.get(), 10);
            tls.not_after = text_col(t.get(), 11);
            tls.chain_valid = sqlite3_column_int(t.get(), 12) != 0;
            tls.hostname_valid = sqlite3_column_int(t.get(), 13) != 0;
            tls.sha256 = text_col(t.get(), 14);
            data.tls = tls;
        }
    }
    return data;
}

StorageStatus HistoryStore::status(std::uint64_t max_bytes) const {
    StorageStatus s;
    s.path = path_;
    s.bytes = sqlite_total_size(path_);
    s.max_bytes = max_bytes;
    Statement c(db_, "SELECT COUNT(*) FROM connections;");
    if (sqlite3_step(c.get()) == SQLITE_ROW) s.connection_count = static_cast<std::uint64_t>(sqlite3_column_int64(c.get(), 0));
    Statement t(db_, "SELECT COUNT(*) FROM transport_samples;");
    if (sqlite3_step(t.get()) == SQLITE_ROW) s.sample_count = static_cast<std::uint64_t>(sqlite3_column_int64(t.get(), 0));
    return s;
}

void HistoryStore::prune_to_budget(std::uint64_t max_bytes) {
    if (max_bytes == 0) return;

    auto bytes = sqlite_total_size(path_);
    if (bytes <= max_bytes) return;

    // Crossing the configured hard cap triggers cleanup to 90% of the cap.
    // The default 200 MiB budget therefore cleans down to <= 180 MiB.
    const auto target_bytes = max_bytes - (max_bytes / 10ULL);

    // First eliminate transient WAL growth. If the checkpoint itself restores
    // enough headroom, no evidence has to be deleted.
    exec("PRAGMA wal_checkpoint(TRUNCATE);");
    bytes = sqlite_total_size(path_);
    if (bytes <= target_bytes) return;

    const auto compact_and_measure = [&]() {
        prune_orphans(db_);
        // Under storage pressure, drain the current freelist before measuring
        // again. This avoids deleting additional history simply because freed
        // pages have not yet been returned to the filesystem.
        exec("PRAGMA incremental_vacuum;");
        exec("PRAGMA wal_checkpoint(TRUNCATE);");
        return sqlite_total_size(path_);
    };

    bytes = compact_and_measure();

    while (bytes > target_bytes) {
        int removed = 0;

        // Primary retention tier: reclaim the oldest non-anomalous history.
        // DEGRADED, FAILED, CHANGED, and SUSPICIOUS are protected here.
        {
            Statement del(db_, R"SQL(
DELETE FROM connections
WHERE id IN (
    SELECT id
    FROM connections
    WHERE performance_state NOT IN ('DEGRADED','FAILED')
      AND trust_state NOT IN ('CHANGED','SUSPICIOUS')
    ORDER BY first_seen_ns ASC, id ASC
    LIMIT 64
);
)SQL");
            del.step_done();
            removed = sqlite3_changes(db_);
        }

        // Protection is priority rather than immortality: if only anomalous
        // history remains and storage is still above the cleanup target, use
        // a smaller emergency batch so the configured hard cap remains
        // enforceable instead of allowing unbounded growth.
        if (removed == 0) {
            Statement emergency(db_, R"SQL(
DELETE FROM connections
WHERE id IN (
    SELECT id
    FROM connections
    WHERE performance_state IN ('DEGRADED','FAILED')
       OR trust_state IN ('CHANGED','SUSPICIOUS')
    ORDER BY first_seen_ns ASC, id ASC
    LIMIT 8
);
)SQL");
            emergency.step_done();
            removed = sqlite3_changes(db_);
        }

        if (removed == 0) break;

        // Reclaim dependent/orphaned metadata and physical pages between
        // every bounded deletion batch before deciding whether more history
        // must be removed.
        bytes = compact_and_measure();
    }

    if (bytes > max_bytes) {
        throw std::runtime_error("SQLite history cannot satisfy configured storage cap");
    }
}

} // namespace neta
