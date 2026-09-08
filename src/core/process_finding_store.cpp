#include "neta/process_finding_store.hpp"

#include "neta/crypto.hpp"

#include <sqlite3.h>

#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>

namespace neta {
namespace {

class Statement {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db));
    }
    ~Statement() { sqlite3_finalize(stmt_); }
    sqlite3_stmt* get() const noexcept { return stmt_; }
    void done() {
        if (sqlite3_step(stmt_) != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(db_));
    }
private:
    sqlite3* db_;
    sqlite3_stmt* stmt_{nullptr};
};

std::string text_col(sqlite3_stmt* stmt, int column) {
    const auto* value = sqlite3_column_text(stmt, column);
    return value ? reinterpret_cast<const char*>(value) : std::string{};
}

std::string sqlite_path_utf8(const std::filesystem::path& path) {
#ifdef _WIN32
    const auto value = path.u8string();
    return std::string(reinterpret_cast<const char*>(value.data()), value.size());
#else
    return path.string();
#endif
}

std::string optional_process_key(const std::optional<ProcessInstanceKey>& key) {
    return key ? stable_process_key(*key) : std::string{};
}

StoredProcessFinding from_row(sqlite3_stmt* stmt) {
    StoredProcessFinding row;
    row.finding_id = text_col(stmt, 0);
    row.finding_key = text_col(stmt, 1);
    row.rule_id = text_col(stmt, 2);
    row.ruleset_version = text_col(stmt, 3);
    row.severity = text_col(stmt, 4);
    row.process_key = text_col(stmt, 5);
    row.parent_key = text_col(stmt, 6);
    row.pid = sqlite3_column_int64(stmt, 7);
    if (sqlite3_column_type(stmt, 8) != SQLITE_NULL) row.parent_pid = sqlite3_column_int64(stmt, 8);
    row.process_image = text_col(stmt, 9);
    row.parent_image = text_col(stmt, 10);
    row.command_line = text_col(stmt, 11);
    row.summary = text_col(stmt, 12);
    row.interpretation = text_col(stmt, 13);
    row.evidence_root = text_col(stmt, 14);
    row.observed_at_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 15));
    row.first_seen_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 16));
    row.last_seen_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 17));
    row.occurrence_count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 18));
    row.report_state = text_col(stmt, 19);
    return row;
}

constexpr const char* finding_columns =
    "finding_id,finding_key,rule_id,ruleset_version,severity,process_key,parent_key,pid,parent_pid,"
    "process_image,parent_image,command_line,summary,interpretation,evidence_root,observed_at_ns,"
    "first_seen_ns,last_seen_ns,occurrence_count,report_state";

}  // namespace

std::string stable_process_key(const ProcessInstanceKey& key) {
    if (key.platform_key) return "native:" + std::to_string(*key.platform_key) + ":pid:" + std::to_string(key.pid);
    if (key.start_time_ns) return "start-ns:" + std::to_string(*key.start_time_ns) + ":pid:" + std::to_string(key.pid);
    return "unstable:pid:" + std::to_string(key.pid);
}

ProcessFindingStore::ProcessFindingStore(std::filesystem::path path) : path_(std::move(path)) {
    if (!path_.parent_path().empty()) std::filesystem::create_directories(path_.parent_path());
    const auto database_path = sqlite_path_utf8(path_);
    if (sqlite3_open_v2(database_path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK)
        throw std::runtime_error("failed to open SQLite DB for process findings: " + std::string(sqlite3_errmsg(db_)));
    sqlite3_busy_timeout(db_, 5000);
    exec("PRAGMA foreign_keys=ON;");
    exec("PRAGMA journal_mode=WAL;");
    exec("PRAGMA synchronous=NORMAL;");
    initialize_schema();
}

ProcessFindingStore::~ProcessFindingStore() { if (db_) sqlite3_close(db_); }

void ProcessFindingStore::exec(const char* sql) const {
    char* error = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "SQLite process finding error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

void ProcessFindingStore::initialize_schema() {
    exec(R"SQL(
CREATE TABLE IF NOT EXISTS process_instances_ms5(
 process_key TEXT PRIMARY KEY,
 pid INTEGER NOT NULL,
 parent_key TEXT,
 parent_pid INTEGER,
 started_at_ns INTEGER NOT NULL,
 exited_at_ns INTEGER,
 exit_code INTEGER,
 uid INTEGER,
 gid INTEGER,
 session_id INTEGER,
 user_identity TEXT NOT NULL DEFAULT '',
 integrity_level TEXT NOT NULL DEFAULT '',
 elevated INTEGER,
 comm TEXT NOT NULL DEFAULT '',
 executable_path TEXT NOT NULL DEFAULT '',
 command_line TEXT NOT NULL DEFAULT '',
 working_directory TEXT NOT NULL DEFAULT '',
 updated_at_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_process_instances_ms5_pid ON process_instances_ms5(pid,started_at_ns DESC);
CREATE INDEX IF NOT EXISTS idx_process_instances_ms5_parent ON process_instances_ms5(parent_key,started_at_ns);
CREATE TABLE IF NOT EXISTS process_findings_ms5(
 finding_id TEXT PRIMARY KEY,
 finding_key TEXT NOT NULL UNIQUE,
 rule_id TEXT NOT NULL,
 ruleset_version TEXT NOT NULL,
 severity TEXT NOT NULL,
 process_key TEXT NOT NULL,
 parent_key TEXT,
 pid INTEGER NOT NULL,
 parent_pid INTEGER,
 process_image TEXT NOT NULL DEFAULT '',
 parent_image TEXT NOT NULL DEFAULT '',
 command_line TEXT NOT NULL DEFAULT '',
 summary TEXT NOT NULL,
 interpretation TEXT NOT NULL,
 evidence_root TEXT NOT NULL,
 observed_at_ns INTEGER NOT NULL,
 first_seen_ns INTEGER NOT NULL,
 last_seen_ns INTEGER NOT NULL,
 occurrence_count INTEGER NOT NULL DEFAULT 1,
 report_state TEXT NOT NULL DEFAULT 'PENDING',
 last_report_attempt_ns INTEGER,
 reported_at_ns INTEGER,
 FOREIGN KEY(process_key) REFERENCES process_instances_ms5(process_key)
);
CREATE INDEX IF NOT EXISTS idx_process_findings_ms5_recent ON process_findings_ms5(last_seen_ns DESC);
CREATE INDEX IF NOT EXISTS idx_process_findings_ms5_report ON process_findings_ms5(report_state,last_report_attempt_ns,last_seen_ns);
)SQL");
}

void ProcessFindingStore::upsert_process(const ProcessNode& node) {
    const auto key = stable_process_key(node.key);
    const auto parent_key = optional_process_key(node.parent);
    Statement stmt(db_, R"SQL(
INSERT INTO process_instances_ms5(process_key,pid,parent_key,parent_pid,started_at_ns,exited_at_ns,exit_code,uid,gid,session_id,user_identity,integrity_level,elevated,comm,executable_path,command_line,working_directory,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(process_key) DO UPDATE SET
 parent_key=excluded.parent_key,parent_pid=excluded.parent_pid,exited_at_ns=excluded.exited_at_ns,
 exit_code=excluded.exit_code,uid=excluded.uid,gid=excluded.gid,session_id=excluded.session_id,
 user_identity=excluded.user_identity,integrity_level=excluded.integrity_level,elevated=excluded.elevated,
 comm=excluded.comm,executable_path=excluded.executable_path,command_line=excluded.command_line,
 working_directory=excluded.working_directory,updated_at_ns=excluded.updated_at_ns;
)SQL");
    sqlite3_bind_text(stmt.get(), 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, node.key.pid);
    if (parent_key.empty()) sqlite3_bind_null(stmt.get(), 3); else sqlite3_bind_text(stmt.get(), 3, parent_key.c_str(), -1, SQLITE_TRANSIENT);
    if (node.parent_pid) sqlite3_bind_int64(stmt.get(), 4, *node.parent_pid); else sqlite3_bind_null(stmt.get(), 4);
    sqlite3_bind_int64(stmt.get(), 5, static_cast<sqlite3_int64>(node.started_at_ns));
    if (node.exited_at_ns) sqlite3_bind_int64(stmt.get(), 6, static_cast<sqlite3_int64>(*node.exited_at_ns)); else sqlite3_bind_null(stmt.get(), 6);
    if (node.exit_code) sqlite3_bind_int(stmt.get(), 7, *node.exit_code); else sqlite3_bind_null(stmt.get(), 7);
    if (node.uid) sqlite3_bind_int64(stmt.get(), 8, *node.uid); else sqlite3_bind_null(stmt.get(), 8);
    if (node.gid) sqlite3_bind_int64(stmt.get(), 9, *node.gid); else sqlite3_bind_null(stmt.get(), 9);
    if (node.session_id) sqlite3_bind_int64(stmt.get(), 10, *node.session_id); else sqlite3_bind_null(stmt.get(), 10);
    sqlite3_bind_text(stmt.get(), 11, node.user_identity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 12, node.integrity_level.c_str(), -1, SQLITE_TRANSIENT);
    if (node.elevated) sqlite3_bind_int(stmt.get(), 13, *node.elevated ? 1 : 0); else sqlite3_bind_null(stmt.get(), 13);
    sqlite3_bind_text(stmt.get(), 14, node.comm.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 15, node.executable_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 16, node.command_line.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 17, node.working_directory.c_str(), -1, SQLITE_TRANSIENT);
    const auto updated = node.exited_at_ns.value_or(node.started_at_ns);
    sqlite3_bind_int64(stmt.get(), 18, static_cast<sqlite3_int64>(updated));
    stmt.done();
}

StoredProcessFinding ProcessFindingStore::upsert_finding(const ProcessFinding& finding) {
    const auto process_key = stable_process_key(finding.process);
    const auto parent_key = optional_process_key(finding.parent);
    const auto finding_key = finding.rule_id + "|" + process_key + "|" + parent_key;
    const auto digest = sha256_hex(finding_key);
    const auto finding_id = "FINDING-PROC-" + digest.substr(0, 24);
    const auto evidence_root = "sha256:" + sha256_hex(
        finding.rule_id + "|" + finding.ruleset_version + "|" + process_key + "|" + parent_key + "|" +
        finding.process_image + "|" + finding.parent_image + "|" + finding.command_line + "|" +
        std::to_string(finding.observed_at_ns));

    Statement stmt(db_, R"SQL(
INSERT INTO process_findings_ms5(finding_id,finding_key,rule_id,ruleset_version,severity,process_key,parent_key,pid,parent_pid,process_image,parent_image,command_line,summary,interpretation,evidence_root,observed_at_ns,first_seen_ns,last_seen_ns,occurrence_count,report_state)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'PENDING')
ON CONFLICT(finding_key) DO UPDATE SET
 severity=excluded.severity,process_image=excluded.process_image,parent_image=excluded.parent_image,
 command_line=excluded.command_line,summary=excluded.summary,interpretation=excluded.interpretation,
 evidence_root=excluded.evidence_root,observed_at_ns=excluded.observed_at_ns,last_seen_ns=excluded.last_seen_ns,
 occurrence_count=process_findings_ms5.occurrence_count+1,
 report_state=CASE WHEN process_findings_ms5.evidence_root<>excluded.evidence_root THEN 'PENDING' ELSE process_findings_ms5.report_state END;
)SQL");
    sqlite3_bind_text(stmt.get(), 1, finding_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, finding_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, finding.rule_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, finding.ruleset_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, to_string(finding.severity), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, process_key.c_str(), -1, SQLITE_TRANSIENT);
    if (parent_key.empty()) sqlite3_bind_null(stmt.get(), 7); else sqlite3_bind_text(stmt.get(), 7, parent_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 8, finding.process.pid);
    if (finding.parent) sqlite3_bind_int64(stmt.get(), 9, finding.parent->pid); else sqlite3_bind_null(stmt.get(), 9);
    sqlite3_bind_text(stmt.get(), 10, finding.process_image.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 11, finding.parent_image.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 12, finding.command_line.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 13, finding.summary.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 14, finding.interpretation.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 15, evidence_root.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 16, static_cast<sqlite3_int64>(finding.observed_at_ns));
    sqlite3_bind_int64(stmt.get(), 17, static_cast<sqlite3_int64>(finding.observed_at_ns));
    sqlite3_bind_int64(stmt.get(), 18, static_cast<sqlite3_int64>(finding.observed_at_ns));
    stmt.done();

    Statement query(db_, (std::string("SELECT ") + finding_columns + " FROM process_findings_ms5 WHERE finding_key=?;").c_str());
    sqlite3_bind_text(query.get(), 1, finding_key.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(query.get()) != SQLITE_ROW) throw std::runtime_error(sqlite3_errmsg(db_));
    return from_row(query.get());
}

std::vector<StoredProcessFinding> ProcessFindingStore::recent_findings(std::size_t limit) const {
    Statement stmt(db_, (std::string("SELECT ") + finding_columns + " FROM process_findings_ms5 ORDER BY last_seen_ns DESC LIMIT ?;").c_str());
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(limit));
    std::vector<StoredProcessFinding> rows;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) rows.push_back(from_row(stmt.get()));
    return rows;
}

std::vector<StoredProcessFinding> ProcessFindingStore::pending_for_report(std::size_t limit,
                                                                          std::uint64_t now_ns,
                                                                          std::uint64_t retry_after_ns) const {
    Statement stmt(db_, (std::string("SELECT ") + finding_columns +
        " FROM process_findings_ms5 WHERE report_state='PENDING' AND (last_report_attempt_ns IS NULL OR last_report_attempt_ns<=?) ORDER BY last_seen_ns LIMIT ?;").c_str());
    const auto cutoff = now_ns > retry_after_ns ? now_ns - retry_after_ns : 0;
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(cutoff));
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(limit));
    std::vector<StoredProcessFinding> rows;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) rows.push_back(from_row(stmt.get()));
    return rows;
}

void ProcessFindingStore::mark_report_attempt(const std::string& finding_id, std::uint64_t now_ns) {
    Statement stmt(db_, "UPDATE process_findings_ms5 SET last_report_attempt_ns=? WHERE finding_id=?;");
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(now_ns));
    sqlite3_bind_text(stmt.get(), 2, finding_id.c_str(), -1, SQLITE_TRANSIENT);
    stmt.done();
}

void ProcessFindingStore::mark_reported(const std::string& finding_id, std::uint64_t now_ns) {
    Statement stmt(db_, "UPDATE process_findings_ms5 SET report_state='REPORTED',reported_at_ns=?,last_report_attempt_ns=? WHERE finding_id=?;");
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(now_ns));
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(now_ns));
    sqlite3_bind_text(stmt.get(), 3, finding_id.c_str(), -1, SQLITE_TRANSIENT);
    stmt.done();
}

}  // namespace neta
