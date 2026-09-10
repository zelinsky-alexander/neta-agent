#include "neta/artifact_evidence_store.hpp"

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

std::string tags_json(const std::vector<std::string>& tags) {
    std::string out = "[";
    for (std::size_t i = 0; i < tags.size(); ++i) {
        if (i != 0) out += ',';
        out += '"';
        for (char c : tags[i]) {
            if (c == '\\' || c == '"') out += '\\';
            out += c;
        }
        out += '"';
    }
    out += ']';
    return out;
}

}  // namespace

ArtifactEvidenceStore::ArtifactEvidenceStore(std::filesystem::path path) : path_(std::move(path)) {
    if (!path_.parent_path().empty()) std::filesystem::create_directories(path_.parent_path());
    const auto database_path = sqlite_path_utf8(path_);
    if (sqlite3_open_v2(database_path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK)
        throw std::runtime_error("failed to open SQLite DB for artifact evidence: " + std::string(sqlite3_errmsg(db_)));
    sqlite3_busy_timeout(db_, 5000);
    exec("PRAGMA journal_mode=WAL;");
    exec("PRAGMA synchronous=NORMAL;");
    initialize_schema();
}

ArtifactEvidenceStore::~ArtifactEvidenceStore() {
    if (db_) sqlite3_close(db_);
}

void ArtifactEvidenceStore::exec(const char* sql) const {
    char* error = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "SQLite artifact evidence error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

void ArtifactEvidenceStore::initialize_schema() {
    exec(R"SQL(
CREATE TABLE IF NOT EXISTS artifact_evidence_rm4(
 artifact_sha256 TEXT NOT NULL,
 artifact_path TEXT NOT NULL,
 artifact_size INTEGER,
 provider_name TEXT NOT NULL,
 provider_version TEXT NOT NULL DEFAULT '',
 ruleset_id TEXT NOT NULL DEFAULT '',
 ruleset_sha256 TEXT NOT NULL DEFAULT '',
 scan_state TEXT NOT NULL,
 detail TEXT NOT NULL DEFAULT '',
 first_observed_ns INTEGER NOT NULL,
 last_observed_ns INTEGER NOT NULL,
 observation_count INTEGER NOT NULL DEFAULT 1,
 PRIMARY KEY(artifact_sha256,provider_name,ruleset_sha256)
);
CREATE INDEX IF NOT EXISTS idx_artifact_evidence_rm4_recent
 ON artifact_evidence_rm4(last_observed_ns DESC);
CREATE TABLE IF NOT EXISTS artifact_matches_rm4(
 artifact_sha256 TEXT NOT NULL,
 provider_name TEXT NOT NULL,
 ruleset_sha256 TEXT NOT NULL DEFAULT '',
 rule_name TEXT NOT NULL,
 rule_namespace TEXT NOT NULL DEFAULT '',
 tags_json TEXT NOT NULL DEFAULT '[]',
 PRIMARY KEY(artifact_sha256,provider_name,ruleset_sha256,rule_name,rule_namespace)
);
CREATE INDEX IF NOT EXISTS idx_artifact_matches_rm4_rule
 ON artifact_matches_rm4(rule_name,rule_namespace);
)SQL");
}

void ArtifactEvidenceStore::record(const ArtifactIdentity& artifact,
                                   const AntimalwareEvidence& evidence,
                                   std::uint64_t observed_at_ns) {
    if (!artifact.sha256 || artifact.sha256->empty()) return;
    const auto size = artifact.size ? static_cast<sqlite3_int64>(*artifact.size) : 0;
    const std::string path = artifact.path.string();
    const char* state = to_string(evidence.state);

    Statement stmt(db_, R"SQL(
INSERT INTO artifact_evidence_rm4(
 artifact_sha256,artifact_path,artifact_size,provider_name,provider_version,ruleset_id,ruleset_sha256,
 scan_state,detail,first_observed_ns,last_observed_ns,observation_count)
VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
ON CONFLICT(artifact_sha256,provider_name,ruleset_sha256) DO UPDATE SET
 artifact_path=excluded.artifact_path,
 artifact_size=excluded.artifact_size,
 provider_version=excluded.provider_version,
 ruleset_id=excluded.ruleset_id,
 scan_state=excluded.scan_state,
 detail=excluded.detail,
 last_observed_ns=excluded.last_observed_ns,
 observation_count=artifact_evidence_rm4.observation_count+1;
)SQL");
    sqlite3_bind_text(stmt.get(), 1, artifact.sha256->c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, path.c_str(), -1, SQLITE_TRANSIENT);
    if (artifact.size) sqlite3_bind_int64(stmt.get(), 3, size); else sqlite3_bind_null(stmt.get(), 3);
    sqlite3_bind_text(stmt.get(), 4, evidence.provider_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, evidence.provider_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, evidence.ruleset_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, evidence.ruleset_sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 8, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 9, evidence.detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 10, static_cast<sqlite3_int64>(observed_at_ns));
    sqlite3_bind_int64(stmt.get(), 11, static_cast<sqlite3_int64>(observed_at_ns));
    stmt.done();

    for (const auto& match : evidence.matches) {
        Statement match_stmt(db_, R"SQL(
INSERT INTO artifact_matches_rm4(
 artifact_sha256,provider_name,ruleset_sha256,rule_name,rule_namespace,tags_json)
VALUES(?,?,?,?,?,?)
ON CONFLICT(artifact_sha256,provider_name,ruleset_sha256,rule_name,rule_namespace) DO UPDATE SET
 tags_json=excluded.tags_json;
)SQL");
        const auto tags = tags_json(match.tags);
        sqlite3_bind_text(match_stmt.get(), 1, artifact.sha256->c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(match_stmt.get(), 2, evidence.provider_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(match_stmt.get(), 3, evidence.ruleset_sha256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(match_stmt.get(), 4, match.rule_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(match_stmt.get(), 5, match.rule_namespace.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(match_stmt.get(), 6, tags.c_str(), -1, SQLITE_TRANSIENT);
        match_stmt.done();
    }
}

std::vector<StoredArtifactEvidence> ArtifactEvidenceStore::recent(std::size_t limit) const {
    Statement stmt(db_, R"SQL(
SELECT artifact_sha256,artifact_path,coalesce(artifact_size,0),provider_name,provider_version,
       ruleset_id,ruleset_sha256,scan_state,detail,first_observed_ns,last_observed_ns,observation_count
FROM artifact_evidence_rm4 ORDER BY last_observed_ns DESC LIMIT ?;
)SQL");
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(limit));
    std::vector<StoredArtifactEvidence> rows;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        StoredArtifactEvidence row;
        row.artifact_sha256 = text_col(stmt.get(), 0);
        row.artifact_path = text_col(stmt.get(), 1);
        row.artifact_size = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 2));
        row.provider_name = text_col(stmt.get(), 3);
        row.provider_version = text_col(stmt.get(), 4);
        row.ruleset_id = text_col(stmt.get(), 5);
        row.ruleset_sha256 = text_col(stmt.get(), 6);
        row.state = text_col(stmt.get(), 7);
        row.detail = text_col(stmt.get(), 8);
        row.first_observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 9));
        row.last_observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 10));
        row.observation_count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 11));

        Statement matches(db_, R"SQL(
SELECT rule_name,rule_namespace FROM artifact_matches_rm4
WHERE artifact_sha256=? AND provider_name=? AND ruleset_sha256=?
ORDER BY rule_namespace,rule_name;
)SQL");
        sqlite3_bind_text(matches.get(), 1, row.artifact_sha256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(matches.get(), 2, row.provider_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(matches.get(), 3, row.ruleset_sha256.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(matches.get()) == SQLITE_ROW) {
            AntimalwareMatch match;
            match.rule_name = text_col(matches.get(), 0);
            match.rule_namespace = text_col(matches.get(), 1);
            row.matches.push_back(std::move(match));
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

}  // namespace neta
