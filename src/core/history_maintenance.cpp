#include "neta/history_store.hpp"

#include <sqlite3.h>

#include <filesystem>
#include <stdexcept>

namespace neta {
namespace {

class Statement {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db));
        }
    }
    ~Statement() { sqlite3_finalize(statement_); }
    sqlite3_stmt* get() const { return statement_; }
    void step_done() {
        if (sqlite3_step(statement_) != SQLITE_DONE) {
            throw std::runtime_error(sqlite3_errmsg(db_));
        }
    }
private:
    sqlite3* db_;
    sqlite3_stmt* statement_{nullptr};
};

std::uint64_t file_size_or_zero(const std::filesystem::path& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    return error ? 0 : static_cast<std::uint64_t>(size);
}

std::uint64_t sqlite_total_size(const std::filesystem::path& path) {
    return file_size_or_zero(path) + file_size_or_zero(path.string() + "-wal");
}

int auto_vacuum_mode(sqlite3* db) {
    Statement statement(db, "PRAGMA auto_vacuum;");
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }
    return sqlite3_column_int(statement.get(), 0);
}

void prune_orphans(sqlite3* db) {
    Statement processes(db, R"SQL(
DELETE FROM processes
WHERE NOT EXISTS (
    SELECT 1 FROM connections WHERE connections.process_id = processes.id
);
)SQL");
    processes.step_done();

    Statement tls(db, R"SQL(
DELETE FROM tls_observations
WHERE NOT EXISTS (
    SELECT 1 FROM verdicts WHERE verdicts.tls_observation_id = tls_observations.id
)
AND NOT EXISTS (
    SELECT 1 FROM connection_tls_observations
    WHERE connection_tls_observations.tls_observation_id = tls_observations.id
);
)SQL");
    tls.step_done();

    Statement baselines(db, R"SQL(
DELETE FROM baselines AS candidate
WHERE NOT EXISTS (
    SELECT 1 FROM verdicts WHERE verdicts.baseline_hash = candidate.sha256
)
AND EXISTS (
    SELECT 1 FROM baselines AS newer
    WHERE newer.target_host = candidate.target_host
      AND newer.target_port = candidate.target_port
      AND (newer.created_ns > candidate.created_ns
           OR (newer.created_ns = candidate.created_ns AND newer.id > candidate.id))
);
)SQL");
    baselines.step_done();
}

} // namespace

StorageStatus HistoryStore::status(std::uint64_t max_bytes) const {
    StorageStatus status;
    status.path = path_;
    status.bytes = sqlite_total_size(path_);
    status.max_bytes = max_bytes;
    Statement connections(db_, "SELECT COUNT(*) FROM connections;");
    if (sqlite3_step(connections.get()) == SQLITE_ROW) {
        status.connection_count = static_cast<std::uint64_t>(
            sqlite3_column_int64(connections.get(), 0));
    }
    Statement samples(db_, "SELECT COUNT(*) FROM transport_samples;");
    if (sqlite3_step(samples.get()) == SQLITE_ROW) {
        status.sample_count = static_cast<std::uint64_t>(
            sqlite3_column_int64(samples.get(), 0));
    }
    return status;
}

void HistoryStore::prune_to_budget(std::uint64_t max_bytes) {
    if (max_bytes == 0) return;
    auto bytes = sqlite_total_size(path_);
    if (bytes <= max_bytes) return;
    const auto target_bytes = max_bytes - (max_bytes / 10ULL);

    exec("PRAGMA wal_checkpoint(TRUNCATE);");
    bytes = sqlite_total_size(path_);
    if (bytes <= target_bytes) return;

    const auto compact_and_measure = [&]() {
        prune_orphans(db_);
        if (auto_vacuum_mode(db_) == 2) {
            exec("PRAGMA incremental_vacuum;");
        } else {
            exec("PRAGMA auto_vacuum=INCREMENTAL;");
            exec("VACUUM;");
        }
        exec("PRAGMA wal_checkpoint(TRUNCATE);");
        return sqlite_total_size(path_);
    };

    bytes = compact_and_measure();
    while (bytes > target_bytes) {
        Statement normal(db_, R"SQL(
DELETE FROM connections
WHERE id IN (
    SELECT id FROM connections
    WHERE performance_state NOT IN ('DEGRADED','FAILED')
      AND trust_state NOT IN ('CHANGED','SUSPICIOUS')
    ORDER BY first_seen_ns ASC,id ASC LIMIT 64
);
)SQL");
        normal.step_done();
        int removed = sqlite3_changes(db_);
        if (removed == 0) {
            Statement anomalous(db_, R"SQL(
DELETE FROM connections
WHERE id IN (
    SELECT id FROM connections
    WHERE performance_state IN ('DEGRADED','FAILED')
       OR trust_state IN ('CHANGED','SUSPICIOUS')
    ORDER BY first_seen_ns ASC,id ASC LIMIT 8
);
)SQL");
            anomalous.step_done();
            removed = sqlite3_changes(db_);
        }
        if (removed == 0) break;
        bytes = compact_and_measure();
    }
    if (bytes > max_bytes) {
        throw std::runtime_error("SQLite history cannot satisfy configured storage cap");
    }
}

} // namespace neta
