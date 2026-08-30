#include "neta/history_store.hpp"

#include "neta/crypto.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace neta {
namespace {

class Statement {
public:
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db));
        }
    }
    ~Statement() { sqlite3_finalize(stmt_); }

    sqlite3_stmt* get() const noexcept { return stmt_; }

private:
    sqlite3_stmt* stmt_{nullptr};
};

void exec_sql(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "SQLite error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

void ensure_name_resolution_schema(sqlite3* db) {
    exec_sql(db, R"SQL(
CREATE TABLE IF NOT EXISTS connection_name_resolution_evidence(
 id INTEGER PRIMARY KEY,
 connection_id INTEGER NOT NULL,
 started_ns INTEGER NOT NULL,
 completed_ns INTEGER NOT NULL,
 query_kind TEXT NOT NULL,
 mechanism TEXT NOT NULL,
 query_name TEXT NOT NULL,
 canonical_name TEXT,
 source TEXT NOT NULL,
 observation_fidelity TEXT NOT NULL,
 correlation_fidelity TEXT NOT NULL,
 relation TEXT NOT NULL,
 agent_pid INTEGER,
 agent_tgid INTEGER,
 kernel_pid INTEGER,
 kernel_tgid INTEGER,
 uid INTEGER,
 process_start_ticks INTEGER,
 comm TEXT,
 network_namespace_inode INTEGER,
 sha256 TEXT NOT NULL,
 UNIQUE(connection_id,completed_ns,query_name,source,relation),
 FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_name_resolution_connection
 ON connection_name_resolution_evidence(connection_id,completed_ns);
CREATE TABLE IF NOT EXISTS connection_name_resolution_addresses(
 evidence_id INTEGER NOT NULL,
 address_family INTEGER NOT NULL,
 address TEXT NOT NULL,
 PRIMARY KEY(evidence_id,address_family,address),
 FOREIGN KEY(evidence_id) REFERENCES connection_name_resolution_evidence(id) ON DELETE CASCADE
);
)SQL");
}

std::string text_column(sqlite3_stmt* stmt, int column) {
    const auto* value = sqlite3_column_text(stmt, column);
    return value ? reinterpret_cast<const char*>(value) : std::string{};
}

EvidenceFidelity fidelity_from_string(const std::string& value) {
    if (value == "EXACT") return EvidenceFidelity::Exact;
    if (value == "STRONGLY_CORRELATED") return EvidenceFidelity::StronglyCorrelated;
    if (value == "SUPPORTING") return EvidenceFidelity::Supporting;
    return EvidenceFidelity::Contextual;
}

std::string evidence_hash(const NameResolutionEvidence& evidence) {
    std::vector<std::string> addresses;
    addresses.reserve(evidence.observation.addresses.size());
    for (const auto& address : evidence.observation.addresses) {
        addresses.push_back(std::to_string(static_cast<int>(address.family)) + ":" + address.address);
    }
    std::sort(addresses.begin(), addresses.end());

    std::string material = std::to_string(evidence.observation.started_ns) + "|" +
        std::to_string(evidence.observation.completed_ns) + "|" +
        to_string(evidence.observation.query_kind) + "|" +
        to_string(evidence.observation.mechanism) + "|" + evidence.observation.query_name + "|" +
        evidence.observation.canonical_name.value_or("") + "|" + evidence.observation.source + "|" +
        to_string(evidence.observation.fidelity) + "|" + to_string(evidence.correlation_fidelity) + "|" +
        to_string(evidence.relation) + "|";
    if (evidence.observation.process.agent_visible.pid) {
        material += std::to_string(*evidence.observation.process.agent_visible.pid);
    }
    material += "|";
    if (evidence.observation.process.agent_visible.tgid) {
        material += std::to_string(*evidence.observation.process.agent_visible.tgid);
    }
    material += "|";
    if (evidence.observation.process.start_ticks) {
        material += std::to_string(*evidence.observation.process.start_ticks);
    }
    material += "|";
    if (evidence.observation.network_namespace_inode) {
        material += std::to_string(*evidence.observation.network_namespace_inode);
    }
    for (const auto& address : addresses) material += "|" + address;
    return sha256_hex(material);
}

void bind_optional_int64(sqlite3_stmt* stmt, int index, const std::optional<std::int64_t>& value) {
    if (value) sqlite3_bind_int64(stmt, index, static_cast<sqlite3_int64>(*value));
    else sqlite3_bind_null(stmt, index);
}

void bind_optional_u64(sqlite3_stmt* stmt, int index, const std::optional<std::uint64_t>& value) {
    if (value) sqlite3_bind_int64(stmt, index, static_cast<sqlite3_int64>(*value));
    else sqlite3_bind_null(stmt, index);
}

void bind_optional_u32(sqlite3_stmt* stmt, int index, const std::optional<std::uint32_t>& value) {
    if (value) sqlite3_bind_int64(stmt, index, static_cast<sqlite3_int64>(*value));
    else sqlite3_bind_null(stmt, index);
}

void bind_optional_text(sqlite3_stmt* stmt, int index, const std::optional<std::string>& value) {
    if (value) sqlite3_bind_text(stmt, index, value->c_str(), -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, index);
}

std::optional<std::int64_t> optional_i64_column(sqlite3_stmt* stmt, int column) {
    if (sqlite3_column_type(stmt, column) == SQLITE_NULL) return std::nullopt;
    return sqlite3_column_int64(stmt, column);
}

std::optional<std::uint64_t> optional_u64_column(sqlite3_stmt* stmt, int column) {
    if (sqlite3_column_type(stmt, column) == SQLITE_NULL) return std::nullopt;
    return static_cast<std::uint64_t>(sqlite3_column_int64(stmt, column));
}

std::optional<std::uint32_t> optional_u32_column(sqlite3_stmt* stmt, int column) {
    if (sqlite3_column_type(stmt, column) == SQLITE_NULL) return std::nullopt;
    return static_cast<std::uint32_t>(sqlite3_column_int64(stmt, column));
}

std::optional<std::string> optional_text_column(sqlite3_stmt* stmt, int column) {
    if (sqlite3_column_type(stmt, column) == SQLITE_NULL) return std::nullopt;
    return text_column(stmt, column);
}

} // namespace

std::int64_t HistoryStore::add_name_resolution_evidence(
    std::int64_t connection_id,
    const NameResolutionEvidence& evidence) {
    ensure_name_resolution_schema(db_);
    Statement insert(db_, R"SQL(
INSERT INTO connection_name_resolution_evidence(
 connection_id,started_ns,completed_ns,query_kind,mechanism,query_name,canonical_name,source,
 observation_fidelity,correlation_fidelity,relation,agent_pid,agent_tgid,kernel_pid,kernel_tgid,
 uid,process_start_ticks,comm,network_namespace_inode,sha256)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(connection_id,completed_ns,query_name,source,relation) DO UPDATE SET
 started_ns=excluded.started_ns,
 query_kind=excluded.query_kind,
 mechanism=excluded.mechanism,
 canonical_name=excluded.canonical_name,
 observation_fidelity=excluded.observation_fidelity,
 correlation_fidelity=excluded.correlation_fidelity,
 agent_pid=excluded.agent_pid,
 agent_tgid=excluded.agent_tgid,
 kernel_pid=excluded.kernel_pid,
 kernel_tgid=excluded.kernel_tgid,
 uid=excluded.uid,
 process_start_ticks=excluded.process_start_ticks,
 comm=excluded.comm,
 network_namespace_inode=excluded.network_namespace_inode,
 sha256=excluded.sha256
RETURNING id;
)SQL");
    int index = 1;
    sqlite3_bind_int64(insert.get(), index++, connection_id);
    sqlite3_bind_int64(insert.get(), index++, static_cast<sqlite3_int64>(evidence.observation.started_ns));
    sqlite3_bind_int64(insert.get(), index++, static_cast<sqlite3_int64>(evidence.observation.completed_ns));
    const auto query_kind = to_string(evidence.observation.query_kind);
    sqlite3_bind_text(insert.get(), index++, query_kind.c_str(), -1, SQLITE_TRANSIENT);
    const auto mechanism = to_string(evidence.observation.mechanism);
    sqlite3_bind_text(insert.get(), index++, mechanism.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.query_name.c_str(), -1, SQLITE_TRANSIENT);
    bind_optional_text(insert.get(), index++, evidence.observation.canonical_name);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.source.c_str(), -1, SQLITE_TRANSIENT);
    const auto observation_fidelity = to_string(evidence.observation.fidelity);
    sqlite3_bind_text(insert.get(), index++, observation_fidelity.c_str(), -1, SQLITE_TRANSIENT);
    const auto link_fidelity = to_string(evidence.correlation_fidelity);
    sqlite3_bind_text(insert.get(), index++, link_fidelity.c_str(), -1, SQLITE_TRANSIENT);
    const auto relation = to_string(evidence.relation);
    sqlite3_bind_text(insert.get(), index++, relation.c_str(), -1, SQLITE_TRANSIENT);
    bind_optional_int64(insert.get(), index++, evidence.observation.process.agent_visible.pid);
    bind_optional_int64(insert.get(), index++, evidence.observation.process.agent_visible.tgid);
    bind_optional_int64(insert.get(), index++, evidence.observation.process.kernel.pid);
    bind_optional_int64(insert.get(), index++, evidence.observation.process.kernel.tgid);
    bind_optional_u32(insert.get(), index++, evidence.observation.process.uid);
    bind_optional_u64(insert.get(), index++, evidence.observation.process.start_ticks);
    bind_optional_text(insert.get(), index++, evidence.observation.process.comm);
    bind_optional_u64(insert.get(), index++, evidence.observation.network_namespace_inode);
    const auto hash = evidence_hash(evidence);
    sqlite3_bind_text(insert.get(), index, hash.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(insert.get()) != SQLITE_ROW) throw std::runtime_error(sqlite3_errmsg(db_));
    const auto evidence_id = sqlite3_column_int64(insert.get(), 0);

    Statement clear_addresses(db_,
        "DELETE FROM connection_name_resolution_addresses WHERE evidence_id=?;");
    sqlite3_bind_int64(clear_addresses.get(), 1, evidence_id);
    if (sqlite3_step(clear_addresses.get()) != SQLITE_DONE) {
        throw std::runtime_error(sqlite3_errmsg(db_));
    }

    for (const auto& address : evidence.observation.addresses) {
        Statement address_insert(db_, R"SQL(
INSERT OR IGNORE INTO connection_name_resolution_addresses(evidence_id,address_family,address)
VALUES(?,?,?);
)SQL");
        sqlite3_bind_int64(address_insert.get(), 1, evidence_id);
        sqlite3_bind_int(address_insert.get(), 2, static_cast<int>(address.family));
        sqlite3_bind_text(address_insert.get(), 3, address.address.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(address_insert.get()) != SQLITE_DONE) {
            throw std::runtime_error(sqlite3_errmsg(db_));
        }
    }
    return evidence_id;
}

std::vector<NameResolutionEvidence> HistoryStore::name_resolution_evidence_for_connection(
    std::int64_t connection_id) const {
    ensure_name_resolution_schema(db_);
    Statement rows(db_, R"SQL(
SELECT id,started_ns,completed_ns,query_kind,mechanism,query_name,canonical_name,source,
 observation_fidelity,correlation_fidelity,relation,agent_pid,agent_tgid,kernel_pid,kernel_tgid,
 uid,process_start_ticks,comm,network_namespace_inode
FROM connection_name_resolution_evidence
WHERE connection_id=?
ORDER BY completed_ns,id;
)SQL");
    sqlite3_bind_int64(rows.get(), 1, connection_id);
    std::vector<NameResolutionEvidence> output;
    while (sqlite3_step(rows.get()) == SQLITE_ROW) {
        const auto evidence_id = sqlite3_column_int64(rows.get(), 0);
        NameResolutionEvidence evidence;
        evidence.observation.started_ns = static_cast<std::uint64_t>(sqlite3_column_int64(rows.get(), 1));
        evidence.observation.completed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(rows.get(), 2));
        evidence.observation.query_kind = name_resolution_query_kind_from_string(text_column(rows.get(), 3));
        evidence.observation.mechanism = name_resolution_mechanism_from_string(text_column(rows.get(), 4));
        evidence.observation.query_name = text_column(rows.get(), 5);
        evidence.observation.canonical_name = optional_text_column(rows.get(), 6);
        evidence.observation.source = text_column(rows.get(), 7);
        evidence.observation.fidelity = fidelity_from_string(text_column(rows.get(), 8));
        evidence.correlation_fidelity = fidelity_from_string(text_column(rows.get(), 9));
        evidence.relation = name_resolution_relation_from_string(text_column(rows.get(), 10));
        evidence.observation.process.agent_visible.pid = optional_i64_column(rows.get(), 11);
        evidence.observation.process.agent_visible.tgid = optional_i64_column(rows.get(), 12);
        evidence.observation.process.kernel.pid = optional_i64_column(rows.get(), 13);
        evidence.observation.process.kernel.tgid = optional_i64_column(rows.get(), 14);
        evidence.observation.process.uid = optional_u32_column(rows.get(), 15);
        evidence.observation.process.start_ticks = optional_u64_column(rows.get(), 16);
        evidence.observation.process.comm = optional_text_column(rows.get(), 17);
        evidence.observation.network_namespace_inode = optional_u64_column(rows.get(), 18);

        Statement addresses(db_, R"SQL(
SELECT address_family,address
FROM connection_name_resolution_addresses
WHERE evidence_id=?
ORDER BY address_family,address;
)SQL");
        sqlite3_bind_int64(addresses.get(), 1, evidence_id);
        while (sqlite3_step(addresses.get()) == SQLITE_ROW) {
            NameResolutionAddress address;
            address.family = static_cast<NetworkAddressFamily>(sqlite3_column_int(addresses.get(), 0));
            address.address = text_column(addresses.get(), 1);
            evidence.observation.addresses.push_back(std::move(address));
        }
        output.push_back(std::move(evidence));
    }
    return output;
}

} // namespace neta
