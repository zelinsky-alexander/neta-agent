#include "neta/history_store.hpp"

#include "neta/tls_session.hpp"

#include <sqlite3.h>

#include <stdexcept>
#include <string>
#include <utility>

namespace neta {
namespace {

class Statement {
public:
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db));
        }
    }
    ~Statement() { sqlite3_finalize(statement_); }
    sqlite3_stmt* get() const noexcept { return statement_; }
private:
    sqlite3_stmt* statement_{nullptr};
};

void exec_sql(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "SQLite error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

void ensure_tls_session_schema(sqlite3* db) {
    exec_sql(db, R"SQL(
CREATE TABLE IF NOT EXISTS connection_tls_session_evidence(
 id INTEGER PRIMARY KEY,
 connection_id INTEGER NOT NULL,
 observed_ns INTEGER NOT NULL,
 local_role TEXT NOT NULL,
 relation TEXT NOT NULL,
 source TEXT NOT NULL,
 observation_fidelity TEXT NOT NULL,
 correlation_fidelity TEXT NOT NULL,
 pid INTEGER NOT NULL,
 uid INTEGER NOT NULL,
 process_start_ticks INTEGER,
 comm TEXT,
 network_namespace_inode INTEGER,
 socket_cookie INTEGER,
 local_address TEXT NOT NULL,
 local_port INTEGER NOT NULL,
 remote_address TEXT NOT NULL,
 remote_port INTEGER NOT NULL,
 tls_version TEXT NOT NULL,
 cipher TEXT NOT NULL,
 alpn TEXT NOT NULL,
 sni TEXT NOT NULL,
 expected_peer_name TEXT,
 matched_peer_name TEXT,
 peer_certificate_present INTEGER NOT NULL,
 peer_verification_required INTEGER NOT NULL,
 verify_result INTEGER,
 peer_authenticated INTEGER NOT NULL,
 leaf_sha256 TEXT NOT NULL,
 spki_sha256 TEXT NOT NULL,
 subject TEXT NOT NULL,
 issuer TEXT NOT NULL,
 not_before TEXT NOT NULL,
 not_after TEXT NOT NULL,
 session_key TEXT NOT NULL,
 sha256 TEXT NOT NULL,
 UNIQUE(connection_id, session_key),
 FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tls_session_connection
 ON connection_tls_session_evidence(connection_id, observed_ns);
)SQL");
}

std::string text_column(sqlite3_stmt* statement, int column) {
    const auto* value = sqlite3_column_text(statement, column);
    return value ? reinterpret_cast<const char*>(value) : std::string{};
}

std::string sized_text_column(sqlite3_stmt* statement, int column) {
    const auto* value = sqlite3_column_text(statement, column);
    if (!value) return {};
    const auto size = sqlite3_column_bytes(statement, column);
    return std::string(reinterpret_cast<const char*>(value), static_cast<std::size_t>(size));
}

std::optional<std::string> optional_text_column(sqlite3_stmt* statement, int column) {
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) return std::nullopt;
    return text_column(statement, column);
}

std::optional<std::uint64_t> optional_u64_column(sqlite3_stmt* statement, int column) {
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) return std::nullopt;
    return static_cast<std::uint64_t>(sqlite3_column_int64(statement, column));
}

std::optional<std::int64_t> optional_i64_column(sqlite3_stmt* statement, int column) {
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) return std::nullopt;
    return static_cast<std::int64_t>(sqlite3_column_int64(statement, column));
}

EvidenceFidelity fidelity_from_string(const std::string& value) {
    if (value == "EXACT") return EvidenceFidelity::Exact;
    if (value == "STRONGLY_CORRELATED") return EvidenceFidelity::StronglyCorrelated;
    if (value == "SUPPORTING") return EvidenceFidelity::Supporting;
    return EvidenceFidelity::Contextual;
}

void bind_optional_u64(sqlite3_stmt* statement, int index,
                       const std::optional<std::uint64_t>& value) {
    if (value) sqlite3_bind_int64(statement, index, static_cast<sqlite3_int64>(*value));
    else sqlite3_bind_null(statement, index);
}

void bind_optional_i64(sqlite3_stmt* statement, int index,
                       const std::optional<std::int64_t>& value) {
    if (value) sqlite3_bind_int64(statement, index, static_cast<sqlite3_int64>(*value));
    else sqlite3_bind_null(statement, index);
}

void bind_optional_text(sqlite3_stmt* statement, int index,
                        const std::optional<std::string>& value) {
    if (value) sqlite3_bind_text(statement, index, value->c_str(), -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(statement, index);
}

} // namespace

std::int64_t HistoryStore::add_tls_session_evidence(std::int64_t connection_id,
                                                     const TlsSessionEvidence& evidence) {
    ensure_tls_session_schema(db_);
    const auto session_key = tls_session_identity_key(evidence.observation);
    const auto hash = tls_session_evidence_hash(evidence);
    Statement insert(db_, R"SQL(
INSERT OR IGNORE INTO connection_tls_session_evidence(
 connection_id,observed_ns,local_role,relation,source,observation_fidelity,
 correlation_fidelity,pid,uid,process_start_ticks,comm,network_namespace_inode,
 socket_cookie,local_address,local_port,remote_address,remote_port,tls_version,cipher,
 alpn,sni,expected_peer_name,matched_peer_name,peer_certificate_present,
 peer_verification_required,verify_result,peer_authenticated,leaf_sha256,spki_sha256,
 subject,issuer,not_before,not_after,session_key,sha256)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
)SQL");
    int index = 1;
    sqlite3_bind_int64(insert.get(), index++, connection_id);
    sqlite3_bind_int64(insert.get(), index++, static_cast<sqlite3_int64>(evidence.observation.observed_ns));
    const auto role = to_string(evidence.observation.local_role);
    sqlite3_bind_text(insert.get(), index++, role.c_str(), -1, SQLITE_TRANSIENT);
    const auto relation = to_string(evidence.relation);
    sqlite3_bind_text(insert.get(), index++, relation.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.source.c_str(), -1, SQLITE_TRANSIENT);
    const auto observation_fidelity = to_string(evidence.observation.fidelity);
    sqlite3_bind_text(insert.get(), index++, observation_fidelity.c_str(), -1, SQLITE_TRANSIENT);
    const auto correlation_fidelity = to_string(evidence.correlation_fidelity);
    sqlite3_bind_text(insert.get(), index++, correlation_fidelity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(insert.get(), index++, evidence.observation.process.pid);
    sqlite3_bind_int64(insert.get(), index++, static_cast<sqlite3_int64>(evidence.observation.process.uid));
    bind_optional_u64(insert.get(), index++, evidence.observation.process.start_ticks);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.process.comm.c_str(), -1, SQLITE_TRANSIENT);
    bind_optional_u64(insert.get(), index++, evidence.observation.network_namespace_inode);
    bind_optional_u64(insert.get(), index++, evidence.observation.socket_cookie);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.local.address.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(insert.get(), index++, evidence.observation.local.port);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.remote.address.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(insert.get(), index++, evidence.observation.remote.port);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.tls_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.cipher.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.alpn.c_str(),
                      static_cast<int>(evidence.observation.alpn.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.sni.c_str(), -1, SQLITE_TRANSIENT);
    bind_optional_text(insert.get(), index++, evidence.observation.expected_peer_name);
    bind_optional_text(insert.get(), index++, evidence.observation.matched_peer_name);
    sqlite3_bind_int(insert.get(), index++, evidence.observation.peer_certificate_present ? 1 : 0);
    sqlite3_bind_int(insert.get(), index++, evidence.observation.peer_verification_required ? 1 : 0);
    bind_optional_i64(insert.get(), index++, evidence.observation.verify_result);
    sqlite3_bind_int(insert.get(), index++, evidence.observation.peer_authenticated ? 1 : 0);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.leaf_sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.spki_sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.subject.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.issuer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.not_before.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, evidence.observation.not_after.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index++, session_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert.get(), index, hash.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(insert.get()) != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(db_));

    Statement select(db_, R"SQL(
SELECT id FROM connection_tls_session_evidence
WHERE connection_id=? AND session_key=?;
)SQL");
    sqlite3_bind_int64(select.get(), 1, connection_id);
    sqlite3_bind_text(select.get(), 2, session_key.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(select.get()) != SQLITE_ROW) throw std::runtime_error(sqlite3_errmsg(db_));
    return sqlite3_column_int64(select.get(), 0);
}

std::vector<TlsSessionEvidence> HistoryStore::tls_session_evidence_for_connection(
    std::int64_t connection_id) const {
    ensure_tls_session_schema(db_);
    Statement rows(db_, R"SQL(
SELECT observed_ns,local_role,relation,source,observation_fidelity,correlation_fidelity,
 pid,uid,process_start_ticks,comm,network_namespace_inode,socket_cookie,
 local_address,local_port,remote_address,remote_port,tls_version,cipher,alpn,sni,
 expected_peer_name,matched_peer_name,peer_certificate_present,peer_verification_required,
 verify_result,peer_authenticated,leaf_sha256,spki_sha256,subject,issuer,not_before,not_after
FROM connection_tls_session_evidence
WHERE connection_id=? ORDER BY observed_ns,id;
)SQL");
    sqlite3_bind_int64(rows.get(), 1, connection_id);
    std::vector<TlsSessionEvidence> output;
    while (sqlite3_step(rows.get()) == SQLITE_ROW) {
        TlsSessionEvidence evidence;
        auto& observation = evidence.observation;
        observation.observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(rows.get(), 0));
        observation.local_role = tls_session_role_from_string(text_column(rows.get(), 1));
        evidence.relation = tls_session_relation_from_string(text_column(rows.get(), 2));
        observation.source = text_column(rows.get(), 3);
        observation.fidelity = fidelity_from_string(text_column(rows.get(), 4));
        evidence.correlation_fidelity = fidelity_from_string(text_column(rows.get(), 5));
        observation.process.pid = sqlite3_column_int64(rows.get(), 6);
        observation.process.uid = static_cast<std::uint32_t>(sqlite3_column_int64(rows.get(), 7));
        observation.process.start_ticks = optional_u64_column(rows.get(), 8);
        observation.process.comm = text_column(rows.get(), 9);
        observation.network_namespace_inode = optional_u64_column(rows.get(), 10);
        observation.socket_cookie = optional_u64_column(rows.get(), 11);
        observation.local.address = text_column(rows.get(), 12);
        observation.local.port = static_cast<std::uint16_t>(sqlite3_column_int(rows.get(), 13));
        observation.remote.address = text_column(rows.get(), 14);
        observation.remote.port = static_cast<std::uint16_t>(sqlite3_column_int(rows.get(), 15));
        observation.tls_version = text_column(rows.get(), 16);
        observation.cipher = text_column(rows.get(), 17);
        observation.alpn = sized_text_column(rows.get(), 18);
        observation.sni = text_column(rows.get(), 19);
        observation.expected_peer_name = optional_text_column(rows.get(), 20);
        observation.matched_peer_name = optional_text_column(rows.get(), 21);
        observation.peer_certificate_present = sqlite3_column_int(rows.get(), 22) != 0;
        observation.peer_verification_required = sqlite3_column_int(rows.get(), 23) != 0;
        observation.verify_result = optional_i64_column(rows.get(), 24);
        observation.peer_authenticated = sqlite3_column_int(rows.get(), 25) != 0;
        observation.leaf_sha256 = text_column(rows.get(), 26);
        observation.spki_sha256 = text_column(rows.get(), 27);
        observation.subject = text_column(rows.get(), 28);
        observation.issuer = text_column(rows.get(), 29);
        observation.not_before = text_column(rows.get(), 30);
        observation.not_after = text_column(rows.get(), 31);
        output.push_back(std::move(evidence));
    }
    return output;
}

} // namespace neta
