#include "neta/history_store.hpp"

#include <sqlite3.h>

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

void ensure_schema(sqlite3* db) {
    constexpr const char* sql = R"SQL(
CREATE TABLE IF NOT EXISTS host_identities(
 id INTEGER PRIMARY KEY,
 host_id TEXT NOT NULL UNIQUE,
 hostname TEXT NOT NULL,
 os TEXT NOT NULL,
 architecture TEXT NOT NULL,
 environment_class TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_boots(
 id INTEGER PRIMARY KEY,
 host_identity_id INTEGER NOT NULL,
 boot_id TEXT NOT NULL,
 kernel_release TEXT NOT NULL,
 UNIQUE(host_identity_id,boot_id),
 FOREIGN KEY(host_identity_id) REFERENCES host_identities(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS network_environments(
 id INTEGER PRIMARY KEY,
 host_boot_id INTEGER NOT NULL,
 network_namespace_inode INTEGER,
 interface_index INTEGER,
 interface_name TEXT NOT NULL,
 interface_mac TEXT NOT NULL,
 interface_mtu INTEGER,
 local_address TEXT NOT NULL,
 gateway TEXT NOT NULL,
 preferred_source TEXT NOT NULL,
 route_table INTEGER,
 route_metric INTEGER,
 environment_fingerprint TEXT NOT NULL UNIQUE,
 FOREIGN KEY(host_boot_id) REFERENCES host_boots(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS connection_network_environments(
 connection_id INTEGER PRIMARY KEY,
 network_environment_id INTEGER NOT NULL,
 captured_at_ns INTEGER NOT NULL,
 fidelity TEXT NOT NULL,
 source TEXT NOT NULL,
 FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE,
 FOREIGN KEY(network_environment_id) REFERENCES network_environments(id)
);
CREATE INDEX IF NOT EXISTS idx_connection_network_environment
 ON connection_network_environments(network_environment_id);
)SQL";
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "SQLite error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

std::int64_t select_id(sqlite3* db, const char* sql, const std::string& key) {
    Statement stmt(db, sql);
    sqlite3_bind_text(stmt.get(), 1, key.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) throw std::runtime_error("environment row not found after upsert");
    return sqlite3_column_int64(stmt.get(), 0);
}

EvidenceFidelity fidelity_from_string(const std::string& value) {
    if (value == "EXACT") return EvidenceFidelity::Exact;
    if (value == "SUPPORTING") return EvidenceFidelity::Supporting;
    if (value == "CONTEXTUAL") return EvidenceFidelity::Contextual;
    return EvidenceFidelity::StronglyCorrelated;
}

} // namespace

std::int64_t HistoryStore::add_host_network_environment(
    std::int64_t connection_id, const HostNetworkEnvironmentEvidence& e) {
    ensure_schema(db_);

    Statement host(db_, R"SQL(
INSERT INTO host_identities(host_id,hostname,os,architecture,environment_class)
VALUES(?,?,?,?,?)
ON CONFLICT(host_id) DO UPDATE SET
 hostname=excluded.hostname,os=excluded.os,architecture=excluded.architecture,
 environment_class=excluded.environment_class;
)SQL");
    sqlite3_bind_text(host.get(), 1, e.host_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(host.get(), 2, e.hostname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(host.get(), 3, e.os.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(host.get(), 4, e.architecture.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(host.get(), 5, e.environment_class.c_str(), -1, SQLITE_TRANSIENT);
    host.step_done();
    const auto host_id = select_id(db_, "SELECT id FROM host_identities WHERE host_id=?;", e.host_id);

    Statement boot(db_, R"SQL(
INSERT INTO host_boots(host_identity_id,boot_id,kernel_release)
VALUES(?,?,?)
ON CONFLICT(host_identity_id,boot_id) DO UPDATE SET kernel_release=excluded.kernel_release;
)SQL");
    sqlite3_bind_int64(boot.get(), 1, host_id);
    sqlite3_bind_text(boot.get(), 2, e.boot_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(boot.get(), 3, e.kernel_release.c_str(), -1, SQLITE_TRANSIENT);
    boot.step_done();
    Statement boot_id_stmt(db_, "SELECT id FROM host_boots WHERE host_identity_id=? AND boot_id=?;");
    sqlite3_bind_int64(boot_id_stmt.get(), 1, host_id);
    sqlite3_bind_text(boot_id_stmt.get(), 2, e.boot_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(boot_id_stmt.get()) != SQLITE_ROW) throw std::runtime_error("host boot row not found after upsert");
    const auto boot_row_id = sqlite3_column_int64(boot_id_stmt.get(), 0);

    Statement env(db_, R"SQL(
INSERT INTO network_environments(
 host_boot_id,network_namespace_inode,interface_index,interface_name,interface_mac,
 interface_mtu,local_address,gateway,preferred_source,route_table,route_metric,
 environment_fingerprint)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(environment_fingerprint) DO NOTHING;
)SQL");
    int i = 1;
    sqlite3_bind_int64(env.get(), i++, boot_row_id);
    if (e.network_namespace_inode) sqlite3_bind_int64(env.get(), i, static_cast<sqlite3_int64>(*e.network_namespace_inode)); else sqlite3_bind_null(env.get(), i); ++i;
    if (e.interface_index) sqlite3_bind_int64(env.get(), i, *e.interface_index); else sqlite3_bind_null(env.get(), i); ++i;
    sqlite3_bind_text(env.get(), i++, e.interface_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(env.get(), i++, e.interface_mac.c_str(), -1, SQLITE_TRANSIENT);
    if (e.interface_mtu) sqlite3_bind_int64(env.get(), i, *e.interface_mtu); else sqlite3_bind_null(env.get(), i); ++i;
    sqlite3_bind_text(env.get(), i++, e.local_address.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(env.get(), i++, e.gateway.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(env.get(), i++, e.preferred_source.c_str(), -1, SQLITE_TRANSIENT);
    if (e.route_table) sqlite3_bind_int64(env.get(), i, *e.route_table); else sqlite3_bind_null(env.get(), i); ++i;
    if (e.route_metric) sqlite3_bind_int64(env.get(), i, *e.route_metric); else sqlite3_bind_null(env.get(), i); ++i;
    sqlite3_bind_text(env.get(), i, e.environment_fingerprint.c_str(), -1, SQLITE_TRANSIENT);
    env.step_done();
    const auto environment_id = select_id(
        db_, "SELECT id FROM network_environments WHERE environment_fingerprint=?;",
        e.environment_fingerprint);

    Statement link(db_, R"SQL(
INSERT INTO connection_network_environments(
 connection_id,network_environment_id,captured_at_ns,fidelity,source)
VALUES(?,?,?,?,?)
ON CONFLICT(connection_id) DO UPDATE SET
 network_environment_id=excluded.network_environment_id,
 captured_at_ns=excluded.captured_at_ns,
 fidelity=excluded.fidelity,
 source=excluded.source;
)SQL");
    sqlite3_bind_int64(link.get(), 1, connection_id);
    sqlite3_bind_int64(link.get(), 2, environment_id);
    sqlite3_bind_int64(link.get(), 3, static_cast<sqlite3_int64>(e.captured_at_ns));
    const auto fidelity = to_string(e.fidelity);
    sqlite3_bind_text(link.get(), 4, fidelity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(link.get(), 5, e.source.c_str(), -1, SQLITE_TRANSIENT);
    link.step_done();
    return environment_id;
}

std::optional<HostNetworkEnvironmentEvidence>
HistoryStore::host_network_environment_for_connection(std::int64_t connection_id) const {
    ensure_schema(db_);
    Statement stmt(db_, R"SQL(
SELECT l.captured_at_ns,l.fidelity,l.source,
       h.host_id,h.hostname,h.os,b.boot_id,b.kernel_release,h.architecture,h.environment_class,
       e.network_namespace_inode,e.interface_index,e.interface_name,e.interface_mac,e.interface_mtu,
       e.local_address,e.gateway,e.preferred_source,e.route_table,e.route_metric,e.environment_fingerprint
FROM connection_network_environments l
JOIN network_environments e ON e.id=l.network_environment_id
JOIN host_boots b ON b.id=e.host_boot_id
JOIN host_identities h ON h.id=b.host_identity_id
WHERE l.connection_id=?;
)SQL");
    sqlite3_bind_int64(stmt.get(), 1, connection_id);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return std::nullopt;

    HostNetworkEnvironmentEvidence e;
    e.captured_at_ns = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 0));
    e.fidelity = fidelity_from_string(text_col(stmt.get(), 1));
    e.source = text_col(stmt.get(), 2);
    e.host_id = text_col(stmt.get(), 3);
    e.hostname = text_col(stmt.get(), 4);
    e.os = text_col(stmt.get(), 5);
    e.boot_id = text_col(stmt.get(), 6);
    e.kernel_release = text_col(stmt.get(), 7);
    e.architecture = text_col(stmt.get(), 8);
    e.environment_class = text_col(stmt.get(), 9);
    if (sqlite3_column_type(stmt.get(), 10) != SQLITE_NULL) e.network_namespace_inode = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.get(), 10));
    if (sqlite3_column_type(stmt.get(), 11) != SQLITE_NULL) e.interface_index = static_cast<std::uint32_t>(sqlite3_column_int64(stmt.get(), 11));
    e.interface_name = text_col(stmt.get(), 12);
    e.interface_mac = text_col(stmt.get(), 13);
    if (sqlite3_column_type(stmt.get(), 14) != SQLITE_NULL) e.interface_mtu = static_cast<std::uint32_t>(sqlite3_column_int64(stmt.get(), 14));
    e.local_address = text_col(stmt.get(), 15);
    e.gateway = text_col(stmt.get(), 16);
    e.preferred_source = text_col(stmt.get(), 17);
    if (sqlite3_column_type(stmt.get(), 18) != SQLITE_NULL) e.route_table = static_cast<std::uint32_t>(sqlite3_column_int64(stmt.get(), 18));
    if (sqlite3_column_type(stmt.get(), 19) != SQLITE_NULL) e.route_metric = static_cast<std::uint32_t>(sqlite3_column_int64(stmt.get(), 19));
    e.environment_fingerprint = text_col(stmt.get(), 20);
    return e;
}

} // namespace neta
