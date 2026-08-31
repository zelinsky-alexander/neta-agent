#include "neta/history_store.hpp"

#include <sqlite3.h>

#include <cassert>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

std::filesystem::path database_path() {
    return std::filesystem::temp_directory_path() / "neta-ms3-tls-session.sqlite";
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

std::int64_t count_rows(sqlite3* db, const char* table) {
    const std::string sql = std::string("SELECT COUNT(*) FROM ") + table + ';';
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }
    assert(sqlite3_step(statement) == SQLITE_ROW);
    const auto count = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return count;
}

neta::TlsSessionEvidence evidence() {
    neta::TlsSessionEvidence value;
    auto& observation = value.observation;
    observation.observed_ns = 5'000;
    observation.local_role = neta::TlsSessionRole::Client;
    observation.process.pid = 42;
    observation.process.uid = 1000;
    observation.process.start_ticks = 88;
    observation.process.comm = "tls-client";
    observation.network_namespace_inode = 77;
    observation.socket_cookie = 900;
    observation.local = {"192.0.2.10", 45000};
    observation.remote = {"203.0.113.20", 443};
    observation.tls_version = "TLSv1.3";
    observation.cipher = "TLS_AES_256_GCM_SHA384";
    observation.alpn = "h2";
    observation.sni = "api.example.test";
    observation.expected_peer_name = "api.example.test";
    observation.matched_peer_name = "api.example.test";
    observation.peer_certificate_present = true;
    observation.peer_verification_required = true;
    observation.verify_result = 0;
    observation.peer_authenticated = true;
    observation.leaf_sha256 = "leaf";
    observation.spki_sha256 = "spki";
    observation.subject = "CN=api.example.test";
    observation.issuer = "CN=test-ca";
    observation.not_before = "Aug 30 00:00:00 2026 GMT";
    observation.not_after = "Aug 31 00:00:00 2026 GMT";
    observation.fidelity = neta::EvidenceFidelity::Exact;
    observation.source = "openssl3:application-shim";
    value.relation = neta::TlsSessionRelation::OutboundServerIdentity;
    value.correlation_fidelity = neta::EvidenceFidelity::Exact;
    return value;
}

void round_trip_idempotence_and_cascade() {
    const auto path = database_path();
    remove_database(path);
    std::int64_t connection_id = 0;
    {
        neta::HistoryStore store(path);
        neta::SocketObservation socket;
        socket.socket_cookie = 900;
        socket.network_namespace_inode = 77;
        socket.local_ip = "192.0.2.10";
        socket.local_port = 45000;
        socket.remote_ip = "203.0.113.20";
        socket.remote_port = 443;
        neta::ProcessIdentity process;
        process.pid = 42;
        process.uid = 1000;
        process.start_ticks = 88;
        process.comm = "tls-client";
        connection_id = store.begin_connection(
            socket, process, "api.example.test", 1'000,
            neta::ConnectionDirection::Outbound);

        const auto first = store.add_tls_session_evidence(connection_id, evidence());
        const auto second = store.add_tls_session_evidence(connection_id, evidence());
        assert(first == second);
        const auto stored = store.tls_session_evidence_for_connection(connection_id);
        assert(stored.size() == 1);
        const auto& item = stored.front();
        assert(item.observation.local_role == neta::TlsSessionRole::Client);
        assert(item.relation == neta::TlsSessionRelation::OutboundServerIdentity);
        assert(item.correlation_fidelity == neta::EvidenceFidelity::Exact);
        assert(item.observation.socket_cookie == 900);
        assert(item.observation.spki_sha256 == "spki");
        assert(item.observation.expected_peer_name == "api.example.test");
        assert(item.observation.matched_peer_name == "api.example.test");
        assert(item.observation.peer_authenticated);
        assert(item.observation.verify_result == 0);
    }

    sqlite3* db = nullptr;
    assert(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    assert(sqlite3_exec(db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr) == SQLITE_OK);
    assert(count_rows(db, "connection_tls_session_evidence") == 1);
    const std::string remove = "DELETE FROM connections WHERE id=" +
                               std::to_string(connection_id) + ';';
    assert(sqlite3_exec(db, remove.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
    assert(count_rows(db, "connection_tls_session_evidence") == 0);
    assert(sqlite3_close(db) == SQLITE_OK);
    remove_database(path);
}

} // namespace

int main() {
    round_trip_idempotence_and_cascade();
    std::cout << "HistoryStore TLS session tests passed\n";
}
