#include "neta/history_store.hpp"

#include <sqlite3.h>

#include <cassert>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

std::filesystem::path database_path() {
    return std::filesystem::temp_directory_path() / "neta-ms3-name-resolution.sqlite";
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

std::int64_t count_rows(sqlite3* db, const char* table) {
    const std::string sql = std::string("SELECT COUNT(*) FROM ") + table + ';';
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }
    const auto rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(sqlite3_errmsg(db));
    }
    const auto count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

neta::NameResolutionEvidence evidence_for_connection() {
    neta::NameResolutionEvidence evidence;
    evidence.observation.started_ns = 100;
    evidence.observation.completed_ns = 200;
    evidence.observation.query_kind = neta::NameResolutionQueryKind::Forward;
    evidence.observation.mechanism = neta::NameResolutionMechanism::ApplicationResolverApi;
    evidence.observation.process.agent_visible.pid = 7000;
    evidence.observation.process.agent_visible.tgid = 7000;
    evidence.observation.process.uid = 1000;
    evidence.observation.process.start_ticks = 88;
    evidence.observation.process.comm = "resolver-client";
    evidence.observation.network_namespace_inode = 55;
    evidence.observation.query_name = "service.example.test";
    evidence.observation.canonical_name = "edge.example.test";
    evidence.observation.addresses.push_back(
        {neta::NetworkAddressFamily::IPv4, "192.0.2.44"});
    evidence.observation.addresses.push_back(
        {neta::NetworkAddressFamily::IPv6, "2001:db8::44"});
    evidence.observation.fidelity = neta::EvidenceFidelity::Exact;
    evidence.observation.source = "deterministic-test-resolver";
    evidence.relation = neta::NameResolutionRelation::ResolvedAddressForOutboundConnection;
    evidence.correlation_fidelity = neta::EvidenceFidelity::StronglyCorrelated;
    return evidence;
}

void round_trip_and_cascade_are_bounded() {
    const auto path = database_path();
    remove_database(path);
    std::int64_t connection_id = 0;
    {
        neta::HistoryStore store(path);
        neta::SocketObservation socket;
        socket.socket_cookie = 99;
        socket.network_namespace_inode = 55;
        socket.local_ip = "192.0.2.10";
        socket.local_port = 45000;
        socket.remote_ip = "192.0.2.44";
        socket.remote_port = 443;

        neta::ProcessIdentity process;
        process.pid = 7000;
        process.uid = 1000;
        process.start_ticks = 88;
        process.comm = "resolver-client";
        connection_id = store.begin_connection(
            socket, process, "", 300, neta::ConnectionDirection::Outbound);

        auto evidence = evidence_for_connection();
        const auto first_id = store.add_name_resolution_evidence(connection_id, evidence);
        assert(first_id > 0);

        evidence.observation.addresses.pop_back();
        const auto updated_id = store.add_name_resolution_evidence(connection_id, evidence);
        assert(updated_id == first_id);

        const auto stored = store.name_resolution_evidence_for_connection(connection_id);
        assert(stored.size() == 1);
        assert(stored.front().observation.query_name == "service.example.test");
        assert(stored.front().observation.canonical_name == "edge.example.test");
        assert(stored.front().observation.process.agent_visible.tgid == 7000);
        assert(stored.front().observation.process.start_ticks == 88);
        assert(stored.front().observation.network_namespace_inode == 55);
        assert(stored.front().observation.addresses.size() == 1);
        assert(stored.front().observation.addresses.front().address == "192.0.2.44");
        assert(stored.front().observation.fidelity == neta::EvidenceFidelity::Exact);
        assert(stored.front().correlation_fidelity ==
               neta::EvidenceFidelity::StronglyCorrelated);
    }

    sqlite3* db = nullptr;
    assert(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    assert(sqlite3_exec(db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr) == SQLITE_OK);
    assert(count_rows(db, "connection_name_resolution_evidence") == 1);
    assert(count_rows(db, "connection_name_resolution_addresses") == 1);
    const std::string remove_connection =
        "DELETE FROM connections WHERE id=" + std::to_string(connection_id) + ';';
    assert(sqlite3_exec(db, remove_connection.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
    assert(count_rows(db, "connection_name_resolution_evidence") == 0);
    assert(count_rows(db, "connection_name_resolution_addresses") == 0);
    assert(sqlite3_close(db) == SQLITE_OK);
    remove_database(path);
}

} // namespace

int main() {
    round_trip_and_cascade_are_bounded();
    std::cout << "HistoryStore name-resolution tests passed\n";
}
