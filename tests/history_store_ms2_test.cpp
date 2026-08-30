#include "neta/history_store.hpp"

#include <sqlite3.h>

#include <cassert>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

std::filesystem::path path_for(const char* name) {
    return std::filesystem::temp_directory_path() /
           (std::string("neta-ms2-history-") + name + ".sqlite");
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void execute(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "SQLite error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

void old_connection_migrates_to_unknown() {
    const auto path = path_for("migration");
    remove_database(path);
    sqlite3* db = nullptr;
    assert(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    execute(db, R"SQL(
CREATE TABLE processes(
 id INTEGER PRIMARY KEY,pid INTEGER NOT NULL,uid INTEGER NOT NULL,
 start_ticks INTEGER NOT NULL,comm TEXT NOT NULL,executable_path TEXT NOT NULL,
 UNIQUE(pid,start_ticks));
CREATE TABLE connections(
 id INTEGER PRIMARY KEY,socket_cookie INTEGER NOT NULL,socket_inode INTEGER NOT NULL,
 process_id INTEGER,local_ip TEXT NOT NULL,local_port INTEGER NOT NULL,
 remote_ip TEXT NOT NULL,remote_port INTEGER NOT NULL,target_host TEXT NOT NULL DEFAULT '',
 lifecycle_state TEXT NOT NULL,first_seen_ns INTEGER NOT NULL,last_seen_ns INTEGER NOT NULL,
 performance_state TEXT NOT NULL DEFAULT 'INSUFFICIENT_EVIDENCE',
 trust_state TEXT NOT NULL DEFAULT 'UNVERIFIED',
 FOREIGN KEY(process_id) REFERENCES processes(id));
INSERT INTO processes VALUES(1,42,1000,123,'legacy','/legacy');
INSERT INTO connections VALUES(1,77,88,1,'127.0.0.1',40000,'127.0.0.2',443,
 'legacy.example','CLOSED',1,2,'NORMAL','STABLE');
)SQL");
    assert(sqlite3_close(db) == SQLITE_OK);
    {
        neta::HistoryStore store(path);
        const auto connection = store.connection(1);
        assert(connection);
        assert(connection->direction == neta::ConnectionDirection::Unknown);
        assert(connection->process.start_ticks == 123);
        assert(!connection->network_namespace_inode);
    }
    {
        neta::HistoryStore reopened(path);
        assert(reopened.connection(1)->direction == neta::ConnectionDirection::Unknown);
    }
    remove_database(path);
}

void direction_and_missing_start_are_preserved() {
    const auto path = path_for("semantics");
    remove_database(path);
    {
        neta::HistoryStore store(path);
        neta::SocketObservation socket;
        socket.socket_cookie = 100;
        socket.local_ip = "127.0.0.1";
        socket.local_port = 443;
        socket.remote_ip = "127.0.0.2";
        socket.remote_port = 50000;
        socket.network_namespace_inode = 42;
        neta::ProcessIdentity process;
        process.pid = 9000;
        process.uid = 1000;
        process.comm = "missing-start";
        const auto id = store.begin_connection(
            socket, process, "", 1, neta::ConnectionDirection::Inbound);
        const auto connection = store.connection(id);
        assert(connection);
        assert(connection->direction == neta::ConnectionDirection::Inbound);
        assert(connection->network_namespace_inode == 42);
        assert(!connection->process.start_ticks);
        process.start_ticks = 0;
        process.comm = "zero-start";
        const auto zero_id = store.begin_connection(
            socket, process, "", 2, neta::ConnectionDirection::Inbound);
        const auto zero_connection = store.connection(zero_id);
        assert(zero_connection);
        assert(!zero_connection->process.start_ticks);
        neta::RouteObservation route;
        route.destination = socket.remote_ip;
        route.relation = neta::RouteRelation::InboundResponseRoute;
        route.sha256 = "route-hash";
        store.add_route(id, route);
        const auto persisted_route = store.route_for_connection(id);
        assert(persisted_route);
        assert(persisted_route->relation == neta::RouteRelation::InboundResponseRoute);
    }
    remove_database(path);
}

} // namespace

int main() {
    old_connection_migrates_to_unknown();
    direction_and_missing_start_are_preserved();
    std::cout << "HistoryStore MS2 tests passed\n";
}
