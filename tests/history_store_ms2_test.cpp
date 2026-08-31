#include "neta/history_store.hpp"

#include <sqlite3.h>

#include <cassert>
#include <chrono>
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

std::int64_t scalar_count(const std::filesystem::path& path, const char* sql) {
    sqlite3* db = nullptr;
    assert(sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    assert(sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK);
    assert(sqlite3_step(stmt) == SQLITE_ROW);
    const auto result = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    assert(sqlite3_close(db) == SQLITE_OK);
    return result;
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
        assert(!connection->captured_at_ns);
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
        constexpr std::uint64_t first_seen_ns = 1;
        const auto before_capture = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const auto id = store.begin_connection(
            socket, process, "", first_seen_ns, neta::ConnectionDirection::Inbound);
        const auto after_capture = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const auto connection = store.connection(id);
        assert(connection);
        assert(connection->first_seen_ns == first_seen_ns);
        assert(connection->last_seen_ns == first_seen_ns);
        assert(connection->captured_at_ns);
        const auto captured_at_ns = *connection->captured_at_ns;
        assert(captured_at_ns >= before_capture);
        assert(captured_at_ns <= after_capture);
        store.touch_connection(id, 999, "CLOSED");
        const auto touched = store.connection(id);
        assert(touched);
        assert(touched->first_seen_ns == first_seen_ns);
        assert(touched->last_seen_ns == 999);
        assert(touched->captured_at_ns == captured_at_ns);
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

void host_network_environment_roundtrip_and_dedup() {
    const auto path = path_for("environment");
    remove_database(path);
    {
        neta::HistoryStore store(path);
        neta::SocketObservation socket;
        socket.socket_cookie = 700;
        socket.local_ip = "10.0.0.10";
        socket.local_port = 41000;
        socket.remote_ip = "203.0.113.10";
        socket.remote_port = 443;
        socket.network_namespace_inode = 1001;

        const auto first = store.begin_connection(
            socket, std::nullopt, "example.test", 10,
            neta::ConnectionDirection::Outbound);
        socket.socket_cookie = 701;
        socket.local_port = 41001;
        const auto second = store.begin_connection(
            socket, std::nullopt, "example.test", 11,
            neta::ConnectionDirection::Outbound);

        neta::HostNetworkEnvironmentEvidence environment;
        environment.captured_at_ns = 123456;
        environment.fidelity = neta::EvidenceFidelity::StronglyCorrelated;
        environment.source = "test:host-network-environment";
        environment.host_id = "host-hash";
        environment.hostname = "host-a";
        environment.os = "Linux";
        environment.boot_id = "boot-a";
        environment.kernel_release = "6.test";
        environment.architecture = "x86_64";
        environment.environment_class = "LINUX_HOST";
        environment.network_namespace_inode = 1001;
        environment.interface_index = 2;
        environment.interface_name = "eth0";
        environment.interface_mac = "00:11:22:33:44:55";
        environment.interface_mtu = 1500;
        environment.local_address = "10.0.0.10";
        environment.gateway = "10.0.0.1";
        environment.preferred_source = "10.0.0.10";
        environment.route_table = 254;
        environment.route_metric = 100;
        environment.environment_fingerprint = "environment-a";

        const auto env_one = store.add_host_network_environment(first, environment);
        environment.captured_at_ns = 123457;
        const auto env_two = store.add_host_network_environment(second, environment);
        assert(env_one == env_two);

        const auto restored = store.host_network_environment_for_connection(second);
        assert(restored);
        assert(restored->captured_at_ns == 123457);
        assert(restored->fidelity == neta::EvidenceFidelity::StronglyCorrelated);
        assert(restored->source == "test:host-network-environment");
        assert(restored->host_id == "host-hash");
        assert(restored->hostname == "host-a");
        assert(restored->boot_id == "boot-a");
        assert(restored->kernel_release == "6.test");
        assert(restored->architecture == "x86_64");
        assert(restored->network_namespace_inode == 1001);
        assert(restored->interface_index == 2);
        assert(restored->interface_name == "eth0");
        assert(restored->interface_mac == "00:11:22:33:44:55");
        assert(restored->interface_mtu == 1500);
        assert(restored->local_address == "10.0.0.10");
        assert(restored->gateway == "10.0.0.1");
        assert(restored->preferred_source == "10.0.0.10");
        assert(restored->route_table == 254);
        assert(restored->route_metric == 100);
        assert(restored->environment_fingerprint == "environment-a");

        socket.socket_cookie = 702;
        socket.local_port = 41002;
        socket.network_namespace_inode = 2002;
        const auto third = store.begin_connection(
            socket, std::nullopt, "example.test", 12,
            neta::ConnectionDirection::Outbound);
        environment.captured_at_ns = 123458;
        environment.network_namespace_inode = 2002;
        environment.interface_index = 7;
        environment.interface_name = "veth-test";
        environment.interface_mac = "66:55:44:33:22:11";
        environment.local_address = "10.200.1.2";
        environment.gateway.clear();
        environment.preferred_source = "10.200.1.2";
        environment.route_metric.reset();
        environment.environment_fingerprint = "environment-b";
        const auto env_three = store.add_host_network_environment(third, environment);
        assert(env_three != env_one);
    }

    assert(scalar_count(path, "SELECT COUNT(*) FROM connections;") == 3);
    assert(scalar_count(path, "SELECT COUNT(*) FROM host_identities;") == 1);
    assert(scalar_count(path, "SELECT COUNT(*) FROM host_boots;") == 1);
    assert(scalar_count(path, "SELECT COUNT(*) FROM network_environments;") == 2);
    assert(scalar_count(path, "SELECT COUNT(*) FROM connection_network_environments;") == 3);
    remove_database(path);
}

} // namespace

int main() {
    old_connection_migrates_to_unknown();
    direction_and_missing_start_are_preserved();
    host_network_environment_roundtrip_and_dedup();
    std::cout << "HistoryStore MS2/MS3.4 tests passed\n";
}
