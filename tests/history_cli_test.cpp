#include "neta/history_store.hpp"

#include <sqlite3.h>

#include <cassert>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace {

constexpr std::uint64_t kOlderFirstSeenNs = 1'704'067'200'000'000'000ULL;
constexpr std::uint64_t kNewerFirstSeenNs = 1'704'153'600'000'000'000ULL;

std::filesystem::path test_path(const char* name) {
    return std::filesystem::temp_directory_path() / (std::string("neta-history-cli-") + name);
}

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void clear_capture_time(const std::filesystem::path& path, std::int64_t id) {
    sqlite3* db = nullptr;
    assert(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    const auto sql = "UPDATE connections SET captured_at_ns=NULL WHERE id=" +
                     std::to_string(id) + ";";
    assert(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
    assert(sqlite3_close(db) == SQLITE_OK);
}

std::string format_capture_time(std::uint64_t timestamp_ns, bool include_timezone) {
    const auto timestamp = static_cast<std::time_t>(timestamp_ns / 1'000'000'000ULL);
    std::tm local{};
    localtime_r(&timestamp, &local);
    std::ostringstream out;
    out << std::put_time(&local, include_timezone ? "%Y-%m-%dT%H:%M:%S%z"
                                                  : "%Y-%m-%d %H:%M:%S");
    auto formatted = out.str();
    if (include_timezone && formatted.size() >= 5) {
        formatted.insert(formatted.size() - 2, ":");
    }
    return formatted;
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

std::string shell_quote(const std::filesystem::path& path) {
    return "'" + path.string() + "'";
}

std::int64_t add_connection(neta::HistoryStore& store, std::uint64_t cookie,
                            std::uint64_t first_seen_ns) {
    neta::SocketObservation socket;
    socket.socket_cookie = cookie;
    socket.local_ip = "127.0.0.1";
    socket.local_port = 40000;
    socket.remote_ip = "192.0.2.1";
    socket.remote_port = 443;
    neta::ProcessIdentity process;
    process.pid = 42;
    process.comm = "history-test";
    return store.begin_connection(socket, process, "example.test", first_seen_ns,
                                  neta::ConnectionDirection::Outbound);
}

void history_output_includes_capture_time(const char* binary) {
    const auto database = test_path("database.sqlite");
    const auto output = test_path("output.txt");
    remove_database(database);
    std::optional<std::uint64_t> newer_capture_ns;
    {
        neta::HistoryStore store(database);
        add_connection(store, 1, kOlderFirstSeenNs);
        const auto newer_id = add_connection(store, 2, kNewerFirstSeenNs);
        newer_capture_ns = store.connection(newer_id)->captured_at_ns;
    }
    assert(newer_capture_ns);

    const auto command_prefix = shell_quote(binary) + " history --db " + shell_quote(database);
    assert(std::system((command_prefix + " > " + shell_quote(output)).c_str()) == 0);
    const auto table = read_file(output);
    assert(table.find("CAPTURED") != std::string::npos);
    assert(table.find(format_capture_time(*newer_capture_ns, false)) != std::string::npos);
    assert(table.find("CONN-2") < table.find("CONN-1"));

    assert(std::system((command_prefix + " --json > " + shell_quote(output)).c_str()) == 0);
    const auto list_json = read_file(output);
    const auto newer_json_time = "\"captured_at\":\"" +
                                 format_capture_time(*newer_capture_ns, true) + "\"";
    assert(list_json.find(newer_json_time) != std::string::npos);
    assert(list_json.find("\"id\":2") < list_json.find("\"id\":1"));

    assert(std::system((shell_quote(binary) + " history show 2 --db " + shell_quote(database) +
                        " > " + shell_quote(output)).c_str()) == 0);
    assert(read_file(output).find("Captured: " + format_capture_time(*newer_capture_ns, false)) !=
           std::string::npos);

    assert(std::system((shell_quote(binary) + " history show 2 --db " + shell_quote(database) +
                        " --json > " + shell_quote(output)).c_str()) == 0);
    assert(read_file(output).find(newer_json_time) != std::string::npos);

    clear_capture_time(database, 2);
    assert(std::system((command_prefix + " > " + shell_quote(output)).c_str()) == 0);
    assert(read_file(output).find("-                    OUTBOUND") != std::string::npos);

    assert(std::system((command_prefix + " --json > " + shell_quote(output)).c_str()) == 0);
    assert(read_file(output).find("\"captured_at\":\"UNKNOWN\"") != std::string::npos);

    assert(std::system((shell_quote(binary) + " history show 2 --db " + shell_quote(database) +
                        " > " + shell_quote(output)).c_str()) == 0);
    assert(read_file(output).find("Captured: -") != std::string::npos);

    remove_database(database);
    std::filesystem::remove(output);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    history_output_includes_capture_time(argv[1]);
    std::cout << "History CLI tests passed\n";
}
