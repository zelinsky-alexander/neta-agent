#include "history_schema.hpp"

#include <sqlite3.h>

#include <stdexcept>
#include <string>

namespace neta::history_schema {
namespace {

bool has_column(sqlite3* db, const char* table, const char* column) {
    const std::string sql = "PRAGMA table_info(" + std::string(table) + ");";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }
    bool found = false;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* name = sqlite3_column_text(statement, 1);
        if (name && reinterpret_cast<const char*>(name) == std::string(column)) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(statement);
    return found;
}

} // namespace

void ensure_column(sqlite3* db, const char* table, const char* column,
                   const char* definition) {
    if (has_column(db, table, column)) return;
    const std::string sql = "ALTER TABLE " + std::string(table) + " ADD COLUMN " +
                            definition + ";";
    char* error = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : "SQLite schema migration error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

} // namespace neta::history_schema
