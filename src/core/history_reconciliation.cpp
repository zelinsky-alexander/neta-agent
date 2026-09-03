#include "neta/history_store.hpp"

#include <sqlite3.h>

#include <stdexcept>
#include <string>

namespace neta {

bool HistoryStore::promote_connection_direction(std::int64_t connection_id,
                                                ConnectionDirection direction) {
    if (direction == ConnectionDirection::Unknown) return false;
    sqlite3_stmt* statement = nullptr;
    constexpr const char* sql =
        "UPDATE connections SET direction=? WHERE id=? AND direction='UNKNOWN';";
    if (sqlite3_prepare_v2(db_, sql, -1, &statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db_));
    }
    const auto direction_text = to_string(direction);
    sqlite3_bind_text(statement, 1, direction_text.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, connection_id);
    const int rc = sqlite3_step(statement);
    if (rc != SQLITE_DONE) {
        const std::string error = sqlite3_errmsg(db_);
        sqlite3_finalize(statement);
        throw std::runtime_error(error);
    }
    const bool changed = sqlite3_changes(db_) == 1;
    sqlite3_finalize(statement);
    return changed;
}

} // namespace neta
