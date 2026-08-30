#pragma once

struct sqlite3;

namespace neta::history_schema {

void ensure_column(sqlite3* db, const char* table, const char* column,
                   const char* definition);

} // namespace neta::history_schema
