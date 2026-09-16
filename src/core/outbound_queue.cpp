#include "neta/outbound_queue.hpp"

#include "neta/crypto.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace neta {
namespace {

class Statement {
public:
    Statement(sqlite3* database, const char* sql) : database_(database) {
        if (sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(database));
    }
    ~Statement() { sqlite3_finalize(statement_); }
    sqlite3_stmt* get() const noexcept { return statement_; }
    void done() {
        if (sqlite3_step(statement_) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_));
    }
private:
    sqlite3* database_;
    sqlite3_stmt* statement_{nullptr};
};

std::string text_column(sqlite3_stmt* statement, int column) {
    const auto* value = sqlite3_column_text(statement, column);
    return value == nullptr ? std::string{} : reinterpret_cast<const char*>(value);
}

OutboundState state_from_string(const std::string& value) {
    if (value == "PENDING") return OutboundState::Pending;
    if (value == "IN_FLIGHT") return OutboundState::InFlight;
    if (value == "ACKED") return OutboundState::Acknowledged;
    return OutboundState::DeadLetter;
}

void bind_text(sqlite3_stmt* statement, int index, const std::string& value) {
    sqlite3_bind_text(statement, index, value.c_str(), -1, SQLITE_TRANSIENT);
}

std::string sqlite_path(const std::filesystem::path& path) {
#ifdef _WIN32
    const auto value = path.u8string();
    return {reinterpret_cast<const char*>(value.data()), value.size()};
#else
    return path.string();
#endif
}

}  // namespace

OutboundQueue::OutboundQueue(std::filesystem::path database, std::string agent_id,
                             std::uint64_t max_bytes)
    : database_(std::move(database)), agent_id_(std::move(agent_id)), max_bytes_(max_bytes) {
    const auto path = sqlite_path(database_);
    if (sqlite3_open_v2(path.c_str(), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK)
        throw std::runtime_error("failed to open SQLite outbound queue");
    sqlite3_busy_timeout(db_, 5000);
    exec("PRAGMA journal_mode=WAL;");
    exec("PRAGMA synchronous=NORMAL;");
    exec("PRAGMA wal_autocheckpoint=256;");
    initialize_schema();
}

OutboundQueue::~OutboundQueue() {
    if (db_ != nullptr) sqlite3_close(db_);
}

void OutboundQueue::exec(const char* sql) const {
    char* error = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error == nullptr ? "SQLite outbound queue error" : error;
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

void OutboundQueue::initialize_schema() {
    exec(R"SQL(
CREATE TABLE IF NOT EXISTS outbound_metadata(
 key TEXT PRIMARY KEY,
 value INTEGER NOT NULL
);
INSERT OR IGNORE INTO outbound_metadata(key,value) VALUES('next_event_counter',1);
INSERT OR IGNORE INTO outbound_metadata(key,value) VALUES('dropped_low_priority',0);
INSERT OR IGNORE INTO outbound_metadata(key,value) VALUES('reported_dropped_low_priority',0);
INSERT OR IGNORE INTO outbound_metadata(key,value) VALUES('coalesced',0);
INSERT OR IGNORE INTO outbound_metadata(key,value) VALUES('last_ack_ns',0);

CREATE TABLE IF NOT EXISTS outbound_messages(
 event_id TEXT PRIMARY KEY,
 event_counter INTEGER NOT NULL UNIQUE,
 producer_key TEXT NOT NULL UNIQUE,
 message_type TEXT NOT NULL,
 finding_type TEXT NOT NULL,
 finding_key TEXT NOT NULL,
 priority INTEGER NOT NULL,
 payload_json TEXT NOT NULL,
 payload_hash TEXT NOT NULL,
 created_at_ns INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('PENDING','IN_FLIGHT','ACKED','DEAD_LETTER')),
 attempt_message_id TEXT,
 attempt_sequence INTEGER,
 attempt_envelope_json TEXT,
 attempt_expires_at_ns INTEGER,
 attempt_count INTEGER NOT NULL DEFAULT 0,
 next_attempt_at_ns INTEGER NOT NULL,
 last_attempt_at_ns INTEGER,
 last_error TEXT,
 ack_status TEXT,
 ack_received_at_ns INTEGER,
 server_received_at TEXT
);
CREATE INDEX IF NOT EXISTS outbound_ready_idx
 ON outbound_messages(state,next_attempt_at_ns,priority DESC,created_at_ns);
)SQL");
}

void OutboundQueue::enforce_budget(std::uint64_t required_bytes) {
    if (max_bytes_ == 0) return;
    std::uint64_t used = 0;
    {
        Statement size(db_, R"SQL(
SELECT COALESCE(SUM(length(payload_json)+COALESCE(length(attempt_envelope_json),0)+512),0)
FROM outbound_messages WHERE state<>'ACKED';
)SQL");
        if (sqlite3_step(size.get()) != SQLITE_ROW) throw std::runtime_error(sqlite3_errmsg(db_));
        used = static_cast<std::uint64_t>(sqlite3_column_int64(size.get(), 0));
    }
    if (required_bytes <= max_bytes_ && used <= max_bytes_ - required_bytes) return;

    Statement remove_acked(db_, R"SQL(
DELETE FROM outbound_messages WHERE event_id IN (
 SELECT event_id FROM outbound_messages
 WHERE state='ACKED' ORDER BY ack_received_at_ns LIMIT 256
);
)SQL");
    remove_acked.done();
    while (required_bytes > max_bytes_ || used > max_bytes_ - required_bytes) {
        Statement remove_low(db_, R"SQL(
DELETE FROM outbound_messages
WHERE event_id=(
 SELECT event_id FROM outbound_messages
 WHERE state='PENDING' AND attempt_count=0 AND priority<=1
 ORDER BY priority,created_at_ns LIMIT 1
);
)SQL");
        remove_low.done();
        if (sqlite3_changes(db_) == 0)
            throw std::runtime_error("outbound queue capacity is reserved for important findings");
        exec("UPDATE outbound_metadata SET value=value+1 WHERE key='dropped_low_priority';");
        Statement measured(db_, R"SQL(
SELECT COALESCE(SUM(length(payload_json)+COALESCE(length(attempt_envelope_json),0)+512),0)
FROM outbound_messages WHERE state<>'ACKED';
)SQL");
        if (sqlite3_step(measured.get()) != SQLITE_ROW) throw std::runtime_error(sqlite3_errmsg(db_));
        used = static_cast<std::uint64_t>(sqlite3_column_int64(measured.get(), 0));
    }
}

std::string OutboundQueue::enqueue(const std::string& producer_key,
                                   const std::string& message_type,
                                   const std::string& finding_type,
                                   const std::string& finding_key,
                                   int priority,
                                   const std::string& payload_json,
                                   const std::string& payload_hash,
                                   std::uint64_t now_ns) {
    exec("BEGIN IMMEDIATE;");
    try {
        std::string existing_event;
        {
            Statement existing(db_, "SELECT event_id FROM outbound_messages WHERE producer_key=?;");
            bind_text(existing.get(), 1, producer_key);
            if (sqlite3_step(existing.get()) == SQLITE_ROW)
                existing_event = text_column(existing.get(), 0);
        }
        if (!existing_event.empty()) {
            exec("UPDATE outbound_metadata SET value=value+1 WHERE key='coalesced';");
            exec("COMMIT;");
            return existing_event;
        }

        enforce_budget(static_cast<std::uint64_t>(payload_json.size()) + 512ULL);
        std::uint64_t value = 0;
        {
            Statement counter(db_, "SELECT value FROM outbound_metadata WHERE key='next_event_counter';");
            if (sqlite3_step(counter.get()) != SQLITE_ROW)
                throw std::runtime_error("outbound counter is missing");
            value = static_cast<std::uint64_t>(sqlite3_column_int64(counter.get(), 0));
        }
        const std::string event_id = agent_id_ + ":" + std::to_string(value);
        Statement insert(db_, R"SQL(
INSERT INTO outbound_messages(
 event_id,event_counter,producer_key,message_type,finding_type,finding_key,priority,
 payload_json,payload_hash,created_at_ns,state,next_attempt_at_ns)
VALUES(?,?,?,?,?,?,?,?,?,?,'PENDING',?);
)SQL");
        int index = 1;
        bind_text(insert.get(), index++, event_id);
        sqlite3_bind_int64(insert.get(), index++, static_cast<sqlite3_int64>(value));
        bind_text(insert.get(), index++, producer_key);
        bind_text(insert.get(), index++, message_type);
        bind_text(insert.get(), index++, finding_type);
        bind_text(insert.get(), index++, finding_key);
        sqlite3_bind_int(insert.get(), index++, priority);
        bind_text(insert.get(), index++, payload_json);
        bind_text(insert.get(), index++, payload_hash);
        sqlite3_bind_int64(insert.get(), index++, static_cast<sqlite3_int64>(now_ns));
        sqlite3_bind_int64(insert.get(), index, static_cast<sqlite3_int64>(now_ns));
        insert.done();
        exec("UPDATE outbound_metadata SET value=value+1 WHERE key='next_event_counter';");
        exec("COMMIT;");
        return event_id;
    } catch (...) {
        try { exec("ROLLBACK;"); } catch (...) {}
        throw;
    }
}

std::optional<OutboundMessage> OutboundQueue::next_ready(std::uint64_t now_ns) const {
    Statement statement(db_, R"SQL(
SELECT event_id,event_counter,producer_key,message_type,finding_type,finding_key,priority,
 payload_json,payload_hash,state,COALESCE(attempt_message_id,''),COALESCE(attempt_sequence,0),
 COALESCE(attempt_envelope_json,''),COALESCE(attempt_expires_at_ns,0),attempt_count
FROM outbound_messages
WHERE state IN ('PENDING','IN_FLIGHT') AND next_attempt_at_ns<=?
ORDER BY priority DESC,created_at_ns LIMIT 1;
)SQL");
    sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(now_ns));
    if (sqlite3_step(statement.get()) != SQLITE_ROW) return std::nullopt;
    OutboundMessage message;
    message.event_id = text_column(statement.get(), 0);
    message.event_counter = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
    message.producer_key = text_column(statement.get(), 2);
    message.message_type = text_column(statement.get(), 3);
    message.finding_type = text_column(statement.get(), 4);
    message.finding_key = text_column(statement.get(), 5);
    message.priority = sqlite3_column_int(statement.get(), 6);
    message.payload_json = text_column(statement.get(), 7);
    message.payload_hash = text_column(statement.get(), 8);
    message.state = state_from_string(text_column(statement.get(), 9));
    message.attempt_message_id = text_column(statement.get(), 10);
    message.attempt_sequence = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 11));
    message.attempt_envelope_json = text_column(statement.get(), 12);
    message.attempt_expires_at_ns = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 13));
    message.attempt_count = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 14));
    return message;
}

void OutboundQueue::store_attempt(const OutboundMessage& message, std::uint64_t now_ns) {
    exec("BEGIN IMMEDIATE;");
    try {
        Statement reserve(db_, "UPDATE outbound_messages SET state='IN_FLIGHT' WHERE event_id=?;");
        bind_text(reserve.get(), 1, message.event_id);
        reserve.done();
        if (sqlite3_changes(db_) != 1)
            throw std::runtime_error("outbound event disappeared before its attempt was stored");
        std::uint64_t existing_bytes = 0;
        {
            Statement existing(db_, R"SQL(
SELECT length(COALESCE(attempt_envelope_json,''))
FROM outbound_messages WHERE event_id=?;
)SQL");
            bind_text(existing.get(), 1, message.event_id);
            if (sqlite3_step(existing.get()) != SQLITE_ROW)
                throw std::runtime_error("outbound event disappeared before its attempt was stored");
            existing_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(existing.get(), 0));
        }
        const auto attempt_bytes = static_cast<std::uint64_t>(message.attempt_envelope_json.size());
        if (attempt_bytes > existing_bytes) enforce_budget(attempt_bytes - existing_bytes);
        Statement statement(db_, R"SQL(
UPDATE outbound_messages SET state='IN_FLIGHT',attempt_message_id=?,attempt_sequence=?,
 attempt_envelope_json=?,attempt_expires_at_ns=?,attempt_count=attempt_count+1,
 last_attempt_at_ns=?,last_error=NULL WHERE event_id=?;
)SQL");
        bind_text(statement.get(), 1, message.attempt_message_id);
        sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(message.attempt_sequence));
        bind_text(statement.get(), 3, message.attempt_envelope_json);
        sqlite3_bind_int64(statement.get(), 4, static_cast<sqlite3_int64>(message.attempt_expires_at_ns));
        sqlite3_bind_int64(statement.get(), 5, static_cast<sqlite3_int64>(now_ns));
        bind_text(statement.get(), 6, message.event_id);
        statement.done();
        exec("COMMIT;");
    } catch (...) {
        try { exec("ROLLBACK;"); } catch (...) {}
        throw;
    }
}

void OutboundQueue::mark_retry(const std::string& event_id, std::uint64_t next_attempt_ns,
                               const std::string& error) {
    Statement statement(db_, R"SQL(
UPDATE outbound_messages
SET state='PENDING',next_attempt_at_ns=?,last_error=? WHERE event_id=?;
)SQL");
    sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(next_attempt_ns));
    bind_text(statement.get(), 2, error.substr(0, 1024));
    bind_text(statement.get(), 3, event_id);
    statement.done();
}

void OutboundQueue::mark_dead_letter(const std::string& event_id, const std::string& error) {
    Statement statement(db_, R"SQL(
UPDATE outbound_messages
SET state='DEAD_LETTER',last_error=? WHERE event_id=?;
)SQL");
    bind_text(statement.get(), 1, error.substr(0, 1024));
    bind_text(statement.get(), 2, event_id);
    statement.done();
}

void OutboundQueue::mark_acknowledged(const std::string& event_id, const CoordinatorAck& ack,
                                      std::uint64_t now_ns) {
    exec("BEGIN IMMEDIATE;");
    try {
        Statement statement(db_, R"SQL(
UPDATE outbound_messages SET state='ACKED',ack_status=?,ack_received_at_ns=?,
 server_received_at=?,last_error=NULL WHERE event_id=?;
)SQL");
        bind_text(statement.get(), 1, ack.status);
        sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(now_ns));
        bind_text(statement.get(), 3, ack.received_at);
        bind_text(statement.get(), 4, event_id);
        statement.done();
        Statement gap(db_, R"SQL(
UPDATE outbound_metadata
SET value=MAX(value,COALESCE((
 SELECT CAST(finding_key AS INTEGER) FROM outbound_messages
 WHERE event_id=? AND finding_type='TELEMETRY_GAP'
),value))
WHERE key='reported_dropped_low_priority';
)SQL");
        bind_text(gap.get(), 1, event_id);
        gap.done();
        Statement metadata(db_, "UPDATE outbound_metadata SET value=? WHERE key='last_ack_ns';");
        sqlite3_bind_int64(metadata.get(), 1, static_cast<sqlite3_int64>(now_ns));
        metadata.done();
        exec("COMMIT;");
    } catch (...) {
        try { exec("ROLLBACK;"); } catch (...) {}
        throw;
    }
}

bool OutboundQueue::is_acknowledged(const std::string& event_id) const {
    Statement statement(db_, "SELECT 1 FROM outbound_messages WHERE event_id=? AND state='ACKED';");
    bind_text(statement.get(), 1, event_id);
    return sqlite3_step(statement.get()) == SQLITE_ROW;
}

OutboundQueueStatus OutboundQueue::status() const {
    OutboundQueueStatus result;
    Statement counts(db_, R"SQL(
SELECT count(*) FILTER(WHERE state='PENDING'),count(*) FILTER(WHERE state='IN_FLIGHT'),
 count(*) FILTER(WHERE state='ACKED'),count(*) FILTER(WHERE state='DEAD_LETTER'),
 COALESCE(SUM(length(payload_json)+COALESCE(length(attempt_envelope_json),0)+512),0),
 COALESCE(MIN(created_at_ns) FILTER(WHERE state IN ('PENDING','IN_FLIGHT')),0)
FROM outbound_messages;
)SQL");
    if (sqlite3_step(counts.get()) != SQLITE_ROW) throw std::runtime_error(sqlite3_errmsg(db_));
    result.pending = static_cast<std::uint64_t>(sqlite3_column_int64(counts.get(), 0));
    result.in_flight = static_cast<std::uint64_t>(sqlite3_column_int64(counts.get(), 1));
    result.acknowledged = static_cast<std::uint64_t>(sqlite3_column_int64(counts.get(), 2));
    result.dead_letter = static_cast<std::uint64_t>(sqlite3_column_int64(counts.get(), 3));
    result.logical_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(counts.get(), 4));
    result.oldest_pending_ns = static_cast<std::uint64_t>(sqlite3_column_int64(counts.get(), 5));
    Statement metadata(db_, "SELECT key,value FROM outbound_metadata;");
    while (sqlite3_step(metadata.get()) == SQLITE_ROW) {
        const auto key = text_column(metadata.get(), 0);
        const auto value = static_cast<std::uint64_t>(sqlite3_column_int64(metadata.get(), 1));
        if (key == "dropped_low_priority") result.dropped_low_priority = value;
        else if (key == "coalesced") result.coalesced = value;
        else if (key == "last_ack_ns") result.last_ack_ns = value;
    }
    return result;
}

void OutboundQueue::enqueue_gap_marker(std::uint64_t now_ns) {
    std::uint64_t dropped = 0;
    std::uint64_t reported = 0;
    {
        Statement metadata(db_, R"SQL(
SELECT key,value FROM outbound_metadata
WHERE key IN ('dropped_low_priority','reported_dropped_low_priority');
)SQL");
        while (sqlite3_step(metadata.get()) == SQLITE_ROW) {
            const auto key = text_column(metadata.get(), 0);
            const auto value = static_cast<std::uint64_t>(sqlite3_column_int64(metadata.get(), 1));
            if (key == "dropped_low_priority") dropped = value;
            else reported = value;
        }
    }
    if (dropped <= reported) return;
    {
        Statement pending(db_, R"SQL(
SELECT 1 FROM outbound_messages
WHERE finding_type='TELEMETRY_GAP' AND state IN ('PENDING','IN_FLIGHT') LIMIT 1;
)SQL");
        if (sqlite3_step(pending.get()) == SQLITE_ROW) return;
    }

    std::ostringstream payload;
    payload << "{\"telemetry_gap\":{\"reason\":\"outbox_capacity\","
            << "\"dropped_low_priority\":" << dropped << "}}";
    const auto body = payload.str();
    static_cast<void>(enqueue(
        "EvidenceSummary:TelemetryGap:" + std::to_string(dropped),
        "EvidenceSummary", "TELEMETRY_GAP", std::to_string(dropped), 4,
        body, "sha256:" + sha256_hex(body), now_ns));
}

void OutboundQueue::prune_acknowledged(std::uint64_t older_than_ns) {
    Statement statement(db_, "DELETE FROM outbound_messages WHERE state='ACKED' AND ack_received_at_ns<?;");
    sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(older_than_ns));
    statement.done();
}

}  // namespace neta
