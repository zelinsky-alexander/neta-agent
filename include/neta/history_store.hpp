#pragma once

#include "neta/model.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace neta {

struct StorageStatus {
    std::filesystem::path path;
    std::uint64_t bytes{0};
    std::uint64_t max_bytes{0};
    std::uint64_t connection_count{0};
    std::uint64_t sample_count{0};
};

struct ExportData {
    ConnectionSummary connection;
    std::vector<TcpSnapshot> samples;
    std::optional<RouteObservation> route;
    std::optional<TlsObservation> tls;
    std::optional<Baseline> baseline;
    std::optional<AssuranceVerdict> verdict;
};

class HistoryStore {
public:
    explicit HistoryStore(std::filesystem::path path);
    ~HistoryStore();

    HistoryStore(const HistoryStore&) = delete;
    HistoryStore& operator=(const HistoryStore&) = delete;

    std::int64_t upsert_process(const ProcessIdentity& process);
    std::int64_t begin_connection(const SocketObservation& socket,
                                  const std::optional<ProcessIdentity>& process,
                                  const std::string& target_host,
                                  std::uint64_t first_seen_ns);
    void touch_connection(std::int64_t connection_id, std::uint64_t last_seen_ns,
                          const std::string& lifecycle_state);
    std::int64_t add_tcp_sample(std::int64_t connection_id, const TcpSnapshot& sample);
    std::int64_t add_route(std::int64_t connection_id, const RouteObservation& route);
    std::int64_t add_tls(const TlsObservation& tls);
    void save_baseline(const Baseline& baseline);
    std::optional<Baseline> baseline_for(const std::string& target_host,
                                         std::uint16_t target_port) const;
    void save_verdict(std::int64_t connection_id, const AssuranceVerdict& verdict,
                      std::optional<std::int64_t> tls_id = std::nullopt);

    std::vector<ConnectionSummary> recent_connections(std::size_t limit) const;
    std::optional<ConnectionSummary> connection(std::int64_t id) const;
    std::vector<TcpSnapshot> samples_for_connection(std::int64_t id) const;
    std::vector<TcpSnapshot> recent_samples_for_target(const std::string& host,
                                                       std::uint16_t port,
                                                       std::size_t limit) const;
    std::optional<RouteObservation> route_for_connection(std::int64_t id) const;
    std::optional<TlsObservation> latest_tls_for_target(const std::string& host,
                                                        std::uint16_t port) const;
    std::optional<AssuranceVerdict> verdict_for_connection(std::int64_t id) const;
    ExportData export_data(std::int64_t id) const;

    StorageStatus status(std::uint64_t max_bytes) const;
    void prune_to_budget(std::uint64_t max_bytes);

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    void initialize_schema();
    void exec(const char* sql) const;

    std::filesystem::path path_;
    sqlite3* db_{nullptr};

    // add_tls() records the current command/session probe. Connections opened
    // afterwards in the same HistoryStore instance are linked to that probe as
    // SUPPORTING evidence even if no baseline/verdict exists yet.
    std::optional<std::int64_t> pending_tls_id_;
    std::string pending_tls_host_;
    std::uint16_t pending_tls_port_{0};
};

} // namespace neta
