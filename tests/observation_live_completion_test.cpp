#include "neta/observation_session.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <optional>
#include <utility>
#include <vector>

namespace {

class EmptySocketObserver final : public neta::platform::ConnectionObserver {
public:
    std::vector<neta::SocketObservation> snapshot() override { return {}; }
};

class ScriptedLifecycleObserver final : public neta::LifecycleObserver {
public:
    ScriptedLifecycleObserver() {
        capability_.built_in = true;
        capability_.btf_core_runtime = true;
        capability_.connect_events = true;
        capability_.accept_events = true;
        capability_.close_events = true;
        capability_.drop_counter = true;

        neta::ConnectionLifecycleEvent accept;
        accept.type = neta::ConnectionLifecycleEventType::Accept;
        accept.timestamp_ns = 100;
        accept.protocol = neta::TransportProtocol::Tcp;
        accept.endpoint_kind = neta::TcpEndpointKind::Connection;
        accept.network_namespace_inode = 42;
        accept.local = neta::NetworkEndpoint{"127.0.0.1", 9443};
        accept.remote = neta::NetworkEndpoint{"127.0.0.1", 45000};
        accept.process.agent_visible.pid = 321;
        accept.process.agent_visible.tgid = 321;
        accept.process.uid = 1000;
        accept.process.start_ticks = 321;
        accept.process.comm = "lab-server";
        accept.socket_cookie = 777;

        auto close = accept;
        close.type = neta::ConnectionLifecycleEventType::Close;
        close.timestamp_ns = 200;
        batches_.push_back({accept});
        batches_.push_back({close});
    }

    const neta::LifecycleCapability& capability() const noexcept override { return capability_; }
    neta::LifecycleHealth health() const override { return neta::LifecycleHealth{0}; }
    std::vector<neta::ConnectionLifecycleEvent> poll(std::chrono::milliseconds) override {
        if (index_ >= batches_.size()) return {};
        return batches_[index_++];
    }

private:
    neta::LifecycleCapability capability_;
    std::vector<std::vector<neta::ConnectionLifecycleEvent>> batches_;
    std::size_t index_{0};
};

class NoProcessResolver final : public neta::platform::ProcessResolver {
public:
    std::optional<neta::ProcessIdentity> resolve(std::uint64_t) override { return std::nullopt; }
};

class NoRouteObserver final : public neta::platform::RouteObserver {
public:
    std::optional<neta::RouteObservation> route_to(const std::string&) override { return std::nullopt; }
};

void remove_database(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

} // namespace

int main() {
    using namespace std::chrono_literals;
    const auto path = std::filesystem::temp_directory_path() /
                      "neta-observation-live-completion.sqlite";
    remove_database(path);

    EmptySocketObserver sockets;
    ScriptedLifecycleObserver lifecycle;
    NoProcessResolver processes;
    NoRouteObserver routes;
    neta::HistoryStore store(path);
    neta::AdmissionPolicyConfig config;
    config.mode = neta::ObservationMode::All;
    neta::ObservationSession session(store, sockets, lifecycle, processes, routes,
                                     neta::ConnectionAdmissionPolicy(config), "");

    std::size_t completed = 0;
    std::int64_t completed_id = 0;
    neta::ObservationRuntimeCallbacks callbacks;
    callbacks.connection_completed = [&](std::int64_t connection_id) {
        ++completed;
        completed_id = connection_id;
    };

    const auto result = session.run(std::nullopt, 1ms,
                                    [&] { return completed != 0; }, callbacks);
    assert(completed == 1);
    assert(completed_id > 0);
    assert(result.admitted_connections == 1);
    const auto connection = store.connection(completed_id);
    assert(connection);
    assert(connection->direction == neta::ConnectionDirection::Inbound);
    assert(connection->lifecycle_state == "CLOSED");

    remove_database(path);
    return 0;
}
