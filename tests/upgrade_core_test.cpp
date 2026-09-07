#include "neta/behavior_detection.hpp"
#include "neta/crypto.hpp"
#include "neta/upgrade.hpp"
#include "neta/upgrade_runtime.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::filesystem::path temp_dir() {
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    auto path = std::filesystem::temp_directory_path() / ("neta-upgrade-test-" + suffix);
    std::filesystem::create_directories(path);
    return path;
}

struct TempDir {
    std::filesystem::path path{temp_dir()};
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

neta::UpgradeInstruction instruction_for(const neta::BuildIdentity& local) {
    neta::UpgradeInstruction instruction;
    instruction.upgrade_id = "11111111-2222-4333-8444-555555555555";
    instruction.version = local.version + ".next";
    instruction.build_id = "upgrade-test-build";
    instruction.git_commit = "1a2b3c4d5e6f7081928374655647382910abcdef";
    instruction.os = local.os;
    instruction.arch = local.arch;
    instruction.artifact_name = local.os == "windows" ? "neta-agent-test.zip" : "neta-agent-test.tar.gz";
    instruction.download_url = "https://github.com/zelinsky-alexander/neta-agent/releases/download/v-test/" + instruction.artifact_name;
    instruction.sha256 = std::string(64, 'a');
    return instruction;
}

std::string response_for(const neta::UpgradeInstruction& instruction) {
    return std::string("{\"message_id\":\"m1\",\"status\":\"ACCEPTED\",\"upgrade\":{") +
           "\"upgrade_id\":\"" + instruction.upgrade_id + "\"," +
           "\"version\":\"" + instruction.version + "\"," +
           "\"build_id\":\"" + instruction.build_id + "\"," +
           "\"git_commit\":\"" + instruction.git_commit + "\"," +
           "\"os\":\"" + instruction.os + "\"," +
           "\"arch\":\"" + instruction.arch + "\"," +
           "\"artifact_name\":\"" + instruction.artifact_name + "\"," +
           "\"download_url\":\"" + instruction.download_url + "\"," +
           "\"sha256\":\"" + instruction.sha256 + "\"}}";
}

void test_build_identity() {
    TempDir dir;
    const std::string installed_sha(64, 'b');
    {
        std::ofstream out(dir.path / "installed-build.conf");
        out << "artifact_sha256=" << installed_sha << '\n';
    }
    const auto build = neta::current_build_identity(dir.path);
    assert(!build.version.empty());
    assert(!build.build_id.empty());
    assert(build.os == "linux" || build.os == "windows");
    assert(!build.arch.empty());
    assert(build.artifact_sha256 == installed_sha);
    const auto json = neta::build_identity_json(build);
    assert(json.find("\"build_id\"") != std::string::npos);
    assert(json.find(installed_sha) != std::string::npos);
}

void test_instruction_parse_and_policy() {
    const auto local = neta::current_build_identity();
    const auto expected = instruction_for(local);
    const auto parsed = neta::parse_upgrade_instruction_response(response_for(expected));
    assert(parsed.has_value());
    assert(parsed->upgrade_id == expected.upgrade_id);
    assert(parsed->git_commit == expected.git_commit);
    assert(parsed->download_url == expected.download_url);
    neta::validate_upgrade_instruction(*parsed, local);

    assert(!neta::parse_upgrade_instruction_response("{\"status\":\"ACCEPTED\"}").has_value());
    auto bad = expected;
    bad.download_url = "https://example.com/neta-agent.zip";
    bool rejected = false;
    try { neta::validate_upgrade_instruction(bad, local); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);

    bad = expected;
    bad.os = local.os == "windows" ? "linux" : "windows";
    rejected = false;
    try { neta::validate_upgrade_instruction(bad, local); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
}

void test_durable_state_and_idempotency() {
    TempDir dir;
    const auto local = neta::current_build_identity(dir.path);
    const auto instruction = instruction_for(local);
    neta::UpgradeStateStore store(dir.path);
    const auto first = store.accept(instruction, local);
    assert(first.state == neta::UpgradeLocalState::Received);
    assert(std::filesystem::exists(store.path()));

    const auto repeated = store.accept(instruction, local);
    assert(repeated.instruction.upgrade_id == instruction.upgrade_id);
    assert(repeated.state == neta::UpgradeLocalState::Received);

    auto changed = instruction;
    changed.sha256 = std::string(64, 'c');
    bool rejected = false;
    try { (void)store.accept(changed, local); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);

    const auto loaded = store.load();
    assert(loaded.has_value());
    assert(loaded->instruction.sha256 == instruction.sha256);
}

void test_post_activation_replay_is_idempotent() {
    TempDir dir;
    const auto old_build = neta::current_build_identity(dir.path);
    const auto instruction = instruction_for(old_build);
    neta::UpgradeStateStore store(dir.path);
    (void)store.accept(instruction, old_build);

    auto restarted_target = old_build;
    restarted_target.version = instruction.version;
    restarted_target.build_id = instruction.build_id;
    restarted_target.git_commit = instruction.git_commit;
    restarted_target.artifact_sha256 = instruction.sha256;

    const auto replay = store.accept(instruction, restarted_target);
    assert(replay.instruction.upgrade_id == instruction.upgrade_id);
    assert(replay.state == neta::UpgradeLocalState::Received);

    auto changed_same_id = instruction;
    changed_same_id.sha256 = std::string(64, 'c');
    bool rejected = false;
    try { (void)store.accept(changed_same_id, restarted_target); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);

    auto new_request_for_running_build = instruction;
    new_request_for_running_build.upgrade_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    rejected = false;
    try { (void)store.accept(new_request_for_running_build, restarted_target); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
}

void test_stale_verified_upgrade_can_be_superseded_when_target_is_running() {
    TempDir dir;
    const auto original = neta::current_build_identity(dir.path);
    const auto old_instruction = instruction_for(original);
    neta::UpgradeStateStore store(dir.path);
    auto old_state = store.accept(old_instruction, original);
    old_state.state = neta::UpgradeLocalState::Verified;
    store.save(old_state);

    auto running = original;
    running.version = old_instruction.version;
    running.build_id = old_instruction.build_id;
    running.git_commit = old_instruction.git_commit;
    running.artifact_sha256 = old_instruction.sha256;

    auto next = instruction_for(running);
    next.upgrade_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    next.version = running.version + ".next";
    next.build_id = "upgrade-test-build-2";
    next.git_commit = "2a2b3c4d5e6f7081928374655647382910abcdef";
    next.sha256 = std::string(64, 'b');

    const auto accepted = store.accept(next, running);
    assert(accepted.instruction.upgrade_id == next.upgrade_id);
    assert(accepted.state == neta::UpgradeLocalState::Received);
}

void test_terminal_activation_allows_new_upgrade() {
    for (const auto terminal : {neta::UpgradeActivationState::Failed,
                                neta::UpgradeActivationState::RolledBack}) {
        TempDir dir;
        const auto local = neta::current_build_identity(dir.path);
        const auto old_instruction = instruction_for(local);
        neta::UpgradeStateStore store(dir.path);
        auto old_state = store.accept(old_instruction, local);
        old_state.state = neta::UpgradeLocalState::Verified;
        store.save(old_state);

        neta::UpgradeActivationStore activation_store(dir.path);
        neta::UpgradeActivationRecord activation;
        activation.upgrade_id = old_instruction.upgrade_id;
        activation.state = terminal;
        activation.install_root = dir.path / "install";
        activation_store.save(activation);

        auto next = old_instruction;
        next.upgrade_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        const auto accepted = store.accept(next, local);
        assert(accepted.instruction.upgrade_id == next.upgrade_id);
        assert(accepted.state == neta::UpgradeLocalState::Received);
    }
}

void test_active_different_upgrade_still_rejected() {
    TempDir dir;
    const auto local = neta::current_build_identity(dir.path);
    const auto old_instruction = instruction_for(local);
    neta::UpgradeStateStore store(dir.path);
    auto old_state = store.accept(old_instruction, local);
    old_state.state = neta::UpgradeLocalState::Verified;
    store.save(old_state);

    auto next = old_instruction;
    next.upgrade_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    bool rejected = false;
    try { (void)store.accept(next, local); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
}

void test_local_sha_verification() {
    TempDir dir;
    const auto artifact = dir.path / "artifact.bin";
    {
        std::ofstream out(artifact, std::ios::binary);
        out << "hello";
    }
    const std::string expected = neta::sha256_hex("hello");
    neta::ArtifactDownloader::verify_file(artifact, expected, 1024);

    bool mismatch = false;
    try { neta::ArtifactDownloader::verify_file(artifact, std::string(64, '0'), 1024); }
    catch (const std::runtime_error&) { mismatch = true; }
    assert(mismatch);

    bool oversized = false;
    try { neta::ArtifactDownloader::verify_file(artifact, expected, 4); }
    catch (const std::runtime_error&) { oversized = true; }
    assert(oversized);
}

void test_activation_state_round_trip() {
    TempDir dir;
    neta::UpgradeActivationStore store(dir.path);
    neta::UpgradeActivationRecord record;
    record.upgrade_id = "11111111-2222-4333-8444-555555555555";
    record.state = neta::UpgradeActivationState::Installing;
    record.install_root = dir.path / "install";
    record.previous_target = "versions/old";
    record.active_target = "versions/new";
    record.failure_code = "";
    record.failure_message = "";
    store.save(record);

    const auto loaded = store.load();
    assert(loaded.has_value());
    assert(loaded->upgrade_id == record.upgrade_id);
    assert(loaded->state == neta::UpgradeActivationState::Installing);
    assert(loaded->previous_target == record.previous_target);
    assert(loaded->active_target == record.active_target);
    assert(neta::to_string(neta::UpgradeActivationState::LocalHealthy) == "LOCAL_HEALTHY");
    assert(neta::to_string(neta::UpgradeActivationState::RolledBack) == "ROLLED_BACK");
}

void test_health_is_fail_closed() {
    TempDir dir;
    const auto local = neta::current_build_identity(dir.path);
    const auto expected = instruction_for(local);
    const auto result = neta::check_upgrade_health(dir.path, expected);
    assert(!result.healthy);
    assert(!result.failure_code.empty());
}

void test_terminal_activation_does_not_relaunch() {
    for (const auto terminal : {neta::UpgradeActivationState::Failed,
                                neta::UpgradeActivationState::RolledBack}) {
        TempDir dir;
        const auto local = neta::current_build_identity(dir.path);
        const auto instruction = instruction_for(local);
        neta::UpgradeStateStore state_store(dir.path);
        (void)state_store.accept(instruction, local);

        neta::UpgradeActivationStore activation_store(dir.path);
        neta::UpgradeActivationRecord activation;
        activation.upgrade_id = instruction.upgrade_id;
        activation.state = terminal;
        activation.install_root = dir.path / "install";
        activation.active_target = (activation.install_root / "versions" / instruction.build_id).string();
        activation_store.save(activation);

        assert(!neta::launch_upgrade_worker_if_needed(dir.path));
    }
}

void test_progress_status_is_bounded() {
    TempDir dir;
    bool rejected = false;
    try {
        neta::UpgradeProgressReporter::send(dir.path,
            "11111111-2222-4333-8444-555555555555", "CONFIRMED");
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
}

neta::ConnectionSummary behavior_connection(std::int64_t id, std::uint64_t first_seen_ns,
                                            const char* process, const char* remote,
                                            std::uint16_t port) {
    neta::ConnectionSummary result;
    result.id = id;
    result.first_seen_ns = first_seen_ns;
    result.last_seen_ns = first_seen_ns + 10'000'000ULL;
    result.direction = neta::ConnectionDirection::Outbound;
    result.process.comm = process;
    result.process.executable_path = std::string("/test/") + process;
    result.remote_ip = remote;
    result.remote_port = port;
    result.lifecycle_state = "CLOSED";
    return result;
}

std::vector<neta::ConnectionSummary> periodic_connections(std::size_t count,
                                                           std::uint64_t interval_ns) {
    std::vector<neta::ConnectionSummary> result;
    result.reserve(count);
    constexpr std::uint64_t start = 10'000'000'000ULL;
    for (std::size_t index = 0; index < count; ++index) {
        result.push_back(behavior_connection(
            static_cast<std::int64_t>(index + 1),
            start + static_cast<std::uint64_t>(index) * interval_ns,
            "curl", "192.0.2.10", 18080));
    }
    return result;
}

void test_periodic_outbound_behavior_detection() {
    const auto beacon = periodic_connections(12, 5'000'000'000ULL);
    const auto finding = neta::detect_periodic_outbound(beacon, 12);
    assert(finding.has_value());
    assert(finding->type == "PERIODIC_OUTBOUND_CONNECTION");
    assert(finding->severity == "LOW");
    assert(finding->malicious_intent == "UNKNOWN");
    assert(finding->connection_ids.size() == 12);
    assert(finding->median_interval_ns == 5'000'000'000ULL);
    assert(finding->regular_interval_fraction == 1.0);
    assert(finding->confidence == 1.0);
    assert(finding->evidence_root.starts_with("sha256:"));
    assert(finding->interpretation.find("Malicious intent is not established") !=
           std::string::npos);

    const auto too_few = periodic_connections(2, 5'000'000'000ULL);
    assert(!neta::detect_periodic_outbound(too_few, 2));

    auto irregular = periodic_connections(12, 5'000'000'000ULL);
    const std::uint64_t irregular_seconds[] = {10, 13, 22, 26, 40, 45, 53, 57, 70, 75, 87, 92};
    for (std::size_t index = 0; index < irregular.size(); ++index) {
        irregular[index].first_seen_ns = irregular_seconds[index] * 1'000'000'000ULL;
    }
    assert(!neta::detect_periodic_outbound(irregular, 12));

    std::vector<neta::ConnectionSummary> browser_burst;
    const std::uint64_t burst_ms[] = {0, 35, 80, 120, 180, 260, 350, 470, 900, 1400, 2200, 3100};
    for (std::size_t index = 0; index < std::size(burst_ms); ++index) {
        browser_burst.push_back(behavior_connection(
            static_cast<std::int64_t>(index + 1),
            20'000'000'000ULL + burst_ms[index] * 1'000'000ULL,
            "chrome", "192.0.2.20", 443));
    }
    assert(!neta::detect_periodic_outbound(browser_burst, 12));
}

} // namespace

int main() {
    test_build_identity();
    test_instruction_parse_and_policy();
    test_durable_state_and_idempotency();
    test_post_activation_replay_is_idempotent();
    test_stale_verified_upgrade_can_be_superseded_when_target_is_running();
    test_terminal_activation_allows_new_upgrade();
    test_active_different_upgrade_still_rejected();
    test_local_sha_verification();
    test_activation_state_round_trip();
    test_health_is_fail_closed();
    test_terminal_activation_does_not_relaunch();
    test_progress_status_is_bounded();
    test_periodic_outbound_behavior_detection();
    std::cout << "upgrade core and portable behavior tests passed\n";
    return 0;
}
