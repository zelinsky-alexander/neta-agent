#include "neta/crypto.hpp"
#include "neta/upgrade.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

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
    instruction.artifact_name = "neta-agent-test.zip";
    instruction.download_url = "https://github.com/zelinsky-alexander/neta-agent/releases/download/v-test/neta-agent-test.zip";
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

} // namespace

int main() {
    test_build_identity();
    test_instruction_parse_and_policy();
    test_durable_state_and_idempotency();
    test_local_sha_verification();
    std::cout << "upgrade core tests passed\n";
    return 0;
}
