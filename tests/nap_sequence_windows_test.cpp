#include "neta/nap_sequence.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::filesystem::path test_root() {
    return std::filesystem::temp_directory_path() /
           ("neta-nap-sequence-windows-" + std::to_string(GetCurrentProcessId()));
}

void write_binary(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot create test file " + path.string());
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!output) throw std::runtime_error("cannot write test file " + path.string());
}

std::string read_binary(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read test file " + path.string());
    return std::string((std::istreambuf_iterator<char>(input)), {});
}

bool allocation_throws(const std::filesystem::path& dir) {
    try {
        static_cast<void>(neta::next_nap_sequence(dir));
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

std::wstring quote_arg(const std::wstring& value) {
    if (value.find_first_of(L" \t\"") == std::wstring::npos) return value;
    std::wstring out = L"\"";
    unsigned backslashes = 0;
    for (const wchar_t c : value) {
        if (c == L'\\') { ++backslashes; continue; }
        if (c == L'\"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'\"');
            backslashes = 0;
            continue;
        }
        out.append(backslashes, L'\\');
        backslashes = 0;
        out.push_back(c);
    }
    out.append(backslashes * 2, L'\\');
    out.push_back(L'\"');
    return out;
}

std::filesystem::path executable_path() {
    std::wstring buffer(32768, L'\0');
    const DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (size == 0 || size >= buffer.size()) throw std::runtime_error("GetModuleFileNameW failed");
    buffer.resize(size);
    return std::filesystem::path(buffer);
}

PROCESS_INFORMATION launch_child(const std::filesystem::path& executable,
                                 const std::filesystem::path& state_dir,
                                 const std::filesystem::path& output_path) {
    std::wstring command = quote_arg(executable.wstring()) + L" --child " +
                           quote_arg(state_dir.wstring()) + L" " + quote_arg(output_path.wstring());
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) == FALSE) {
        throw std::runtime_error("CreateProcessW concurrency child failed");
    }
    CloseHandle(process.hThread);
    return process;
}

void wait_children(std::vector<PROCESS_INFORMATION>& children) {
    for (auto& child : children) {
        const DWORD wait = WaitForSingleObject(child.hProcess, 15000);
        assert(wait == WAIT_OBJECT_0);
        DWORD exit_code = 1;
        assert(GetExitCodeProcess(child.hProcess, &exit_code) != FALSE);
        CloseHandle(child.hProcess);
        assert(exit_code == 0);
    }
}

void test_legacy_migration(const std::filesystem::path& root) {
    const auto dir = root / "legacy-migration";
    std::filesystem::create_directories(dir);
    write_binary(dir / "sequence", "1752\n");
    const auto before = neta::inspect_nap_sequence_state(dir);
    assert(before.health == neta::NapSequenceHealth::LegacyMigrationRequired);
    assert(before.has_sequence && before.sequence == 1752);
    assert(neta::next_nap_sequence(dir) == 1753);
    const auto after = neta::inspect_nap_sequence_state(dir);
    assert(after.health == neta::NapSequenceHealth::Healthy);
    assert(after.slot0_valid && after.slot1_valid);
    assert(after.has_sequence && after.sequence == 1753);
    assert(after.recovery_detail.find("Migrated validated legacy NAP sequence") != std::string::npos);
}

void test_corrupt_legacy_inputs(const std::filesystem::path& root) {
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"five-nuls", std::string(5, '\0')},
        {"empty", ""},
        {"truncated", "17x"},
        {"overflow", "18446744073709551616\n"},
    };
    for (const auto& [name, content] : cases) {
        const auto dir = root / name;
        std::filesystem::create_directories(dir);
        write_binary(dir / "sequence", content);
        assert(allocation_throws(dir));
        const auto status = neta::inspect_nap_sequence_state(dir);
        assert(status.health == neta::NapSequenceHealth::Unrecoverable);
        assert(!status.has_sequence);
    }
}

void test_single_slot_recovery(const std::filesystem::path& root) {
    const auto dir = root / "single-slot-recovery";
    neta::initialize_nap_sequence_state(dir, 100);
    assert(neta::next_nap_sequence(dir) == 101);
    write_binary(dir / "sequence.0", std::string(5, '\0'));
    const auto degraded = neta::inspect_nap_sequence_state(dir);
    assert(degraded.health == neta::NapSequenceHealth::Recovered);
    assert(degraded.has_sequence && degraded.sequence == 101);
    assert(neta::next_nap_sequence(dir) == 102);
    const auto repaired = neta::inspect_nap_sequence_state(dir);
    assert(repaired.health == neta::NapSequenceHealth::Healthy);
    assert(repaired.slot0_valid && repaired.slot1_valid);
    assert(repaired.sequence == 102);
    assert(repaired.recovery_detail.find("Recovered NAP sequence state") != std::string::npos);
}

void test_both_slots_corrupt_fail_closed(const std::filesystem::path& root) {
    const auto dir = root / "both-corrupt";
    neta::initialize_nap_sequence_state(dir, 200);
    write_binary(dir / "sequence.0", "broken-0");
    write_binary(dir / "sequence.1", "broken-1");
    write_binary(dir / "sequence", "999999\n");
    assert(allocation_throws(dir));
    const auto status = neta::inspect_nap_sequence_state(dir);
    assert(status.health == neta::NapSequenceHealth::Unrecoverable);
    assert(!status.has_sequence);
}

void test_simulated_crash_states(const std::filesystem::path& root) {
    {
        const auto dir = root / "crash-truncated-slot";
        neta::initialize_nap_sequence_state(dir, 300);
        write_binary(dir / "sequence.0", "");
        assert(neta::next_nap_sequence(dir) == 301);
        const auto status = neta::inspect_nap_sequence_state(dir);
        assert(status.health == neta::NapSequenceHealth::Healthy && status.sequence == 301);
    }
    {
        const auto dir = root / "crash-partial-write";
        neta::initialize_nap_sequence_state(dir, 400);
        write_binary(dir / "sequence.1", "NETA-NAP-SEQUENCE/1\nsequence=401\nchecksum=sha256:");
        assert(neta::next_nap_sequence(dir) == 401);
        const auto status = neta::inspect_nap_sequence_state(dir);
        assert(status.health == neta::NapSequenceHealth::Healthy && status.sequence == 401);
    }
    {
        const auto dir = root / "crash-between-slot-flushes";
        neta::initialize_nap_sequence_state(dir, 500);
        const auto old_slot = read_binary(dir / "sequence.1");
        assert(neta::next_nap_sequence(dir) == 501);
        write_binary(dir / "sequence.1", old_slot);
        const auto interrupted = neta::inspect_nap_sequence_state(dir);
        assert(interrupted.health == neta::NapSequenceHealth::Healthy);
        assert(interrupted.sequence == 501);
        assert(neta::next_nap_sequence(dir) == 502);
        const auto recovered = neta::inspect_nap_sequence_state(dir);
        assert(recovered.health == neta::NapSequenceHealth::Healthy && recovered.sequence == 502);
    }
}

void test_multiprocess_concurrency(const std::filesystem::path& root) {
    const auto dir = root / "concurrency";
    neta::initialize_nap_sequence_state(dir, 1000);
    const auto exe = executable_path();
    constexpr int child_count = 8;
    std::vector<PROCESS_INFORMATION> children;
    children.reserve(child_count);
    for (int index = 0; index < child_count; ++index) {
        children.push_back(launch_child(exe, dir, dir / ("child-" + std::to_string(index) + ".txt")));
    }
    wait_children(children);
    std::set<std::uint64_t> values;
    for (int index = 0; index < child_count; ++index) {
        std::ifstream input(dir / ("child-" + std::to_string(index) + ".txt"));
        std::uint64_t value = 0;
        input >> value;
        assert(input.good() || input.eof());
        values.insert(value);
    }
    assert(values.size() == child_count);
    std::uint64_t expected = 1001;
    for (const auto value : values) assert(value == expected++);
    const auto status = neta::inspect_nap_sequence_state(dir);
    assert(status.health == neta::NapSequenceHealth::Healthy);
    assert(status.sequence == 1000 + child_count);
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "--child") {
        try {
            const auto sequence = neta::next_nap_sequence(argv[2]);
            std::ofstream output(argv[3], std::ios::trunc);
            output << sequence << '\n';
            return output ? 0 : 2;
        } catch (...) {
            return 3;
        }
    }

    const auto root = test_root();
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    try {
        test_legacy_migration(root);
        test_corrupt_legacy_inputs(root);
        test_single_slot_recovery(root);
        test_both_slots_corrupt_fail_closed(root);
        test_simulated_crash_states(root);
        test_multiprocess_concurrency(root);
    } catch (...) {
        std::filesystem::remove_all(root);
        throw;
    }
    std::filesystem::remove_all(root);
    return 0;
}
