#include "neta/rule_convergence.hpp"

#include "neta/rule_update.hpp"
#include "neta/rules/json_parser.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace neta {
namespace {

std::string rule_convergence_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool rule_convergence_valid_sha(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

std::filesystem::path rule_convergence_marker(const std::filesystem::path& state_dir) {
    return state_dir / "rules" / "convergence.pending";
}

std::string rule_convergence_read_marker(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::string value;
    std::getline(input, value);
    if (!value.empty() && value.back() == '\r') value.pop_back();
    return rule_convergence_lower(value);
}

void rule_convergence_write_marker(const std::filesystem::path& path, const std::string& sha256) {
    std::filesystem::create_directories(path.parent_path());
    const auto temporary = path.string() + ".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("cannot create rule convergence marker");
        output << sha256 << '\n';
        if (!output) throw std::runtime_error("cannot write rule convergence marker");
    }
    std::error_code ec;
    std::filesystem::rename(temporary, path, ec);
#ifdef _WIN32
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(temporary, path, ec);
    }
#endif
    if (ec) {
        std::filesystem::remove(temporary);
        throw std::runtime_error("cannot activate rule convergence marker: " + ec.message());
    }
}

bool rule_convergence_marker_recent(const std::filesystem::path& path, const std::string& desired_sha256) {
    if (!std::filesystem::is_regular_file(path)) return false;
    if (rule_convergence_read_marker(path) != desired_sha256) return false;
    std::error_code ec;
    const auto modified = std::filesystem::last_write_time(path, ec);
    if (ec) return false;
    return decltype(modified)::clock::now() - modified < std::chrono::minutes(10);
}

void rule_convergence_remove_marker(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

#ifdef _WIN32
std::wstring rule_convergence_quote(const std::wstring& value) {
    if (value.find_first_of(L" \t\"") == std::wstring::npos) return value;
    std::wstring out = L"\"";
    unsigned backslashes = 0;
    for (wchar_t c : value) {
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

void rule_convergence_launch_worker(const std::filesystem::path& state_dir,
                                    const std::string&) {
    std::vector<wchar_t> executable(32768);
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length >= executable.size())
        throw std::runtime_error("cannot resolve NETA agent executable for rule convergence");
    const std::wstring exe(executable.data(), length);
    std::wstring command = rule_convergence_quote(exe) + L" fleet rules-update --state-dir " +
                           rule_convergence_quote(state_dir.wstring());
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
    if (!CreateProcessW(exe.c_str(), mutable_command.data(), nullptr, nullptr, FALSE, flags,
                        nullptr, nullptr, &startup, &process)) {
        throw std::runtime_error("cannot launch detached Windows rule-update worker");
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}
#else
std::filesystem::path rule_convergence_current_executable() {
    std::vector<char> buffer(4096);
    for (;;) {
        const auto count = readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
        if (count < 0) throw std::runtime_error("cannot resolve NETA agent executable for rule convergence");
        if (static_cast<std::size_t>(count) < buffer.size() - 1) {
            buffer[static_cast<std::size_t>(count)] = '\0';
            return std::filesystem::path(buffer.data());
        }
        if (buffer.size() >= 1024U * 1024U)
            throw std::runtime_error("NETA agent executable path is unreasonably long");
        buffer.resize(buffer.size() * 2);
    }
}

void rule_convergence_launch_worker(const std::filesystem::path& state_dir,
                                    const std::string& desired_sha256) {
    const auto executable = rule_convergence_current_executable();
    const std::string unit = "neta-rules-update-" + std::to_string(static_cast<long long>(getpid())) + "-" +
                             desired_sha256.substr(0, 12);
    const pid_t child = fork();
    if (child < 0) throw std::runtime_error("cannot fork rule convergence launcher");
    if (child == 0) {
        execlp("systemd-run", "systemd-run", "--quiet", "--collect", "--unit", unit.c_str(),
               executable.c_str(), "fleet", "rules-update", "--state-dir", state_dir.c_str(),
               static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0)
        throw std::runtime_error("cannot wait for rule convergence launcher");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw std::runtime_error("systemd-run failed to submit detached rule-update worker");
}
#endif

} // namespace

RuleControlDecision parse_rule_control_response(const std::string& response_body) {
    RuleControlDecision decision;
    const auto root = rules::JsonParser(response_body).parse();
    const auto* control = root.find("rules");
    if (control == nullptr) return decision;

    const auto& revision_value = control->at("desiredRevision");
    const double revision = revision_value.as_number();
    if (!std::isfinite(revision) || revision <= 0 || std::floor(revision) != revision ||
        revision > static_cast<double>(std::numeric_limits<std::uint64_t>::max())) {
        throw std::runtime_error("heartbeat desired rule revision is invalid");
    }
    decision.desired_revision = static_cast<std::uint64_t>(revision);
    decision.desired_sha256 = rule_convergence_lower(control->at("desiredSha256").as_string());
    if (!rule_convergence_valid_sha(decision.desired_sha256))
        throw std::runtime_error("heartbeat desired rule SHA-256 is invalid");
    decision.fetch_required = control->at("fetchRequired").as_boolean();
    if (const auto* refresh = control->find("refreshRequested"))
        decision.refresh_requested = refresh->as_boolean();
    decision.present = true;
    return decision;
}

bool accept_rule_control_from_coordinator_response(const std::filesystem::path& state_dir,
                                                   const std::string& response_body) {
    const auto decision = parse_rule_control_response(response_body);
    if (!decision.present) return false;

    const auto active = active_rule_bundle_state(state_dir);
    std::string active_sha = rule_convergence_lower(active.sha256);
    if (active_sha.starts_with("sha256:")) active_sha.erase(0, 7);
    const bool drift = active_sha != decision.desired_sha256;
    const auto marker = rule_convergence_marker(state_dir);

    // A matching local bundle is sufficient unless the operator explicitly asked
    // the endpoint to re-fetch/revalidate it. Coordinator state can lag the local
    // file briefly while an external updater is completing its ACTIVE ACK.
    if (!drift && !decision.refresh_requested) {
        rule_convergence_remove_marker(marker);
        return false;
    }
    if (!drift && !decision.fetch_required && !decision.refresh_requested) return false;

    // Prevent AgentHello from starting a second worker while the first updater is
    // restarting the service. A stale marker expires so failed workers retry later.
    if (rule_convergence_marker_recent(marker, decision.desired_sha256)) return false;

    rule_convergence_write_marker(marker, decision.desired_sha256);
    try {
        rule_convergence_launch_worker(state_dir, decision.desired_sha256);
    } catch (...) {
        rule_convergence_remove_marker(marker);
        throw;
    }
    return true;
}

} // namespace neta
