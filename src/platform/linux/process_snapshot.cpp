#include "neta/platform.hpp"

#include <unistd.h>

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

namespace neta::platform {
namespace {

struct ProcStat {
    std::int64_t pid{0};
    std::int64_t ppid{0};
    std::uint32_t session{0};
    std::uint64_t start_ticks{0};
    std::string comm;
};

std::optional<std::int64_t> parse_pid(const std::string& text) {
    std::int64_t value = 0;
    const auto* first = text.data();
    const auto* last = first + text.size();
    const auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc{} || ptr != last || value <= 0) return std::nullopt;
    return value;
}

std::string read_file(const std::filesystem::path& path, bool binary = false) {
    std::ifstream input(path, binary ? std::ios::binary : std::ios::in);
    if (!input) return {};
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::string read_link(const std::filesystem::path& path) {
    std::error_code error;
    const auto value = std::filesystem::read_symlink(path, error);
    return error ? std::string{} : value.string();
}

std::optional<ProcStat> read_stat(std::int64_t pid) {
    const auto text = read_file(std::filesystem::path("/proc") / std::to_string(pid) / "stat");
    if (text.empty()) return std::nullopt;
    const auto open = text.find('(');
    const auto close = text.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close <= open) return std::nullopt;

    ProcStat result;
    result.pid = pid;
    result.comm = text.substr(open + 1, close - open - 1);
    std::istringstream fields(text.substr(close + 2));
    char state = 0;
    std::int64_t ppid = 0;
    std::int64_t pgrp = 0;
    std::uint32_t session = 0;
    fields >> state >> ppid >> pgrp >> session;
    if (!fields) return std::nullopt;
    std::string ignored;
    for (int field = 7; field <= 21; ++field) {
        if (!(fields >> ignored)) return std::nullopt;
    }
    std::uint64_t start_ticks = 0;
    if (!(fields >> start_ticks)) return std::nullopt;
    result.ppid = ppid;
    result.session = session;
    result.start_ticks = start_ticks;
    return result;
}

std::optional<std::uint64_t> ticks_to_ns(std::uint64_t ticks) {
    const long hz = ::sysconf(_SC_CLK_TCK);
    if (hz <= 0) return std::nullopt;
    const auto divisor = static_cast<std::uint64_t>(hz);
    constexpr std::uint64_t billion = 1'000'000'000ULL;
    return (ticks / divisor) * billion + ((ticks % divisor) * billion) / divisor;
}

void read_ids(std::int64_t pid, ProcessExecEvent& event) {
    std::ifstream input(std::filesystem::path("/proc") / std::to_string(pid) / "status");
    std::string key;
    while (input >> key) {
        if (key == "Uid:") {
            std::uint32_t uid = 0;
            input >> uid;
            if (input) event.uid = uid;
        } else if (key == "Gid:") {
            std::uint32_t gid = 0;
            input >> gid;
            if (input) event.gid = gid;
        }
        std::string rest;
        std::getline(input, rest);
    }
}

std::string read_cmdline(std::int64_t pid) {
    auto text = read_file(std::filesystem::path("/proc") / std::to_string(pid) / "cmdline", true);
    for (auto& ch : text) if (ch == '\0') ch = ' ';
    while (!text.empty() && text.back() == ' ') text.pop_back();
    return text;
}

}  // namespace

std::vector<ProcessExecEvent> snapshot_processes() {
    std::vector<ProcessExecEvent> result;
    std::error_code error;
    std::filesystem::directory_iterator current("/proc", error);
    const std::filesystem::directory_iterator end;
    while (!error && current != end) {
        const auto entry = *current;
        current.increment(error);
        std::error_code type_error;
        if (!entry.is_directory(type_error) || type_error) continue;
        const auto pid = parse_pid(entry.path().filename().string());
        if (!pid) continue;
        const auto stat = read_stat(*pid);
        if (!stat) continue;
        const auto start_ns = ticks_to_ns(stat->start_ticks);
        if (!start_ns) continue;

        ProcessExecEvent event;
        event.type = ProcessExecEventType::Start;
        event.timestamp_ns = *start_ns;
        event.pid = *pid;
        event.tgid = *pid;
        event.process_start_time_ns = *start_ns;
        event.parent_pid = stat->ppid;
        event.parent_tgid = stat->ppid;
        event.session_id = stat->session;
        event.comm = stat->comm;
        event.executable_path = read_link(entry.path() / "exe");
        event.command_line = read_cmdline(*pid);
        event.working_directory = read_link(entry.path() / "cwd");
        read_ids(*pid, event);
        if (event.uid) {
            event.user_identity = "uid:" + std::to_string(*event.uid);
            event.elevated = *event.uid == 0;
            event.integrity_level = *event.uid == 0 ? "root" : "user";
        }
        if (stat->ppid > 0) {
            if (const auto parent = read_stat(stat->ppid)) {
                event.parent_process_start_time_ns = ticks_to_ns(parent->start_ticks);
            }
        }
        result.push_back(std::move(event));
    }
    return result;
}

}  // namespace neta::platform
