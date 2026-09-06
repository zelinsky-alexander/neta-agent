#include "neta/platform.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>

namespace neta::platform {
namespace fs = std::filesystem;
namespace {

constexpr std::size_t kLinuxCommVisibleBytes = 15;

std::optional<std::uint64_t> process_start_ticks(std::int64_t pid) {
    std::ifstream in("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    std::getline(in, line);
    const auto end_comm = line.rfind(')');
    if (end_comm == std::string::npos || end_comm + 2 >= line.size()) return std::nullopt;
    std::istringstream fields(line.substr(end_comm + 2));
    std::string token;
    for (int i = 0; i <= 19; ++i) {
        if (!(fields >> token)) return std::nullopt;
    }
    try { return std::stoull(token); } catch (...) { return std::nullopt; }
}

std::string first_line(const std::string& path) {
    std::ifstream in(path);
    std::string value;
    std::getline(in, value);
    return value;
}

std::string first_cmdline_argument(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::string value;
    std::getline(in, value, '\0');
    return value;
}

std::string basename_or_empty(const std::string& path) {
    if (path.empty()) return {};
    return fs::path(path).filename().string();
}

std::string process_display_name(const std::string& comm,
                                 const std::string& executable_path,
                                 const std::string& argv0) {
    if (comm.size() < kLinuxCommVisibleBytes) return comm;

    // /proc/<pid>/comm is backed by Linux TASK_COMM_LEN (16 bytes including
    // the terminator), so a 15-byte value may be silently truncated. Prefer
    // the kernel's executable symlink when available. Short-lived processes
    // can disappear between socket attribution and readlink(/proc/<pid>/exe),
    // so fall back to argv[0] from /proc/<pid>/cmdline before retaining comm.
    if (const auto executable_name = basename_or_empty(executable_path); !executable_name.empty())
        return executable_name;
    if (const auto argv0_name = basename_or_empty(argv0); !argv0_name.empty())
        return argv0_name;
    return comm;
}

class LinuxProcessResolver final : public ProcessResolver {
public:
    std::optional<ProcessIdentity> resolve(std::uint64_t socket_inode) override {
        const std::string needle = "socket:[" + std::to_string(socket_inode) + "]";
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator("/proc", fs::directory_options::skip_permission_denied, ec)) {
            if (ec) { ec.clear(); continue; }
            const auto name = entry.path().filename().string();
            if (name.empty() || !std::all_of(name.begin(), name.end(), [](unsigned char c) { return std::isdigit(c); })) continue;
            const auto pid = static_cast<std::int64_t>(std::stoll(name));
            const auto fd_dir = entry.path() / "fd";
            for (const auto& fd : fs::directory_iterator(fd_dir, fs::directory_options::skip_permission_denied, ec)) {
                if (ec) { ec.clear(); break; }
                auto target = fs::read_symlink(fd.path(), ec).string();
                if (ec) { ec.clear(); continue; }
                if (target != needle) continue;

                ProcessIdentity result;
                result.pid = pid;
                struct stat st{};
                if (::stat(entry.path().c_str(), &st) == 0) result.uid = st.st_uid;
                result.start_ticks = process_start_ticks(pid);
                result.comm = first_line((entry.path() / "comm").string());
                auto exe = fs::read_symlink(entry.path() / "exe", ec);
                if (!ec) result.executable_path = exe.string(); else ec.clear();
                const std::string argv0 = result.comm.size() >= kLinuxCommVisibleBytes && result.executable_path.empty()
                    ? first_cmdline_argument(entry.path() / "cmdline")
                    : std::string{};
                result.comm = process_display_name(result.comm, result.executable_path, argv0);
                return result;
            }
        }
        return std::nullopt;
    }
};

} // namespace

std::unique_ptr<ProcessResolver> make_process_resolver() {
    return std::make_unique<LinuxProcessResolver>();
}

} // namespace neta::platform
