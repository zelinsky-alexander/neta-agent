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

std::uint64_t process_start_ticks(std::int64_t pid) {
    std::ifstream in("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    std::getline(in, line);
    const auto end_comm = line.rfind(')');
    if (end_comm == std::string::npos || end_comm + 2 >= line.size()) return 0;
    std::istringstream fields(line.substr(end_comm + 2));
    std::string token;
    for (int i = 0; i <= 19; ++i) {
        if (!(fields >> token)) return 0;
    }
    try { return std::stoull(token); } catch (...) { return 0; }
}

std::string first_line(const std::string& path) {
    std::ifstream in(path);
    std::string value;
    std::getline(in, value);
    return value;
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
