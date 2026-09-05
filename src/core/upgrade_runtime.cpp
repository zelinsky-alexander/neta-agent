#include "neta/upgrade_runtime.hpp"

#include "neta/crypto.hpp"
#include "neta/fleet_client.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace neta {
namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

constexpr std::size_t kFailureCodeMax = 64;
constexpr std::size_t kFailureMessageMax = 1000;

std::string bounded(std::string value, std::size_t max) {
    if (value.size() > max) value.resize(max);
    return value;
}

std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<unsigned int>(c) << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open " + path.string());
    return std::string((std::istreambuf_iterator<char>(input)), {});
}

void atomic_write(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    const auto temporary = path.string() + ".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("cannot write " + temporary);
        output << content;
        if (!output) throw std::runtime_error("failed writing " + temporary);
    }
#ifndef _WIN32
    std::filesystem::permissions(temporary,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
#endif
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
        throw std::runtime_error("cannot atomically replace " + path.string() + ": " + ec.message());
    }
}

std::string member_string(const std::string& text, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    auto pos = text.find(needle);
    if (pos == std::string::npos) return {};
    pos = text.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    ++pos;
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
    if (pos >= text.size() || text[pos] != '"') return {};
    ++pos;
    std::string out;
    while (pos < text.size()) {
        const char c = text[pos++];
        if (c == '"') return out;
        if (c != '\\') { out.push_back(c); continue; }
        if (pos >= text.size()) break;
        const char escaped = text[pos++];
        switch (escaped) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default: throw std::runtime_error("unsupported JSON escape in upgrade activation state");
        }
    }
    throw std::runtime_error("unterminated JSON string in upgrade activation state");
}

std::string activation_json(const UpgradeActivationRecord& record) {
    std::ostringstream out;
    out << "{\n"
        << "  \"upgrade_id\": \"" << json_escape(record.upgrade_id) << "\",\n"
        << "  \"state\": \"" << to_string(record.state) << "\",\n"
        << "  \"install_root\": \"" << json_escape(record.install_root.generic_string()) << "\",\n"
        << "  \"previous_target\": \"" << json_escape(record.previous_target) << "\",\n"
        << "  \"active_target\": \"" << json_escape(record.active_target) << "\",\n"
        << "  \"failure_code\": \"" << json_escape(record.failure_code) << "\",\n"
        << "  \"failure_message\": \"" << json_escape(record.failure_message) << "\"\n"
        << "}\n";
    return out.str();
}

bool safe_token(const std::string& value) {
    return !value.empty() && value.size() <= 128 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '.' || c == '_' || c == '-';
        });
}

void require_identity_files(const std::filesystem::path& state_dir) {
    for (const auto* file : {"identity.conf", "agent.crt", "agent.key", "fleet-ca.crt"}) {
        const auto path = state_dir / file;
        if (!std::filesystem::is_regular_file(path))
            throw std::runtime_error(std::string("fleet identity file missing: ") + file);
    }
    static_cast<void>(FleetClient::load_identity(state_dir));
}

void write_installed_build(const std::filesystem::path& state_dir,
                           const UpgradeInstruction& instruction) {
    std::ostringstream out;
    out << "artifact_sha256=" << instruction.sha256 << '\n'
        << "upgrade_id=" << instruction.upgrade_id << '\n'
        << "version=" << instruction.version << '\n'
        << "build_id=" << instruction.build_id << '\n'
        << "git_commit=" << instruction.git_commit << '\n';
    atomic_write(state_dir / "installed-build.conf", out.str());
}

#ifdef _WIN32
std::wstring quote_windows_arg(const std::wstring& value) {
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

int run_process(const std::vector<std::wstring>& args) {
    if (args.empty()) return -1;
    std::wstring command;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i != 0) command.push_back(L' ');
        command += quote_windows_arg(args[i]);
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) return -1;
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(code);
}

bool service_running(const std::string& name) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) return false;
    const std::wstring wname(name.begin(), name.end());
    SC_HANDLE service = OpenServiceW(manager, wname.c_str(), SERVICE_QUERY_STATUS);
    if (service == nullptr) { CloseServiceHandle(manager); return false; }
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    const bool ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed) != FALSE;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return ok && status.dwCurrentState == SERVICE_RUNNING;
}

void stop_service(const std::string& name) {
    static_cast<void>(run_process({L"sc.exe", L"stop", std::wstring(name.begin(), name.end())}));
    for (int i = 0; i < 40 && service_running(name); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
}

void start_service(const std::string& name) {
    if (run_process({L"sc.exe", L"start", std::wstring(name.begin(), name.end())}) != 0 && !service_running(name))
        throw std::runtime_error("failed to start Windows NETA service");
}
#else
int run_process(const std::vector<std::string>& args) {
    if (args.empty()) return -1;
    const pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& value : args) argv.push_back(const_cast<char*>(value.c_str()));
        argv.push_back(nullptr);
        execv(argv.front(), argv.data());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool service_running(const std::string& name) {
    return run_process({"/usr/bin/systemctl", "is-active", "--quiet", name}) == 0;
}

void stop_service(const std::string& name) {
    static_cast<void>(run_process({"/usr/bin/systemctl", "stop", name}));
}

void start_service(const std::string& name) {
    if (run_process({"/usr/bin/systemctl", "start", name}) != 0)
        throw std::runtime_error("failed to start Linux NETA service");
}
#endif

std::filesystem::path find_packaged_agent(const std::filesystem::path& root) {
    std::optional<std::filesystem::path> found;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
#ifdef _WIN32
        const bool match = entry.path().filename() == "neta-agent.exe";
#else
        const bool match = entry.path().filename() == "neta-agent";
#endif
        if (!match) continue;
        if (found) throw std::runtime_error("upgrade package contains multiple agent executables");
        found = entry.path();
    }
    if (!found) throw std::runtime_error("upgrade package does not contain neta-agent executable");
    return *found;
}

std::filesystem::path extract_version(const UpgradeState& state,
                                      const std::filesystem::path& install_root) {
    if (!safe_token(state.instruction.build_id))
        throw std::runtime_error("upgrade build_id is unsafe for versioned installation");
    ArtifactDownloader::verify_file(state.download_path, state.instruction.sha256);
    const auto versions = install_root / "versions";
    const auto target = versions / state.instruction.build_id;
    if (std::filesystem::exists(target)) {
        static_cast<void>(find_packaged_agent(target));
        return target;
    }
    std::filesystem::create_directories(versions);
    const auto staging = versions / (".staging-" + state.instruction.upgrade_id);
    std::filesystem::remove_all(staging);
    std::filesystem::create_directories(staging);
#ifdef _WIN32
    if (!state.instruction.artifact_name.ends_with(".zip"))
        throw std::runtime_error("Windows upgrade package must be a .zip archive");
    if (run_process({L"tar.exe", L"-xf", state.download_path.wstring(), L"-C", staging.wstring()}) != 0)
        throw std::runtime_error("failed to extract Windows upgrade package");
#else
    if (!(state.instruction.artifact_name.ends_with(".tar.gz") || state.instruction.artifact_name.ends_with(".tgz")))
        throw std::runtime_error("Linux upgrade package must be a .tar.gz archive");
    if (run_process({"/usr/bin/tar", "-xzf", state.download_path.string(), "-C", staging.string(),
                     "--no-same-owner", "--no-same-permissions"}) != 0)
        throw std::runtime_error("failed to extract Linux upgrade package");
#endif
    const auto packaged_agent = find_packaged_agent(staging);
    const auto package_root = packaged_agent.parent_path();
    std::error_code ec;
    std::filesystem::rename(package_root, target, ec);
    if (ec) {
        std::filesystem::create_directories(target);
        std::filesystem::copy(package_root, target,
            std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);
    }
    std::filesystem::remove_all(staging);
    static_cast<void>(find_packaged_agent(target));
    return target;
}

std::string activate_version(const std::filesystem::path& install_root,
                             const std::filesystem::path& target) {
#ifdef _WIN32
    const auto current = install_root / "current";
    const auto previous = install_root / "previous";
    std::filesystem::remove_all(previous);
    std::string previous_target;
    if (std::filesystem::exists(current)) {
        previous_target = current.string();
        std::filesystem::rename(current, previous);
    }
    std::filesystem::copy(target, current,
        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);
    return previous_target;
#else
    const auto current = install_root / "current";
    const auto previous = install_root / "previous";
    std::string old_target;
    std::error_code ec;
    if (std::filesystem::is_symlink(current, ec)) old_target = std::filesystem::read_symlink(current, ec).string();
    if (!old_target.empty()) {
        const auto previous_new = install_root / "previous.new";
        std::filesystem::remove(previous_new, ec);
        std::filesystem::create_symlink(old_target, previous_new);
        std::filesystem::rename(previous_new, previous, ec);
    }
    const auto current_new = install_root / "current.new";
    std::filesystem::remove(current_new, ec);
    std::filesystem::create_symlink(std::filesystem::relative(target, install_root), current_new);
    std::filesystem::rename(current_new, current, ec);
    if (ec) throw std::runtime_error("failed to atomically switch Linux current version: " + ec.message());
    return old_target;
#endif
}

void rollback_version(const UpgradeActivationRecord& activation) {
#ifdef _WIN32
    const auto current = activation.install_root / "current";
    const auto previous = activation.install_root / "previous";
    if (!std::filesystem::exists(previous)) throw std::runtime_error("no previous Windows version available");
    std::filesystem::remove_all(current);
    std::filesystem::rename(previous, current);
#else
    if (activation.previous_target.empty()) throw std::runtime_error("no previous Linux version available");
    const auto current = activation.install_root / "current";
    const auto current_new = activation.install_root / "current.rollback";
    std::error_code ec;
    std::filesystem::remove(current_new, ec);
    std::filesystem::create_symlink(activation.previous_target, current_new);
    std::filesystem::rename(current_new, current, ec);
    if (ec) throw std::runtime_error("failed to restore previous Linux version: " + ec.message());
#endif
}

bool wait_for_health(const UpgradeWorkerOptions& options, const UpgradeInstruction& expected) {
    const auto deadline = std::chrono::steady_clock::now() + options.health_timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (service_running(options.service_name)) {
            const auto health = check_upgrade_health(options.state_dir, expected);
            if (health.healthy) return true;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return false;
}

void best_effort_report(const std::filesystem::path& state_dir,
                        const std::string& upgrade_id,
                        const std::string& status,
                        const std::string& failure_code = {},
                        const std::string& failure_message = {}) noexcept {
    try {
        UpgradeProgressReporter::send(state_dir, upgrade_id, status, failure_code, failure_message);
    } catch (...) {
    }
}

struct ParsedCoordinatorUrl { std::string host; std::string port; std::string path; };

ParsedCoordinatorUrl parse_coordinator_url(const std::string& base) {
    constexpr std::string_view prefix = "https://";
    if (!base.starts_with(prefix)) throw std::runtime_error("coordinator URL must use https://");
    std::string rest = base.substr(prefix.size());
    const auto slash = rest.find('/');
    const std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    ParsedCoordinatorUrl out;
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
        out.host = authority.substr(0, colon);
        out.port = authority.substr(colon + 1);
    } else {
        out.host = authority;
        out.port = "443";
    }
    if (out.host.empty() || out.port.empty()) throw std::runtime_error("invalid coordinator URL");
    out.path = "/api/v1/messages";
    return out;
}

[[noreturn]] void ssl_error(const std::string& what) {
    const unsigned long code = ERR_get_error();
    char buffer[256]{};
    if (code != 0) ERR_error_string_n(code, buffer, sizeof(buffer));
    throw std::runtime_error(what + (code == 0 ? std::string{} : std::string(": ") + buffer));
}

std::uint64_t next_sequence(const std::filesystem::path& state_dir) {
#ifdef _WIN32
    const auto lock_path = state_dir / "sequence.lock";
    HANDLE handle = CreateFileW(lock_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot lock NAP sequence state");
    struct Guard { HANDLE h; ~Guard() { CloseHandle(h); } } guard{handle};
#else
    const auto lock_path = state_dir / "sequence.lock";
    const int fd = open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) throw std::runtime_error("cannot open NAP sequence lock");
    struct Guard { int fd; ~Guard() { flock(fd, LOCK_UN); close(fd); } } guard{fd};
    if (flock(fd, LOCK_EX) != 0) throw std::runtime_error("cannot lock NAP sequence state");
#endif
    const auto sequence_path = state_dir / "sequence";
    std::uint64_t value = 0;
    if (std::filesystem::exists(sequence_path)) value = std::stoull(read_file(sequence_path));
    ++value;
    atomic_write(sequence_path, std::to_string(value) + "\n");
    return value;
}

std::string random_uuid() {
    unsigned char bytes[16]{};
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) ssl_error("message-id generation failed");
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);
    char out[37]{};
    std::snprintf(out, sizeof(out),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return out;
}

std::string iso8601_now(std::chrono::seconds offset = std::chrono::seconds(0)) {
    const auto now = std::chrono::system_clock::now() + offset;
    const auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

void post_progress(const std::filesystem::path& state_dir, const std::string& envelope) {
    const auto identity = FleetClient::load_identity(state_dir);
    const auto url = parse_coordinator_url(identity.coordinator);
    SslCtxPtr context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!context) ssl_error("SSL_CTX_new failed for upgrade progress");
    if (SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1)
        ssl_error("TLS 1.3 setup failed for upgrade progress");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(context.get(), (state_dir / "fleet-ca.crt").string().c_str(), nullptr) != 1)
        ssl_error("cannot load Fleet CA for upgrade progress");
    if (SSL_CTX_use_certificate_chain_file(context.get(), (state_dir / "agent.crt").string().c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(context.get(), (state_dir / "agent.key").string().c_str(), SSL_FILETYPE_PEM) != 1)
        ssl_error("cannot load agent identity for upgrade progress");

    BioPtr bio(BIO_new_ssl_connect(context.get()), BIO_free_all);
    if (!bio) ssl_error("BIO_new_ssl_connect failed for upgrade progress");
    SSL* ssl = nullptr;
    BIO_get_ssl(bio.get(), &ssl);
    if (ssl == nullptr) ssl_error("upgrade progress TLS object unavailable");
    if (SSL_set_tlsext_host_name(ssl, url.host.c_str()) != 1) ssl_error("upgrade progress SNI setup failed");
    X509_VERIFY_PARAM* verify = SSL_get0_param(ssl);
    if (verify == nullptr || X509_VERIFY_PARAM_set1_host(verify, url.host.c_str(), 0) != 1)
        ssl_error("upgrade progress hostname verification setup failed");
    const std::string endpoint = url.host + ":" + url.port;
    BIO_set_conn_hostname(bio.get(), endpoint.c_str());
    if (BIO_do_connect(bio.get()) <= 0 || BIO_do_handshake(bio.get()) <= 0)
        ssl_error("upgrade progress HTTPS connection failed");
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        throw std::runtime_error("coordinator certificate verification failed for upgrade progress");

    std::ostringstream request;
    request << "POST " << url.path << " HTTP/1.1\r\n"
            << "Host: " << url.host << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Accept: application/json\r\n"
            << "Connection: close\r\n"
            << "Content-Length: " << envelope.size() << "\r\n\r\n"
            << envelope;
    const std::string wire = request.str();
    std::size_t offset = 0;
    while (offset < wire.size()) {
        const int amount = static_cast<int>(std::min<std::size_t>(wire.size() - offset, 1U << 20));
        const int written = BIO_write(bio.get(), wire.data() + offset, amount);
        if (written <= 0) ssl_error("upgrade progress HTTPS write failed");
        offset += static_cast<std::size_t>(written);
    }
    std::string response;
    char buffer[4096];
    for (;;) {
        const int count = BIO_read(bio.get(), buffer, static_cast<int>(sizeof(buffer)));
        if (count > 0) { response.append(buffer, static_cast<std::size_t>(count)); continue; }
        if (count == 0) break;
        if (BIO_should_retry(bio.get())) continue;
        break;
    }
    const auto line_end = response.find("\r\n");
    if (line_end == std::string::npos) throw std::runtime_error("invalid upgrade progress HTTP response");
    std::istringstream status_line(response.substr(0, line_end));
    std::string version;
    int status = 0;
    status_line >> version >> status;
    if (status < 200 || status >= 300)
        throw std::runtime_error("coordinator rejected UpgradeProgress with HTTP " + std::to_string(status));
}

} // namespace

std::string to_string(UpgradeActivationState state) {
    switch (state) {
        case UpgradeActivationState::Installing: return "INSTALLING";
        case UpgradeActivationState::LocalHealthy: return "LOCAL_HEALTHY";
        case UpgradeActivationState::Failed: return "FAILED";
        case UpgradeActivationState::RolledBack: return "ROLLED_BACK";
    }
    throw std::runtime_error("unknown upgrade activation state");
}

UpgradeActivationState upgrade_activation_state_from_string(const std::string& value) {
    if (value == "INSTALLING") return UpgradeActivationState::Installing;
    if (value == "LOCAL_HEALTHY") return UpgradeActivationState::LocalHealthy;
    if (value == "FAILED") return UpgradeActivationState::Failed;
    if (value == "ROLLED_BACK") return UpgradeActivationState::RolledBack;
    throw std::runtime_error("unknown upgrade activation state: " + value);
}

UpgradeActivationStore::UpgradeActivationStore(std::filesystem::path state_dir)
    : state_dir_(std::move(state_dir)) {
    if (state_dir_.empty()) throw std::runtime_error("upgrade activation state directory is required");
}

std::filesystem::path UpgradeActivationStore::path() const {
    return state_dir_ / "upgrade" / "activation.json";
}

std::optional<UpgradeActivationRecord> UpgradeActivationStore::load() const {
    if (!std::filesystem::exists(path())) return std::nullopt;
    const auto text = read_file(path());
    UpgradeActivationRecord record;
    record.upgrade_id = member_string(text, "upgrade_id");
    record.state = upgrade_activation_state_from_string(member_string(text, "state"));
    record.install_root = member_string(text, "install_root");
    record.previous_target = member_string(text, "previous_target");
    record.active_target = member_string(text, "active_target");
    record.failure_code = member_string(text, "failure_code");
    record.failure_message = member_string(text, "failure_message");
    if (record.upgrade_id.empty()) throw std::runtime_error("upgrade activation record missing upgrade_id");
    return record;
}

void UpgradeActivationStore::save(const UpgradeActivationRecord& record) const {
    atomic_write(path(), activation_json(record));
}

UpgradeHealthResult check_upgrade_health(const std::filesystem::path& state_dir,
                                         const UpgradeInstruction& expected) {
    try {
        require_identity_files(state_dir);
        const auto build = current_build_identity(state_dir);
        if (build.version != expected.version || build.build_id != expected.build_id ||
            build.git_commit != expected.git_commit || build.os != expected.os || build.arch != expected.arch)
            return {false, "BUILD_IDENTITY_MISMATCH", "running executable does not match expected upgrade target"};
        if (build.artifact_sha256 != expected.sha256)
            return {false, "ARTIFACT_IDENTITY_MISMATCH", "installed artifact SHA does not match expected upgrade target"};
        return {true, {}, "upgrade health checks passed"};
    } catch (const std::exception& error) {
        return {false, "HEALTH_CHECK_FAILED", bounded(error.what(), kFailureMessageMax)};
    }
}

void UpgradeProgressReporter::send(const std::filesystem::path& state_dir,
                                   const std::string& upgrade_id,
                                   const std::string& status,
                                   const std::string& failure_code,
                                   const std::string& failure_message) {
    static const std::vector<std::string> allowed = {
        "DOWNLOADING", "INSTALLING", "LOCAL_HEALTHY", "FAILED", "ROLLED_BACK"
    };
    if (std::find(allowed.begin(), allowed.end(), status) == allowed.end())
        throw std::runtime_error("invalid UpgradeProgress status");
    const auto identity = FleetClient::load_identity(state_dir);
    const std::string code = bounded(failure_code, kFailureCodeMax);
    const std::string message = bounded(failure_message, kFailureMessageMax);
    std::ostringstream payload;
    payload << "{\"upgrade_id\":\"" << json_escape(upgrade_id)
            << "\",\"status\":\"" << status << "\"";
    if (!code.empty()) payload << ",\"failure_code\":\"" << json_escape(code) << "\"";
    if (!message.empty()) payload << ",\"failure_message\":\"" << json_escape(message) << "\"";
    payload << "}";
    const std::string payload_text = payload.str();
    const auto sequence = next_sequence(state_dir);
    const std::string payload_hash = "sha256:" + sha256_hex(payload_text);
    std::ostringstream envelope;
    envelope << "{"
             << "\"protocol\":\"neta-agent/1\","
             << "\"schema_version\":1,"
             << "\"message_id\":\"" << random_uuid() << "\","
             << "\"message_type\":\"UpgradeProgress\","
             << "\"agent_id\":\"" << json_escape(identity.agent_id) << "\","
             << "\"created_at\":\"" << iso8601_now() << "\","
             << "\"expires_at\":\"" << iso8601_now(std::chrono::minutes(5)) << "\","
             << "\"sequence\":" << sequence << ','
             << "\"correlation_id\":null,"
             << "\"payload_hash\":\"" << payload_hash << "\","
             << "\"payload\":" << payload_text << ','
             << "\"signature\":{"
             << "\"algorithm\":\"UNSIGNED-NAP1-DRAFT\","
             << "\"key_id\":\"" << json_escape(identity.certificate_sha256) << "\","
             << "\"value\":\"transport-mtls-only\"}"
             << "}";
    post_progress(state_dir, envelope.str());
}

void run_upgrade_worker(const UpgradeWorkerOptions& options) {
    if (options.state_dir.empty() || options.install_root.empty())
        throw std::runtime_error("upgrade worker requires state_dir and install_root");
    UpgradeStateStore state_store(options.state_dir);
    auto state = state_store.load();
    if (!state) throw std::runtime_error("no pending upgrade instruction");
    UpgradeActivationStore activation_store(options.state_dir);
    UpgradeActivationRecord activation;
    activation.upgrade_id = state->instruction.upgrade_id;
    activation.install_root = options.install_root;

    try {
        if (state->state != UpgradeLocalState::Verified) {
            best_effort_report(options.state_dir, state->instruction.upgrade_id, "DOWNLOADING");
            state = download_pending_upgrade(options.state_dir);
        }
        best_effort_report(options.state_dir, state->instruction.upgrade_id, "INSTALLING");
        activation.state = UpgradeActivationState::Installing;
        activation_store.save(activation);
        const auto target = extract_version(*state, options.install_root);
        activation.active_target = target.string();
        stop_service(options.service_name);
        activation.previous_target = activate_version(options.install_root, target);
        write_installed_build(options.state_dir, state->instruction);
        activation_store.save(activation);
        start_service(options.service_name);
        if (!wait_for_health(options, state->instruction))
            throw std::runtime_error("new agent did not become locally healthy before timeout");
        activation.state = UpgradeActivationState::LocalHealthy;
        activation.failure_code.clear();
        activation.failure_message.clear();
        activation_store.save(activation);
        best_effort_report(options.state_dir, state->instruction.upgrade_id, "LOCAL_HEALTHY");
    } catch (const std::exception& error) {
        const std::string message = bounded(error.what(), kFailureMessageMax);
        activation.state = UpgradeActivationState::Failed;
        activation.failure_code = "HEALTH_OR_ACTIVATION_FAILED";
        activation.failure_message = message;
        activation_store.save(activation);
        best_effort_report(options.state_dir, state->instruction.upgrade_id, "FAILED",
                           activation.failure_code, message);
        try {
            stop_service(options.service_name);
            rollback_version(activation);
            start_service(options.service_name);
            activation.state = UpgradeActivationState::RolledBack;
            activation.failure_code = "ROLLED_BACK_AFTER_FAILURE";
            activation_store.save(activation);
            best_effort_report(options.state_dir, state->instruction.upgrade_id, "ROLLED_BACK",
                               activation.failure_code, message);
        } catch (const std::exception& rollback_error) {
            activation.failure_code = "ROLLBACK_FAILED";
            activation.failure_message = bounded(std::string(error.what()) + "; rollback: " + rollback_error.what(),
                                                 kFailureMessageMax);
            activation_store.save(activation);
            best_effort_report(options.state_dir, state->instruction.upgrade_id, "FAILED",
                               activation.failure_code, activation.failure_message);
        }
        throw;
    }
}

bool launch_upgrade_worker_if_needed(const std::filesystem::path& state_dir) {
    UpgradeStateStore store(state_dir);
    const auto state = store.load();
    if (!state || state->state == UpgradeLocalState::Failed) return false;
    UpgradeActivationStore activation_store(state_dir);
    if (const auto activation = activation_store.load()) {
        if (activation->upgrade_id == state->instruction.upgrade_id &&
            (activation->state == UpgradeActivationState::Installing ||
             activation->state == UpgradeActivationState::LocalHealthy)) return false;
    }
#ifdef _WIN32
    const wchar_t* program_data = _wgetenv(L"ProgramData");
    const std::filesystem::path root = program_data == nullptr
        ? std::filesystem::path(L"C:\\ProgramData\\NETA")
        : std::filesystem::path(program_data) / L"NETA";
    const std::filesystem::path install_root = L"C:\\Program Files\\NETA";
    const auto updater = install_root / L"neta-agent-updater.exe";
    std::wstring command = quote_windows_arg(updater.wstring()) + L" apply --state-dir " +
                           quote_windows_arg(state_dir.wstring()) + L" --install-root " +
                           quote_windows_arg(install_root.wstring()) + L" --service NETAAgent";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(updater.c_str(), command.data(), nullptr, nullptr, FALSE,
                        DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, nullptr, root.c_str(),
                        &startup, &process)) return false;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
#else
    const std::string unit = "neta-agent-upgrade-" + state->instruction.upgrade_id;
    const int rc = run_process({"/usr/bin/systemd-run", "--unit", unit, "--collect", "--quiet",
        "/usr/local/libexec/neta-agent-updater", "apply",
        "--state-dir", state_dir.string(), "--install-root", "/opt/neta-agent",
        "--service", "neta-agent.service"});
    return rc == 0;
#endif
}

} // namespace neta
