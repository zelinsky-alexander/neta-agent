#include "neta/yarax_runtime_update.hpp"

#include "neta/fleet_client.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>

namespace neta {
namespace {

std::string shell_quote(const std::string& value) {
    std::string out = "'";
    for (char c : value) out += c == '\'' ? "'\\''" : std::string(1, c);
    return out + "'";
}

std::string run_capture(const std::string& command) {
#ifndef _WIN32
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) throw std::runtime_error("cannot launch runtime control command");
    std::string out; char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) out += buffer;
    const int rc = pclose(pipe);
    if (rc != 0) throw std::runtime_error("runtime control command failed");
    return out;
#else
    (void)command;
    throw std::runtime_error("YARA-X runtime updates are not supported on Windows yet");
#endif
}

std::string json_string(const std::string& json, const std::string& key) {
    const std::regex pattern("\\\"" + key + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    std::smatch match;
    return std::regex_search(json, match, pattern) ? match[1].str() : std::string{};
}

bool json_bool(const std::string& json, const std::string& key) {
    const std::regex pattern("\\\"" + key + "\\\"\\s*:\\s*(true|false)");
    std::smatch match;
    return std::regex_search(json, match, pattern) && match[1].str() == "true";
}

std::string read_trimmed(const std::filesystem::path& path) {
    std::ifstream in(path); if (!in) return {};
    std::string value; std::getline(in, value);
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ' || value.back() == '\t')) value.pop_back();
    return value;
}

void validate_metadata(const std::string& version, const std::string& base, const std::string& sha) {
    static const std::regex version_re("^[0-9]+\\.[0-9]+\\.[0-9]+([.-][A-Za-z0-9._-]+)?$");
    static const std::regex sha_re("^[0-9a-fA-F]{64}$");
    if (!std::regex_match(version, version_re)) throw std::runtime_error("coordinator returned invalid YARA-X version");
    const std::string expected = "https://github.com/zelinsky-alexander/neta-agent/releases/download/yarax-runtime-v" + version;
    if (base != expected) throw std::runtime_error("coordinator returned untrusted YARA-X runtime source");
    if (!std::regex_match(sha, sha_re)) throw std::runtime_error("coordinator returned invalid YARA-X SHA-256");
}

std::string arch_name() {
#ifndef _WIN32
    const auto machine = run_capture("uname -m");
    if (machine.find("aarch64") != std::string::npos || machine.find("arm64") != std::string::npos) return "arm64";
    if (machine.find("x86_64") != std::string::npos || machine.find("amd64") != std::string::npos) return "x86_64";
#endif
    return {};
}

void ack(const FleetIdentity& identity, const std::filesystem::path& state_dir,
         const std::string& installed, const std::string& active,
         const std::string& active_sha, const std::string& desired,
         const std::string& state, const std::string& error = {}) {
#ifndef _WIN32
    std::ostringstream body;
    body << "{\"installedVersion\":\"" << installed << "\",\"activeVersion\":\"" << active
         << "\",\"activeSha256\":\"" << active_sha << "\",\"desiredVersion\":\"" << desired
         << "\",\"state\":\"" << state << "\",\"error\":\"";
    for (char c : error) { if (c == '\\' || c == '"') body << '\\'; if (c == '\n' || c == '\r') body << ' '; else body << c; }
    body << "\"}";
    const std::string url = identity.coordinator + "/api/v1/agent/yarax/runtime/ack";
    const std::string cmd = "curl -fsS --proto '=https' --tlsv1.2 --cacert " + shell_quote((state_dir/"fleet-ca.crt").string()) +
        " --cert " + shell_quote((state_dir/"agent.crt").string()) + " --key " + shell_quote((state_dir/"agent.key").string()) +
        " -H 'Content-Type: application/json' --data " + shell_quote(body.str()) + " " + shell_quote(url) + " >/dev/null";
    static_cast<void>(run_capture(cmd));
#else
    (void)identity;(void)state_dir;(void)installed;(void)active;(void)active_sha;(void)desired;(void)state;(void)error;
#endif
}

} // namespace

YaraXRuntimeUpdateResult update_yarax_runtime_from_coordinator(const std::filesystem::path& state_dir) {
    YaraXRuntimeUpdateResult result;
#ifdef _WIN32
    result.state = "UNSUPPORTED";
    result.detail = "YARA-X runtime distribution currently targets Linux x86_64/arm64";
    return result;
#else
    const auto identity = FleetClient::load_identity(state_dir);
    const std::string current_url = identity.coordinator + "/api/v1/agent/yarax/runtime/current";
    const std::string query = "curl -fsS --proto '=https' --tlsv1.2 --cacert " + shell_quote((state_dir/"fleet-ca.crt").string()) +
        " --cert " + shell_quote((state_dir/"agent.crt").string()) + " --key " + shell_quote((state_dir/"agent.key").string()) + " " + shell_quote(current_url);
    const std::string metadata = run_capture(query);
    result.update_available = json_bool(metadata, "updateAvailable");
    result.desired_version = json_string(metadata, "version");
    result.active_version = read_trimmed("/usr/local/lib/neta/yara-x/current/VERSION");
    if (!result.update_available) { result.state = result.active_version.empty() ? "UNKNOWN" : "ACTIVE"; return result; }

    const std::string base = json_string(metadata, "releaseBaseUrl");
    const std::string sha = json_string(metadata, "sha256");
    validate_metadata(result.desired_version, base, sha);
    if (result.active_version == result.desired_version) {
        const std::string active_sha = read_trimmed("/usr/local/lib/neta/yara-x/current/ARCHIVE_SHA256");
        ack(identity, state_dir, result.active_version, result.active_version, active_sha, result.desired_version, "ACTIVE");
        result.state = "ACTIVE";
        return result;
    }

    const std::string previous_version = result.active_version;
    const std::string previous_sha = read_trimmed("/usr/local/lib/neta/yara-x/current/ARCHIVE_SHA256");
    ack(identity, state_dir, previous_version, previous_version, previous_sha, result.desired_version, "DOWNLOADING");
    try {
        const std::string arch = arch_name();
        if (arch.empty()) throw std::runtime_error("unsupported Linux architecture");
        const std::string asset = "neta-yarax-runtime-v" + result.desired_version + "-linux-" + arch + ".tar.gz";
        const std::string script =
            "set -euo pipefail; TMP=$(mktemp -d); trap 'rm -rf \"$TMP\"' EXIT; "
            "curl -fsSL --proto '=https' --tlsv1.2 " + shell_quote(base + "/" + asset) + " -o \"$TMP/runtime.tgz\"; "
            "ACTUAL=$(sha256sum \"$TMP/runtime.tgz\" | awk '{print $1}'); test \"$ACTUAL\" = " + shell_quote(sha) + "; "
            "mkdir -p \"$TMP/stage\"; tar -xzf \"$TMP/runtime.tgz\" -C \"$TMP/stage\"; "
            "test \"$(tr -d '[:space:]' < \"$TMP/stage/VERSION\")\" = " + shell_quote(result.desired_version) + "; "
            "ldd -r \"$TMP/stage/libyara_x_capi.so\" >/dev/null; ROOT=/usr/local/lib/neta/yara-x; mkdir -p \"$ROOT\"; "
            "PREVIOUS=$(readlink \"$ROOT/current\" 2>/dev/null || true); "
            "DEST=\"$ROOT/" + result.desired_version + "\"; rm -rf \"$DEST.new\"; mkdir -p \"$DEST.new\"; "
            "install -m 0755 \"$TMP/stage/libyara_x_capi.so\" \"$DEST.new/libyara_x_capi.so\"; "
            "install -m 0644 \"$TMP/stage/VERSION\" \"$DEST.new/VERSION\"; "
            "test ! -f \"$TMP/stage/MANIFEST\" || install -m 0644 \"$TMP/stage/MANIFEST\" \"$DEST.new/MANIFEST\"; "
            "test ! -f \"$TMP/stage/LICENSE.YARA-X\" || install -m 0644 \"$TMP/stage/LICENSE.YARA-X\" \"$DEST.new/LICENSE.YARA-X\"; "
            "printf '%s\\n' \"$ACTUAL\" > \"$DEST.new/ARCHIVE_SHA256\"; rm -rf \"$DEST\"; mv \"$DEST.new\" \"$DEST\"; "
            "if [ -n \"$PREVIOUS\" ]; then ln -sfn \"$PREVIOUS\" \"$ROOT/last-known-good.new\"; mv -Tf \"$ROOT/last-known-good.new\" \"$ROOT/last-known-good\"; fi; "
            "ln -sfn " + shell_quote(result.desired_version) + " \"$ROOT/current.new\"; mv -Tf \"$ROOT/current.new\" \"$ROOT/current\"; "
            "if ! ldd -r \"$ROOT/current/libyara_x_capi.so\" >/dev/null 2>&1; then "
            "  if [ -n \"$PREVIOUS\" ] && [ -e \"$ROOT/$PREVIOUS\" ]; then ln -sfn \"$PREVIOUS\" \"$ROOT/current.rollback\"; mv -Tf \"$ROOT/current.rollback\" \"$ROOT/current\"; else rm -f \"$ROOT/current\"; fi; "
            "  exit 1; "
            "fi";
        static_cast<void>(run_capture("bash -c " + shell_quote(script)));
        result.active_version = result.desired_version;
        result.changed = true;
        result.state = "ACTIVE";
        ack(identity, state_dir, result.active_version, result.active_version, sha, result.desired_version, "ACTIVE");
        std::system("systemctl try-restart --no-block neta-agent.service >/dev/null 2>&1 || true");
    } catch (const std::exception& error) {
        result.active_version = read_trimmed("/usr/local/lib/neta/yara-x/current/VERSION");
        result.state = "APPLY_FAILED";
        result.detail = error.what();
        try { ack(identity, state_dir, result.active_version, result.active_version,
                  read_trimmed("/usr/local/lib/neta/yara-x/current/ARCHIVE_SHA256"), result.desired_version, "APPLY_FAILED", error.what()); } catch (...) {}
        throw;
    }
    return result;
#endif
}

} // namespace neta
