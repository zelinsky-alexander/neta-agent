#include "neta/upgrade.hpp"
#include "neta_build_info.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace neta {
namespace {

using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

struct ParsedHttpsUrl {
    std::string host;
    std::string port;
    std::string path;
};

struct HttpGetResponse {
    int status{0};
    std::string headers;
    std::string body;
};

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }).base();
    if (first >= last) return {};
    return std::string(first, last);
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

std::string json_unescape_string(const std::string& text, std::size_t& pos) {
    if (pos >= text.size() || text[pos] != '"') throw std::runtime_error("expected JSON string");
    ++pos;
    std::string out;
    while (pos < text.size()) {
        const char c = text[pos++];
        if (c == '"') return out;
        if (c != '\\') {
            if (static_cast<unsigned char>(c) < 0x20) throw std::runtime_error("control byte in JSON string");
            out.push_back(c);
            continue;
        }
        if (pos >= text.size()) throw std::runtime_error("unterminated JSON escape");
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
            default: throw std::runtime_error("unsupported JSON escape");
        }
    }
    throw std::runtime_error("unterminated JSON string");
}

void skip_space(const std::string& text, std::size_t& pos) {
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
}

std::optional<std::string> object_member_string(const std::string& object, const std::string& key) {
    std::size_t pos = 0;
    skip_space(object, pos);
    if (pos >= object.size() || object[pos] != '{') throw std::runtime_error("expected JSON object");
    ++pos;
    for (;;) {
        skip_space(object, pos);
        if (pos < object.size() && object[pos] == '}') return std::nullopt;
        const std::string current_key = json_unescape_string(object, pos);
        skip_space(object, pos);
        if (pos >= object.size() || object[pos] != ':') throw std::runtime_error("expected JSON member separator");
        ++pos;
        skip_space(object, pos);
        if (current_key == key) {
            if (object.compare(pos, 4, "null") == 0) return std::nullopt;
            return json_unescape_string(object, pos);
        }

        bool in_string = false;
        bool escaped = false;
        int nested = 0;
        while (pos < object.size()) {
            const char c = object[pos];
            if (in_string) {
                ++pos;
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') in_string = false;
                continue;
            }
            if (c == '"') { in_string = true; ++pos; continue; }
            if (c == '{' || c == '[') { ++nested; ++pos; continue; }
            if (c == '}' || c == ']') {
                if (nested == 0) break;
                --nested;
                ++pos;
                continue;
            }
            if (c == ',' && nested == 0) { ++pos; break; }
            ++pos;
        }
    }
}

std::optional<std::string> object_member_object(const std::string& object, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    std::size_t search = 0;
    while ((search = object.find(needle, search)) != std::string::npos) {
        std::size_t pos = search + needle.size();
        skip_space(object, pos);
        if (pos >= object.size() || object[pos] != ':') { search += needle.size(); continue; }
        ++pos;
        skip_space(object, pos);
        if (object.compare(pos, 4, "null") == 0) return std::nullopt;
        if (pos >= object.size() || object[pos] != '{') throw std::runtime_error(key + " must be a JSON object");
        const std::size_t begin = pos;
        int depth = 0;
        bool in_string = false;
        bool escaped = false;
        for (; pos < object.size(); ++pos) {
            const char c = object[pos];
            if (in_string) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') in_string = false;
                continue;
            }
            if (c == '"') { in_string = true; continue; }
            if (c == '{') ++depth;
            else if (c == '}' && --depth == 0) return object.substr(begin, pos - begin + 1);
        }
        throw std::runtime_error("unterminated JSON object member: " + key);
    }
    return std::nullopt;
}

std::string require_member(const std::string& object, const std::string& key) {
    auto value = object_member_string(object, key);
    if (!value || value->empty()) throw std::runtime_error("upgrade instruction missing " + key);
    return *value;
}

bool is_hex(const std::string& value, std::size_t size) {
    return value.size() == size && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

bool looks_like_uuid(const std::string& value) {
    if (value.size() != 36) return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (std::isxdigit(static_cast<unsigned char>(value[i])) == 0) {
            return false;
        }
    }
    return true;
}

std::string normalize_sha256(std::string value) {
    value = lower(trim(std::move(value)));
    if (value.starts_with("sha256:")) value.erase(0, 7);
    if (!is_hex(value, 64)) throw std::runtime_error("upgrade artifact SHA-256 is invalid");
    return value;
}

bool is_trusted_github_host(const std::string& host) {
    const std::string normalized = lower(host);
    if (normalized == "github.com") return true;
    constexpr std::string_view suffix = ".githubusercontent.com";
    return normalized.size() > suffix.size() && normalized.ends_with(suffix);
}

ParsedHttpsUrl parse_trusted_https_url(const std::string& url) {
    constexpr std::string_view prefix = "https://";
    if (!url.starts_with(prefix)) throw std::runtime_error("upgrade artifact URL must use https://");
    if (url.find('#') != std::string::npos) throw std::runtime_error("upgrade artifact URL must not contain a fragment");
    const auto authority_begin = prefix.size();
    const auto slash = url.find('/', authority_begin);
    const std::string authority = slash == std::string::npos
        ? url.substr(authority_begin) : url.substr(authority_begin, slash - authority_begin);
    if (authority.empty() || authority.find('@') != std::string::npos)
        throw std::runtime_error("upgrade artifact URL authority is invalid");

    ParsedHttpsUrl result;
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos) {
        result.host = authority.substr(0, colon);
        result.port = authority.substr(colon + 1);
    } else {
        result.host = authority;
        result.port = "443";
    }
    result.host = lower(result.host);
    if (result.host.empty() || result.port != "443" || !is_trusted_github_host(result.host))
        throw std::runtime_error("upgrade artifact URL must use trusted GitHub HTTPS hosting on port 443");
    result.path = slash == std::string::npos ? "/" : url.substr(slash);
    if (result.path.empty()) result.path = "/";
    return result;
}

void validate_artifact_name(const std::string& name) {
    if (name.empty() || name == "." || name == ".." ||
        name.find('/') != std::string::npos || name.find('\\') != std::string::npos ||
        name.find('\0') != std::string::npos) {
        throw std::runtime_error("upgrade artifact name must be a single safe file name");
    }
}

std::string header_value(const std::string& headers, const std::string& wanted) {
    const std::string wanted_lower = lower(wanted);
    std::istringstream lines(headers);
    std::string line;
    std::getline(lines, line);
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (lower(trim(line.substr(0, colon))) == wanted_lower)
            return trim(line.substr(colon + 1));
    }
    return {};
}

std::string decode_chunked(const std::string& input, std::size_t max_bytes) {
    std::size_t pos = 0;
    std::string output;
    output.reserve(std::min(input.size(), max_bytes));
    for (;;) {
        const auto line_end = input.find("\r\n", pos);
        if (line_end == std::string::npos) throw std::runtime_error("invalid chunked artifact response");
        std::string size_text = input.substr(pos, line_end - pos);
        const auto extension = size_text.find(';');
        if (extension != std::string::npos) size_text.resize(extension);
        size_text = trim(size_text);
        std::size_t chunk_size = 0;
        const auto parsed = std::from_chars(size_text.data(), size_text.data() + size_text.size(), chunk_size, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != size_text.data() + size_text.size())
            throw std::runtime_error("invalid chunk size in artifact response");
        pos = line_end + 2;
        if (chunk_size == 0) return output;
        if (chunk_size > max_bytes - output.size()) throw std::runtime_error("upgrade artifact exceeds configured size limit");
        if (chunk_size > input.size() - pos) throw std::runtime_error("truncated chunked artifact response");
        output.append(input, pos, chunk_size);
        pos += chunk_size;
        if (input.size() - pos < 2 || input.compare(pos, 2, "\r\n") != 0)
            throw std::runtime_error("invalid chunk terminator in artifact response");
        pos += 2;
    }
}

[[noreturn]] void ssl_error(const std::string& message) {
    const unsigned long code = ERR_get_error();
    char buffer[256]{};
    if (code != 0) ERR_error_string_n(code, buffer, sizeof(buffer));
    throw std::runtime_error(message + (code == 0 ? std::string{} : std::string(": ") + buffer));
}

#ifdef _WIN32
void ensure_winsock() {
    static const bool initialized = [] {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw std::runtime_error("WSAStartup failed for upgrade download");
        return true;
    }();
    (void)initialized;
}
#else
void ensure_winsock() {}
#endif

HttpGetResponse https_get_once(const ParsedHttpsUrl& url, std::size_t max_bytes) {
    ensure_winsock();
    SslCtxPtr context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!context) ssl_error("SSL_CTX_new failed for upgrade download");
    if (SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION) != 1)
        ssl_error("cannot set minimum TLS version for upgrade download");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(context.get()) != 1)
        ssl_error("cannot load system trust roots for upgrade download");

    BioPtr bio(BIO_new_ssl_connect(context.get()), BIO_free_all);
    if (!bio) ssl_error("BIO_new_ssl_connect failed");
    SSL* ssl = nullptr;
    BIO_get_ssl(bio.get(), &ssl);
    if (ssl == nullptr) throw std::runtime_error("upgrade download TLS handle unavailable");
    if (SSL_set_tlsext_host_name(ssl, url.host.c_str()) != 1)
        ssl_error("cannot set upgrade download TLS SNI");
    X509_VERIFY_PARAM* verify = SSL_get0_param(ssl);
    if (verify == nullptr || X509_VERIFY_PARAM_set1_host(verify, url.host.c_str(), 0) != 1)
        ssl_error("cannot configure upgrade download hostname verification");

    const std::string endpoint = url.host + ":" + url.port;
    BIO_set_conn_hostname(bio.get(), endpoint.c_str());
    if (BIO_do_connect(bio.get()) <= 0 || BIO_do_handshake(bio.get()) <= 0)
        ssl_error("upgrade artifact HTTPS connection failed");
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        throw std::runtime_error("upgrade artifact TLS certificate verification failed");

    std::ostringstream request;
    request << "GET " << url.path << " HTTP/1.1\r\n"
            << "Host: " << url.host << "\r\n"
            << "User-Agent: neta-agent-updater/1\r\n"
            << "Accept: application/octet-stream\r\n"
            << "Connection: close\r\n\r\n";
    const std::string wire = request.str();
    if (BIO_write(bio.get(), wire.data(), static_cast<int>(wire.size())) != static_cast<int>(wire.size()))
        ssl_error("upgrade artifact HTTPS request failed");

    constexpr std::size_t header_allowance = 1024U * 1024U;
    if (max_bytes > std::numeric_limits<std::size_t>::max() - header_allowance)
        throw std::runtime_error("upgrade size limit is too large");
    const std::size_t response_limit = max_bytes + header_allowance;
    std::string response;
    std::array<char, 16384> buffer{};
    for (;;) {
        const int count = BIO_read(bio.get(), buffer.data(), static_cast<int>(buffer.size()));
        if (count > 0) {
            if (static_cast<std::size_t>(count) > response_limit - response.size())
                throw std::runtime_error("upgrade artifact exceeds configured size limit");
            response.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0) break;
        if (BIO_should_retry(bio.get())) continue;
        break;
    }

    const auto header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) throw std::runtime_error("invalid HTTP response while downloading upgrade");
    HttpGetResponse result;
    result.headers = response.substr(0, header_end + 2);
    std::istringstream status_line(response.substr(0, response.find("\r\n")));
    std::string http_version;
    status_line >> http_version >> result.status;
    if (result.status <= 0) throw std::runtime_error("invalid HTTP status while downloading upgrade");

    std::string body = response.substr(header_end + 4);
    const std::string transfer_encoding = lower(header_value(result.headers, "Transfer-Encoding"));
    if (transfer_encoding.find("chunked") != std::string::npos) {
        result.body = decode_chunked(body, max_bytes);
    } else {
        const std::string content_length = header_value(result.headers, "Content-Length");
        if (!content_length.empty()) {
            std::size_t declared = 0;
            const auto parsed = std::from_chars(content_length.data(), content_length.data() + content_length.size(), declared);
            if (parsed.ec != std::errc{} || parsed.ptr != content_length.data() + content_length.size())
                throw std::runtime_error("invalid Content-Length while downloading upgrade");
            if (declared > max_bytes) throw std::runtime_error("upgrade artifact exceeds configured size limit");
            if (body.size() != declared) throw std::runtime_error("truncated upgrade artifact response");
        }
        if (body.size() > max_bytes) throw std::runtime_error("upgrade artifact exceeds configured size limit");
        result.body = std::move(body);
    }
    return result;
}

std::string https_download_body(std::string url, std::size_t max_bytes) {
    for (int redirects = 0; redirects <= 5; ++redirects) {
        const auto parsed = parse_trusted_https_url(url);
        const auto response = https_get_once(parsed, max_bytes);
        if (response.status == 200) return response.body;
        if (response.status == 301 || response.status == 302 || response.status == 303 ||
            response.status == 307 || response.status == 308) {
            const std::string location = header_value(response.headers, "Location");
            if (location.empty()) throw std::runtime_error("upgrade download redirect is missing Location");
            parse_trusted_https_url(location);
            url = location;
            continue;
        }
        throw std::runtime_error("upgrade artifact download failed with HTTP " + std::to_string(response.status));
    }
    throw std::runtime_error("upgrade artifact download exceeded redirect limit");
}

std::string sha256_file(const std::filesystem::path& path, std::size_t max_bytes) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open downloaded upgrade artifact: " + path.string());
    MdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
        ssl_error("cannot initialize upgrade SHA-256 verification");

    std::array<char, 65536> buffer{};
    std::size_t total = 0;
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count <= 0) break;
        const auto size = static_cast<std::size_t>(count);
        if (size > max_bytes - total) throw std::runtime_error("upgrade artifact exceeds configured size limit");
        total += size;
        if (EVP_DigestUpdate(context.get(), buffer.data(), size) != 1)
            ssl_error("upgrade SHA-256 verification failed");
    }
    if (!input.eof() && input.fail()) throw std::runtime_error("failed reading upgrade artifact");

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1)
        ssl_error("cannot finalize upgrade SHA-256 verification");
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_size; ++i) out << std::setw(2) << static_cast<unsigned int>(digest[i]);
    return out.str();
}

void atomic_write(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    const auto temp = path.string() + ".tmp";
    {
        std::ofstream output(temp, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("cannot write upgrade state: " + temp);
        output << content;
        if (!output) throw std::runtime_error("failed writing upgrade state: " + temp);
    }
#ifndef _WIN32
    std::filesystem::permissions(temp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
#endif
    std::error_code ec;
    std::filesystem::rename(temp, path, ec);
#ifdef _WIN32
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(temp, path, ec);
    }
#endif
    if (ec) {
        std::filesystem::remove(temp);
        throw std::runtime_error("cannot atomically replace upgrade state: " + ec.message());
    }
}

std::string state_json(const UpgradeState& state) {
    const auto& i = state.instruction;
    std::ostringstream out;
    out << "{\n"
        << "  \"upgrade_id\": \"" << json_escape(i.upgrade_id) << "\",\n"
        << "  \"version\": \"" << json_escape(i.version) << "\",\n"
        << "  \"build_id\": \"" << json_escape(i.build_id) << "\",\n"
        << "  \"git_commit\": \"" << json_escape(i.git_commit) << "\",\n"
        << "  \"os\": \"" << json_escape(i.os) << "\",\n"
        << "  \"arch\": \"" << json_escape(i.arch) << "\",\n"
        << "  \"artifact_name\": \"" << json_escape(i.artifact_name) << "\",\n"
        << "  \"download_url\": \"" << json_escape(i.download_url) << "\",\n"
        << "  \"sha256\": \"" << json_escape(i.sha256) << "\",\n"
        << "  \"state\": \"" << to_string(state.state) << "\",\n"
        << "  \"download_path\": \"" << json_escape(state.download_path.generic_string()) << "\",\n"
        << "  \"last_error\": \"" << json_escape(state.last_error) << "\"\n"
        << "}\n";
    return out.str();
}

UpgradeState state_from_json(const std::string& text) {
    UpgradeState state;
    state.instruction.upgrade_id = require_member(text, "upgrade_id");
    state.instruction.version = require_member(text, "version");
    state.instruction.build_id = require_member(text, "build_id");
    state.instruction.git_commit = require_member(text, "git_commit");
    state.instruction.os = require_member(text, "os");
    state.instruction.arch = require_member(text, "arch");
    state.instruction.artifact_name = require_member(text, "artifact_name");
    state.instruction.download_url = require_member(text, "download_url");
    state.instruction.sha256 = require_member(text, "sha256");
    state.state = upgrade_local_state_from_string(require_member(text, "state"));
    state.download_path = object_member_string(text, "download_path").value_or("");
    state.last_error = object_member_string(text, "last_error").value_or("");
    return state;
}

bool same_instruction(const UpgradeInstruction& a, const UpgradeInstruction& b) {
    return a.upgrade_id == b.upgrade_id && a.version == b.version && a.build_id == b.build_id &&
           lower(a.git_commit) == lower(b.git_commit) && lower(a.os) == lower(b.os) &&
           lower(a.arch) == lower(b.arch) && a.artifact_name == b.artifact_name &&
           a.download_url == b.download_url && normalize_sha256(a.sha256) == normalize_sha256(b.sha256);
}

std::string installed_artifact_sha(const std::filesystem::path& state_dir) {
    if (state_dir.empty()) return {};
    const auto path = state_dir / "installed-build.conf";
    std::ifstream input(path);
    if (!input) return {};
    std::string line;
    while (std::getline(input, line)) {
        constexpr std::string_view prefix = "artifact_sha256=";
        if (line.starts_with(prefix)) {
            try { return normalize_sha256(line.substr(prefix.size())); }
            catch (...) { return {}; }
        }
    }
    return {};
}

} // namespace

BuildIdentity current_build_identity(const std::filesystem::path& state_dir) {
    BuildIdentity build;
    build.version = NETA_BUILD_VERSION;
    build.build_id = NETA_BUILD_ID;
    build.git_commit = lower(NETA_BUILD_GIT_COMMIT);
    build.build_timestamp = NETA_BUILD_TIMESTAMP;
    build.os = lower(NETA_BUILD_OS);
    build.arch = lower(NETA_BUILD_ARCH);
    build.artifact_sha256 = installed_artifact_sha(state_dir);
    build.features = {"build-identity-v1", "upgrade-instruction-v1", "upgrade-download-v1"};
    return build;
}

std::string build_identity_json(const BuildIdentity& build) {
    std::ostringstream out;
    out << "{"
        << "\"version\":\"" << json_escape(build.version) << "\","
        << "\"build_id\":\"" << json_escape(build.build_id) << "\","
        << "\"os\":\"" << json_escape(build.os) << "\","
        << "\"arch\":\"" << json_escape(build.arch) << "\"";
    if (!build.git_commit.empty()) out << ",\"git_commit\":\"" << json_escape(build.git_commit) << "\"";
    if (!build.artifact_sha256.empty()) out << ",\"artifact_sha256\":\"" << json_escape(build.artifact_sha256) << "\"";
    out << ",\"protocol_version\":" << build.protocol_version
        << ",\"schema_version\":" << build.schema_version
        << ",\"features\":[";
    for (std::size_t i = 0; i < build.features.size(); ++i) {
        if (i != 0) out << ',';
        out << '"' << json_escape(build.features[i]) << '"';
    }
    out << "]}";
    return out.str();
}

std::string to_string(UpgradeLocalState state) {
    switch (state) {
        case UpgradeLocalState::Received: return "RECEIVED";
        case UpgradeLocalState::Downloading: return "DOWNLOADING";
        case UpgradeLocalState::Verified: return "VERIFIED";
        case UpgradeLocalState::Failed: return "FAILED";
    }
    throw std::runtime_error("unknown local upgrade state");
}

UpgradeLocalState upgrade_local_state_from_string(const std::string& value) {
    if (value == "RECEIVED") return UpgradeLocalState::Received;
    if (value == "DOWNLOADING") return UpgradeLocalState::Downloading;
    if (value == "VERIFIED") return UpgradeLocalState::Verified;
    if (value == "FAILED") return UpgradeLocalState::Failed;
    throw std::runtime_error("unknown local upgrade state: " + value);
}

std::optional<UpgradeInstruction> parse_upgrade_instruction_response(const std::string& response_body) {
    auto object = object_member_object(response_body, "upgrade");
    if (!object) return std::nullopt;
    UpgradeInstruction instruction;
    instruction.upgrade_id = require_member(*object, "upgrade_id");
    instruction.version = require_member(*object, "version");
    instruction.build_id = require_member(*object, "build_id");
    instruction.git_commit = lower(require_member(*object, "git_commit"));
    instruction.os = lower(require_member(*object, "os"));
    instruction.arch = lower(require_member(*object, "arch"));
    instruction.artifact_name = require_member(*object, "artifact_name");
    instruction.download_url = require_member(*object, "download_url");
    instruction.sha256 = normalize_sha256(require_member(*object, "sha256"));
    return instruction;
}

void validate_upgrade_instruction(const UpgradeInstruction& instruction, const BuildIdentity& local_build) {
    if (!looks_like_uuid(instruction.upgrade_id)) throw std::runtime_error("upgrade_id is not a UUID");
    if (instruction.version.empty() || instruction.build_id.empty())
        throw std::runtime_error("upgrade target version/build_id is missing");
    if (!is_hex(lower(instruction.git_commit), 40))
        throw std::runtime_error("upgrade target git_commit must be a full commit SHA");
    if (lower(instruction.os) != lower(local_build.os) || lower(instruction.arch) != lower(local_build.arch))
        throw std::runtime_error("upgrade target platform does not match this agent");
    validate_artifact_name(instruction.artifact_name);
    parse_trusted_https_url(instruction.download_url);
    normalize_sha256(instruction.sha256);

    const bool same_build = instruction.version == local_build.version && instruction.build_id == local_build.build_id &&
                            lower(instruction.git_commit) == lower(local_build.git_commit);
    const bool same_artifact = !local_build.artifact_sha256.empty() &&
                               normalize_sha256(instruction.sha256) == normalize_sha256(local_build.artifact_sha256);
    if (same_build && (local_build.artifact_sha256.empty() || same_artifact))
        throw std::runtime_error("upgrade target is already the running build");
}

UpgradeStateStore::UpgradeStateStore(std::filesystem::path state_dir) : state_dir_(std::move(state_dir)) {
    if (state_dir_.empty()) throw std::runtime_error("upgrade state directory is required");
}

std::filesystem::path UpgradeStateStore::path() const {
    return state_dir_ / "upgrade" / "current.json";
}

std::optional<UpgradeState> UpgradeStateStore::load() const {
    if (!std::filesystem::exists(path())) return std::nullopt;
    std::ifstream input(path(), std::ios::binary);
    if (!input) throw std::runtime_error("cannot read durable upgrade state");
    return state_from_json(std::string((std::istreambuf_iterator<char>(input)), {}));
}

UpgradeState UpgradeStateStore::accept(const UpgradeInstruction& instruction, const BuildIdentity& local_build) {
    validate_upgrade_instruction(instruction, local_build);
    if (auto existing = load()) {
        if (existing->instruction.upgrade_id == instruction.upgrade_id) {
            if (!same_instruction(existing->instruction, instruction))
                throw std::runtime_error("coordinator repeated upgrade_id with changed immutable target fields");
            return *existing;
        }
        if (existing->state != UpgradeLocalState::Failed)
            throw std::runtime_error("another local upgrade is already active");
    }
    UpgradeState state;
    state.instruction = instruction;
    save(state);
    return state;
}

void UpgradeStateStore::save(const UpgradeState& state) const {
    atomic_write(path(), state_json(state));
}

void ArtifactDownloader::verify_file(const std::filesystem::path& path,
                                     const std::string& expected_sha256,
                                     std::size_t max_bytes) {
    const std::string expected = normalize_sha256(expected_sha256);
    const std::string actual = sha256_file(path, max_bytes);
    if (actual != expected) throw std::runtime_error("downloaded upgrade artifact SHA-256 mismatch");
}

std::filesystem::path ArtifactDownloader::download_and_verify(
    const UpgradeInstruction& instruction,
    const std::filesystem::path& destination_dir,
    std::size_t max_bytes) {
    validate_artifact_name(instruction.artifact_name);
    parse_trusted_https_url(instruction.download_url);
    const std::string expected = normalize_sha256(instruction.sha256);
    std::filesystem::create_directories(destination_dir);
    const auto final_path = destination_dir / instruction.artifact_name;
    if (std::filesystem::exists(final_path)) {
        try {
            verify_file(final_path, expected, max_bytes);
            return final_path;
        } catch (...) {
            std::filesystem::remove(final_path);
        }
    }

    const std::string body = https_download_body(instruction.download_url, max_bytes);
    const auto part_path = final_path.string() + ".part";
    {
        std::ofstream output(part_path, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("cannot create upgrade download file");
        output.write(body.data(), static_cast<std::streamsize>(body.size()));
        if (!output) throw std::runtime_error("failed writing upgrade download file");
    }
    try {
        verify_file(part_path, expected, max_bytes);
        std::error_code ec;
        std::filesystem::rename(part_path, final_path, ec);
#ifdef _WIN32
        if (ec) {
            std::filesystem::remove(final_path, ec);
            ec.clear();
            std::filesystem::rename(part_path, final_path, ec);
        }
#endif
        if (ec) throw std::runtime_error("cannot finalize verified upgrade artifact: " + ec.message());
    } catch (...) {
        std::filesystem::remove(part_path);
        throw;
    }
    return final_path;
}

std::optional<UpgradeState> accept_upgrade_from_coordinator_response(
    const std::filesystem::path& state_dir,
    const std::string& response_body) {
    auto instruction = parse_upgrade_instruction_response(response_body);
    if (!instruction) return std::nullopt;
    UpgradeStateStore store(state_dir);
    return store.accept(*instruction, current_build_identity(state_dir));
}

UpgradeState download_pending_upgrade(const std::filesystem::path& state_dir, std::size_t max_bytes) {
    UpgradeStateStore store(state_dir);
    auto state = store.load();
    if (!state) throw std::runtime_error("no pending upgrade instruction");
    if (state->state == UpgradeLocalState::Verified) return *state;
    if (state->state == UpgradeLocalState::Failed)
        throw std::runtime_error("pending upgrade is in FAILED state: " + state->last_error);

    state->state = UpgradeLocalState::Downloading;
    state->last_error.clear();
    store.save(*state);
    try {
        const auto directory = state_dir / "upgrade" / "downloads" / state->instruction.upgrade_id;
        state->download_path = ArtifactDownloader::download_and_verify(state->instruction, directory, max_bytes);
        state->state = UpgradeLocalState::Verified;
        store.save(*state);
        return *state;
    } catch (const std::exception& e) {
        state->state = UpgradeLocalState::Failed;
        state->last_error = e.what();
        if (state->last_error.size() > 1000) state->last_error.resize(1000);
        store.save(*state);
        throw;
    }
}

} // namespace neta
