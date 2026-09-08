#include "neta/fleet_client.hpp"
#include "neta/crypto.hpp"
#include "neta/rule_update.hpp"
#include "neta/rules/rule_set_loader.hpp"
#include "neta/verdict.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace neta {
namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
struct ParsedUrl { std::string host; std::string port; };

[[noreturn]] void ssl_error(const std::string& what) {
    const unsigned long code = ERR_get_error(); char buffer[256]{};
    if (code != 0) ERR_error_string_n(code, buffer, sizeof(buffer));
    throw std::runtime_error(what + (code != 0 ? std::string(": ") + buffer : std::string{}));
}

ParsedUrl parse_https_url(const std::string& url) {
    constexpr std::string_view prefix = "https://";
    if (!url.starts_with(prefix)) throw std::runtime_error("coordinator URL must use https://");
    std::string authority = url.substr(prefix.size()); const auto slash = authority.find('/');
    if (slash != std::string::npos) authority.resize(slash);
    ParsedUrl out;
    if (!authority.empty() && authority.front() == '[') {
        const auto close = authority.find(']'); if (close == std::string::npos) throw std::runtime_error("invalid coordinator IPv6 URL");
        out.host = authority.substr(1, close - 1);
        out.port = close + 1 < authority.size() && authority[close + 1] == ':' ? authority.substr(close + 2) : "443";
    } else {
        const auto colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) { out.host = authority.substr(0, colon); out.port = authority.substr(colon + 1); }
        else { out.host = authority; out.port = "443"; }
    }
    if (out.host.empty() || out.port.empty()) throw std::runtime_error("invalid coordinator URL"); return out;
}

bool is_ip_literal(const std::string& host) {
    if (host.find(':') != std::string::npos) return true;
    return !host.empty() && std::all_of(host.begin(), host.end(), [](unsigned char c) { return std::isdigit(c) != 0 || c == '.'; });
}

void configure_peer(SSL* ssl, const std::string& host) {
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl); if (!param) throw std::runtime_error("TLS verification parameters unavailable");
    if (is_ip_literal(host)) {
        if (X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str()) != 1) ssl_error("IP verification setup failed");
    } else {
        if (X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0) != 1) ssl_error("hostname verification setup failed");
        if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) ssl_error("TLS SNI setup failed");
    }
}

std::string decode_chunked(const std::string& body) {
    std::string out; std::size_t pos = 0;
    for (;;) {
        const auto line_end = body.find("\r\n", pos); if (line_end == std::string::npos) return body;
        std::string size_text = body.substr(pos, line_end - pos); const auto extension = size_text.find(';');
        if (extension != std::string::npos) size_text.resize(extension);
        std::size_t size = 0; try { size = static_cast<std::size_t>(std::stoull(size_text, nullptr, 16)); } catch (...) { return body; }
        pos = line_end + 2; if (size == 0) return out;
        if (size > body.size() - pos) throw std::runtime_error("truncated chunked coordinator response");
        out.append(body, pos, size); pos += size;
        if (body.size() - pos < 2 || body.compare(pos, 2, "\r\n") != 0) throw std::runtime_error("invalid chunked coordinator response");
        pos += 2;
    }
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); }); return value;
}

std::string header_value(const std::string& headers, const std::string& name) {
    const auto needle = lower(name) + ":"; std::istringstream lines(headers); std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back(); const auto colon = line.find(':'); if (colon == std::string::npos) continue;
        if (lower(line.substr(0, colon + 1)) != needle) continue; std::string value = line.substr(colon + 1);
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin()); return value;
    }
    return {};
}

std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
            case '\\': out << "\\\\"; break; case '"': out << "\\\""; break; case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break; case '\t': out << "\\t"; break;
            default: if (c < 0x20) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec; else out << static_cast<char>(c);
        }
    }
    return out.str();
}

std::string authenticated_post(const std::filesystem::path& state_dir, const std::string& path, const std::string& body) {
    const auto identity = FleetClient::load_identity(state_dir); const auto url = parse_https_url(identity.coordinator);
    SslCtxPtr context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free); if (!context) ssl_error("SSL_CTX_new failed");
    if (SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 || SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1) ssl_error("TLS 1.3 configuration failed");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(context.get(), (state_dir / "fleet-ca.crt").string().c_str(), nullptr) != 1) ssl_error("cannot load Fleet CA");
    if (SSL_CTX_use_certificate_chain_file(context.get(), (state_dir / "agent.crt").string().c_str()) != 1) ssl_error("cannot load agent certificate");
    if (SSL_CTX_use_PrivateKey_file(context.get(), (state_dir / "agent.key").string().c_str(), SSL_FILETYPE_PEM) != 1) ssl_error("cannot load agent private key");
    if (SSL_CTX_check_private_key(context.get()) != 1) ssl_error("agent certificate/private key mismatch");

    BIO* raw = BIO_new_ssl_connect(context.get()); if (!raw) ssl_error("BIO_new_ssl_connect failed"); BioPtr bio(raw, BIO_free_all);
    SSL* ssl = nullptr; BIO_get_ssl(bio.get(), &ssl); if (!ssl) ssl_error("TLS BIO has no SSL object"); configure_peer(ssl, url.host);
    const std::string endpoint = url.host.find(':') == std::string::npos ? url.host + ":" + url.port : "[" + url.host + "]:" + url.port;
    BIO_set_conn_hostname(bio.get(), endpoint.c_str());
    if (BIO_do_connect(bio.get()) <= 0 || BIO_do_handshake(bio.get()) <= 0) ssl_error("coordinator TLS connection failed");
    if (SSL_get_verify_result(ssl) != X509_V_OK) throw std::runtime_error("coordinator certificate verification failed");

    std::ostringstream request; request << "POST " << path << " HTTP/1.1\r\nHost: " << url.host
        << "\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
    const std::string wire = request.str(); std::size_t offset = 0;
    while (offset < wire.size()) {
        const int chunk = static_cast<int>(std::min<std::size_t>(wire.size() - offset, 1U << 20)); const int written = BIO_write(bio.get(), wire.data() + offset, chunk);
        if (written <= 0) ssl_error("HTTPS write failed"); offset += static_cast<std::size_t>(written);
    }
    std::string response; char buffer[8192];
    for (;;) { const int count = BIO_read(bio.get(), buffer, static_cast<int>(sizeof(buffer))); if (count > 0) { response.append(buffer, static_cast<std::size_t>(count)); continue; } if (count == 0) break; if (BIO_should_retry(bio.get())) continue; break; }
    const auto header_end = response.find("\r\n\r\n"); if (header_end == std::string::npos) throw std::runtime_error("invalid coordinator HTTP response");
    std::istringstream status_line(response.substr(0, response.find("\r\n"))); std::string http; int status = 0; status_line >> http >> status;
    const std::string headers = response.substr(0, header_end + 2); std::string response_body = response.substr(header_end + 4);
    if (lower(header_value(headers, "Transfer-Encoding")).find("chunked") != std::string::npos) response_body = decode_chunked(response_body);
    if (status < 200 || status >= 300) throw std::runtime_error("coordinator rule request failed with HTTP " + std::to_string(status) + ": " + response_body);
    return response_body;
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary); if (!input) throw std::runtime_error("cannot open rule bundle: " + path.string());
    return std::string((std::istreambuf_iterator<char>(input)), {});
}

void atomic_write(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path()); const auto temp = path.string() + ".tmp";
    { std::ofstream output(temp, std::ios::binary | std::ios::trunc); if (!output) throw std::runtime_error("cannot write rule bundle: " + temp); output.write(content.data(), static_cast<std::streamsize>(content.size())); if (!output) throw std::runtime_error("failed writing rule bundle"); }
#ifndef _WIN32
    std::filesystem::permissions(temp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace);
#endif
    std::error_code ec; std::filesystem::rename(temp, path, ec);
#ifdef _WIN32
    if (ec) { std::filesystem::remove(path, ec); ec.clear(); std::filesystem::rename(temp, path, ec); }
#endif
    if (ec) { std::filesystem::remove(temp); throw std::runtime_error("cannot atomically activate rule bundle: " + ec.message()); }
}

ActiveRuleBundleState state_from_text(const std::filesystem::path& path, const std::string& text, bool centrally_managed) {
    const auto loaded = rules::RuleSetLoader::load_text(text, path.string());
    ActiveRuleBundleState state; state.path = path; state.revision = loaded.revision; state.version = loaded.version;
    state.sha256 = sha256_hex(text); state.rule_count = loaded.definitions.size(); state.centrally_managed = centrally_managed; return state;
}

} // namespace

std::string FleetClient::fetch_rule_bundle(const std::filesystem::path& state_dir) {
    return authenticated_post(state_dir, "/api/v1/agent/rules/fetch", "{}");
}

std::string FleetClient::acknowledge_rule_bundle(const std::filesystem::path& state_dir, std::uint64_t revision,
                                                 const std::string& sha256, const std::string& status,
                                                 const std::string& error) {
    std::ostringstream body; body << "{\"revision\":" << revision << ",\"sha256\":\"" << json_escape(sha256)
        << "\",\"status\":\"" << json_escape(status) << "\",\"error\":\"" << json_escape(error) << "\"}";
    return authenticated_post(state_dir, "/api/v1/agent/rules/ack", body.str());
}

ActiveRuleBundleState update_rules_from_coordinator(const std::filesystem::path& state_dir) {
    const std::string bundle = FleetClient::fetch_rule_bundle(state_dir);
    const auto parsed = rules::RuleSetLoader::load_text(bundle, "coordinator rule bundle");
    if (parsed.schema_version != 2) throw std::runtime_error("coordinator rule bundle must use schema version 2");
    const std::string hash = sha256_hex(bundle);
    const auto path = state_dir / "rules" / "active.json";
    atomic_write(path, bundle);
    // Installation and runtime activation are distinct. The CLI restarts/reloads the
    // running service and only then sends the final ACTIVE acknowledgement.
    FleetClient::acknowledge_rule_bundle(state_dir, parsed.revision, hash, "INSTALLED");
    return state_from_text(path, bundle, true);
}

ActiveRuleBundleState active_rule_bundle_state(const std::filesystem::path& state_dir) {
    const auto path = state_dir / "rules" / "active.json";
    if (std::filesystem::is_regular_file(path)) return state_from_text(path, read_file(path), true);
    const auto built_in = rules::RuleSetLoader::built_in();
    ActiveRuleBundleState state; state.path.clear(); state.revision = built_in.revision; state.version = built_in.version;
    state.sha256 = rule_set_hash(built_in); state.rule_count = built_in.definitions.size(); state.centrally_managed = false;
    return state;
}

} // namespace neta
