#include "neta/fleet_client.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace neta {
namespace {

using EvidenceBioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using EvidenceSslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

struct EvidenceUrl {
    std::string host;
    std::string port;
};

[[noreturn]] void evidence_ssl_error(const std::string& what) {
    const unsigned long code = ERR_get_error();
    char buffer[256]{};
    if (code != 0) ERR_error_string_n(code, buffer, sizeof(buffer));
    throw std::runtime_error(what + (code != 0 ? std::string(": ") + buffer : std::string{}));
}

EvidenceUrl evidence_parse_https(const std::string& value) {
    constexpr std::string_view prefix = "https://";
    if (!value.starts_with(prefix)) throw std::runtime_error("coordinator URL must use https://");
    std::string authority = value.substr(prefix.size());
    const auto slash = authority.find('/');
    if (slash != std::string::npos) authority.resize(slash);
    EvidenceUrl result;
    if (!authority.empty() && authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string::npos) throw std::runtime_error("invalid coordinator IPv6 URL");
        result.host = authority.substr(1, close - 1);
        result.port = close + 1 < authority.size() && authority[close + 1] == ':'
                ? authority.substr(close + 2) : "443";
    } else {
        const auto colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            result.host = authority.substr(0, colon);
            result.port = authority.substr(colon + 1);
        } else {
            result.host = authority;
            result.port = "443";
        }
    }
    if (result.host.empty() || result.port.empty()) throw std::runtime_error("invalid coordinator URL");
    return result;
}

bool evidence_ip_literal(const std::string& host) {
    if (host.find(':') != std::string::npos) return true;
    return !host.empty() && std::all_of(host.begin(), host.end(), [](unsigned char c) {
        return std::isdigit(c) != 0 || c == '.';
    });
}

void evidence_configure_peer(SSL* ssl, const std::string& host) {
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    if (!param) throw std::runtime_error("TLS verification parameters unavailable");
    if (evidence_ip_literal(host)) {
        if (X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str()) != 1)
            evidence_ssl_error("IP verification setup failed");
    } else {
        if (X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0) != 1)
            evidence_ssl_error("hostname verification setup failed");
        if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1)
            evidence_ssl_error("TLS SNI setup failed");
    }
}

std::string evidence_authenticated_post(const std::filesystem::path& state_dir,
                                        const std::string& path,
                                        const std::string& body) {
    const auto identity = FleetClient::load_identity(state_dir);
    const auto url = evidence_parse_https(identity.coordinator);
    EvidenceSslCtxPtr context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!context) evidence_ssl_error("SSL_CTX_new failed");
    if (SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1)
        evidence_ssl_error("TLS 1.3 configuration failed");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(context.get(), (state_dir / "fleet-ca.crt").string().c_str(), nullptr) != 1)
        evidence_ssl_error("cannot load Fleet CA");
    if (SSL_CTX_use_certificate_chain_file(context.get(), (state_dir / "agent.crt").string().c_str()) != 1)
        evidence_ssl_error("cannot load agent certificate");
    if (SSL_CTX_use_PrivateKey_file(context.get(), (state_dir / "agent.key").string().c_str(), SSL_FILETYPE_PEM) != 1)
        evidence_ssl_error("cannot load agent private key");
    if (SSL_CTX_check_private_key(context.get()) != 1)
        evidence_ssl_error("agent certificate/private key mismatch");

    BIO* raw = BIO_new_ssl_connect(context.get());
    if (!raw) evidence_ssl_error("BIO_new_ssl_connect failed");
    EvidenceBioPtr bio(raw, BIO_free_all);
    SSL* ssl = nullptr;
    BIO_get_ssl(bio.get(), &ssl);
    if (!ssl) evidence_ssl_error("TLS BIO has no SSL object");
    evidence_configure_peer(ssl, url.host);
    const std::string endpoint = url.host.find(':') == std::string::npos
            ? url.host + ":" + url.port : "[" + url.host + "]:" + url.port;
    BIO_set_conn_hostname(bio.get(), endpoint.c_str());
    if (BIO_do_connect(bio.get()) <= 0 || BIO_do_handshake(bio.get()) <= 0)
        evidence_ssl_error("coordinator TLS connection failed");
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        throw std::runtime_error("coordinator certificate verification failed");

    std::ostringstream request;
    request << "POST " << path << " HTTP/1.1\r\nHost: " << url.host
            << "\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: "
            << body.size() << "\r\n\r\n" << body;
    const auto wire = request.str();
    std::size_t offset = 0;
    while (offset < wire.size()) {
        const int chunk = static_cast<int>(std::min<std::size_t>(wire.size() - offset, 1U << 20));
        const int written = BIO_write(bio.get(), wire.data() + offset, chunk);
        if (written <= 0) evidence_ssl_error("artifact evidence HTTPS write failed");
        offset += static_cast<std::size_t>(written);
    }

    std::string response;
    char buffer[8192];
    for (;;) {
        const int count = BIO_read(bio.get(), buffer, static_cast<int>(sizeof(buffer)));
        if (count > 0) {
            response.append(buffer, static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0) break;
        if (BIO_should_retry(bio.get())) continue;
        break;
    }
    const auto line_end = response.find("\r\n");
    const auto header_end = response.find("\r\n\r\n");
    if (line_end == std::string::npos || header_end == std::string::npos)
        throw std::runtime_error("invalid coordinator HTTP response");
    std::istringstream status_line(response.substr(0, line_end));
    std::string http;
    int status = 0;
    status_line >> http >> status;
    const std::string response_body = response.substr(header_end + 4);
    if (status < 200 || status >= 300)
        throw std::runtime_error("coordinator artifact evidence request failed with HTTP " +
                                 std::to_string(status) + ": " + response_body);
    return response_body;
}

}  // namespace

std::string FleetClient::send_evidence_summary(const std::filesystem::path& state_dir,
                                               const std::string& summary_json) {
    if (summary_json.empty()) throw std::invalid_argument("evidence summary JSON is required");
    return evidence_authenticated_post(state_dir, "/api/v1/agent/artifacts/evidence", summary_json);
}

}  // namespace neta
