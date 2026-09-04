#include "neta/fleet_client.hpp"
#include "neta/crypto.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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
#include <vector>

namespace neta {
namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using ReqPtr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

struct ParsedUrl {
    std::string host;
    std::string port;
};

struct HttpResponse {
    int status{0};
    std::string body;
};

[[noreturn]] void ssl_error(const std::string& what) {
    const unsigned long code = ERR_get_error();
    char buffer[256]{};
    if (code != 0) ERR_error_string_n(code, buffer, sizeof(buffer));
    throw std::runtime_error(what + (code != 0 ? std::string(": ") + buffer : std::string{}));
}

ParsedUrl parse_https_url(const std::string& url) {
    constexpr std::string_view prefix = "https://";
    if (!url.starts_with(prefix)) throw std::runtime_error("coordinator URL must use https://");
    std::string authority = url.substr(prefix.size());
    const auto slash = authority.find('/');
    if (slash != std::string::npos) authority.resize(slash);
    if (authority.empty()) throw std::runtime_error("coordinator URL has no host");

    ParsedUrl out;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string::npos) throw std::runtime_error("invalid IPv6 coordinator URL");
        out.host = authority.substr(1, close - 1);
        out.port = close + 1 < authority.size() && authority[close + 1] == ':'
            ? authority.substr(close + 2) : "443";
    } else {
        const auto colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            out.host = authority.substr(0, colon);
            out.port = authority.substr(colon + 1);
        } else {
            out.host = authority;
            out.port = "443";
        }
    }
    if (out.host.empty() || out.port.empty()) throw std::runtime_error("invalid coordinator URL");
    return out;
}

bool is_ip_literal(const std::string& host) {
    if (host.find(':') != std::string::npos) return true;
    return !host.empty() && std::all_of(host.begin(), host.end(), [](unsigned char c) {
        return std::isdigit(c) != 0 || c == '.';
    });
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
                        << static_cast<int>(c) << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

std::string json_string_value(const std::string& text, const std::string& key) {
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
            default: throw std::runtime_error("unsupported JSON escape in coordinator response");
        }
    }
    throw std::runtime_error("unterminated JSON string in coordinator response");
}

std::string decode_chunked_body(const std::string& body) {
    std::size_t pos = 0;
    std::string decoded;
    for (;;) {
        const auto line_end = body.find("\r\n", pos);
        if (line_end == std::string::npos) return body;
        std::string size_text = body.substr(pos, line_end - pos);
        const auto extension = size_text.find(';');
        if (extension != std::string::npos) size_text.resize(extension);
        if (size_text.empty()) return body;
        std::size_t chunk_size = 0;
        try {
            chunk_size = static_cast<std::size_t>(std::stoull(size_text, nullptr, 16));
        } catch (...) {
            return body;
        }
        pos = line_end + 2;
        if (chunk_size == 0) return decoded;
        if (chunk_size > body.size() - pos) return body;
        decoded.append(body, pos, chunk_size);
        pos += chunk_size;
        if (body.size() - pos < 2 || body.compare(pos, 2, "\r\n") != 0) return body;
        pos += 2;
    }
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path.string());
    return std::string((std::istreambuf_iterator<char>(in)), {});
}

void write_file(const std::filesystem::path& path, const std::string& content) {
    const auto temp = path.wstring() + L".tmp";
    {
        std::ofstream out(std::filesystem::path(temp), std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot write temporary fleet state file");
        out << content;
        if (!out) throw std::runtime_error("failed writing fleet state file");
    }
    std::error_code ec;
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(temp, path, ec);
    }
    if (ec) throw std::runtime_error("cannot replace fleet state file: " + ec.message());
}

std::string bio_to_string(BIO* bio) {
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio, &memory);
    if (memory == nullptr) return {};
    return std::string(memory->data, memory->length);
}

PkeyPtr generate_private_key() {
    EVP_PKEY_CTX* raw = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (raw == nullptr) ssl_error("EVP_PKEY_CTX_new_from_name failed");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(raw, EVP_PKEY_CTX_free);
    if (EVP_PKEY_keygen_init(context.get()) <= 0) ssl_error("EVP_PKEY_keygen_init failed");
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(const_cast<char*>(OSSL_PKEY_PARAM_GROUP_NAME),
                                         const_cast<char*>("prime256v1"), 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(context.get(), params) <= 0) ssl_error("setting EC group failed");
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_generate(context.get(), &key) <= 0 || key == nullptr) ssl_error("private-key generation failed");
    return PkeyPtr(key, EVP_PKEY_free);
}

std::string private_key_pem(EVP_PKEY* key) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        ssl_error("private-key PEM encoding failed");
    return bio_to_string(bio.get());
}

std::string csr_pem(EVP_PKEY* key, const std::string& display_name) {
    ReqPtr request(X509_REQ_new(), X509_REQ_free);
    if (!request) ssl_error("X509_REQ_new failed");
    if (X509_REQ_set_version(request.get(), 0L) != 1) ssl_error("X509_REQ_set_version failed");
    X509_NAME* name = X509_REQ_get_subject_name(request.get());
    const std::string common_name = display_name.empty() ? "neta-agent" : display_name;
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(common_name.c_str()),
                                   -1, -1, 0) != 1) ssl_error("CSR subject creation failed");
    if (X509_REQ_set_pubkey(request.get(), key) != 1) ssl_error("X509_REQ_set_pubkey failed");
    if (X509_REQ_sign(request.get(), key, EVP_sha256()) <= 0) ssl_error("CSR signing failed");
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_X509_REQ(bio.get(), request.get()) != 1) ssl_error("CSR PEM encoding failed");
    return bio_to_string(bio.get());
}

void configure_peer_verification(SSL* ssl, const std::string& host) {
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    if (param == nullptr) throw std::runtime_error("SSL verification parameters unavailable");
    if (is_ip_literal(host)) {
        if (X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str()) != 1)
            ssl_error("IP certificate verification setup failed");
    } else {
        if (X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0) != 1)
            ssl_error("hostname certificate verification setup failed");
        if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1)
            ssl_error("TLS SNI setup failed");
    }
}

HttpResponse https_post(const std::string& coordinator, const std::filesystem::path& fleet_ca,
                        const std::optional<std::filesystem::path>& client_certificate,
                        const std::optional<std::filesystem::path>& client_key,
                        const std::string& path, const std::string& body) {
    const auto url = parse_https_url(coordinator);
    SslCtxPtr context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!context) ssl_error("SSL_CTX_new failed");
    if (SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1)
        ssl_error("TLS 1.3 configuration failed");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(context.get(), fleet_ca.string().c_str(), nullptr) != 1)
        ssl_error("cannot load Fleet CA");

    if (client_certificate && client_key) {
        if (SSL_CTX_use_certificate_chain_file(context.get(), client_certificate->string().c_str()) != 1)
            ssl_error("cannot load agent certificate chain");
        if (SSL_CTX_use_PrivateKey_file(context.get(), client_key->string().c_str(), SSL_FILETYPE_PEM) != 1)
            ssl_error("cannot load agent private key");
        if (SSL_CTX_check_private_key(context.get()) != 1)
            ssl_error("agent certificate does not match private key");
    }

    BIO* raw = BIO_new_ssl_connect(context.get());
    if (raw == nullptr) ssl_error("BIO_new_ssl_connect failed");
    BioPtr bio(raw, BIO_free_all);
    SSL* ssl = nullptr;
    BIO_get_ssl(bio.get(), &ssl);
    if (ssl == nullptr) ssl_error("TLS BIO has no SSL object");
    configure_peer_verification(ssl, url.host);

    const std::string endpoint = url.host.find(':') == std::string::npos
        ? url.host + ":" + url.port
        : "[" + url.host + "]:" + url.port;
    BIO_set_conn_hostname(bio.get(), endpoint.c_str());
    if (BIO_do_connect(bio.get()) <= 0) ssl_error("coordinator TCP connection failed");
    if (BIO_do_handshake(bio.get()) <= 0) ssl_error("coordinator TLS handshake failed");
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        throw std::runtime_error("coordinator certificate verification failed");

    std::ostringstream request;
    request << "POST " << path << " HTTP/1.1\r\n"
            << "Host: " << url.host << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Accept: application/json\r\n"
            << "Connection: close\r\n"
            << "Content-Length: " << body.size() << "\r\n\r\n"
            << body;
    const std::string wire = request.str();
    std::size_t offset = 0;
    while (offset < wire.size()) {
        const int chunk = static_cast<int>(std::min<std::size_t>(wire.size() - offset, 1U << 20));
        const int written = BIO_write(bio.get(), wire.data() + offset, chunk);
        if (written <= 0) ssl_error("HTTPS write failed");
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

    const auto header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) throw std::runtime_error("invalid HTTP response from coordinator");
    const auto line_end = response.find("\r\n");
    std::istringstream status_line(response.substr(0, line_end));
    std::string http_version;
    HttpResponse result;
    status_line >> http_version >> result.status;
    result.body = decode_chunked_body(response.substr(header_end + 4));
    return result;
}

CertPtr parse_first_certificate(const std::string& pem) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) ssl_error("certificate BIO creation failed");
    X509* certificate = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!certificate) ssl_error("certificate PEM parsing failed");
    return CertPtr(certificate, X509_free);
}

void verify_certificate_matches_key(const std::string& certificate_pem, EVP_PKEY* key) {
    auto certificate = parse_first_certificate(certificate_pem);
    PkeyPtr public_key(X509_get_pubkey(certificate.get()), EVP_PKEY_free);
    if (!public_key || EVP_PKEY_eq(public_key.get(), key) != 1)
        throw std::runtime_error("issued certificate does not match locally generated private key");
}

std::string random_uuid() {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) ssl_error("random message-id generation failed");
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);
    char out[37];
    std::snprintf(out, sizeof(out),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                  bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return out;
}

std::string iso8601(std::chrono::system_clock::time_point time) {
    const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(time);
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(time - seconds).count();
    const auto tt = std::chrono::system_clock::to_time_t(seconds);
    std::tm tm{};
    gmtime_s(&tm, &tt);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3) << std::setfill('0') << millis << 'Z';
    return out.str();
}

class SequenceLock {
public:
    explicit SequenceLock(const std::filesystem::path& path) {
        handle_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot lock NAP sequence state");
    }
    ~SequenceLock() {
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    }
    SequenceLock(const SequenceLock&) = delete;
    SequenceLock& operator=(const SequenceLock&) = delete;
private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

std::uint64_t next_sequence(const std::filesystem::path& state_dir) {
    SequenceLock lock(state_dir / "sequence.lock");
    const auto sequence_path = state_dir / "sequence";
    std::uint64_t value = 0;
    if (std::filesystem::exists(sequence_path)) {
        const auto text = read_file(sequence_path);
        if (!text.empty()) value = std::stoull(text);
    }
    ++value;
    write_file(sequence_path, std::to_string(value) + "\n");
    return value;
}

std::string identity_config(const FleetIdentity& identity) {
    std::ostringstream out;
    out << "coordinator=" << identity.coordinator << '\n'
        << "fleet_id=" << identity.fleet_id << '\n'
        << "agent_id=" << identity.agent_id << '\n'
        << "certificate_sha256=" << identity.certificate_sha256 << '\n';
    return out.str();
}

std::string config_value(const std::string& text, const std::string& key) {
    const std::string prefix = key + "=";
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.starts_with(prefix)) return line.substr(prefix.size());
    }
    return {};
}

std::string send_payload(const std::filesystem::path& state_dir, const std::string& type,
                         const std::string& payload) {
    const FleetIdentity identity = FleetClient::load_identity(state_dir);
    const auto now = std::chrono::system_clock::now();
    const auto expires = now + std::chrono::minutes(5);
    const auto sequence = next_sequence(state_dir);
    const std::string payload_hash = "sha256:" + sha256_hex(payload);
    std::ostringstream envelope;
    envelope << "{"
             << "\"protocol\":\"neta-agent/1\","
             << "\"schema_version\":1,"
             << "\"message_id\":\"" << random_uuid() << "\","
             << "\"message_type\":\"" << type << "\","
             << "\"agent_id\":\"" << json_escape(identity.agent_id) << "\","
             << "\"created_at\":\"" << iso8601(now) << "\","
             << "\"expires_at\":\"" << iso8601(expires) << "\","
             << "\"sequence\":" << sequence << ','
             << "\"correlation_id\":null,"
             << "\"payload_hash\":\"" << payload_hash << "\","
             << "\"payload\":" << payload << ','
             << "\"signature\":{"
             << "\"algorithm\":\"UNSIGNED-NAP1-DRAFT\","
             << "\"key_id\":\"" << json_escape(identity.certificate_sha256) << "\","
             << "\"value\":\"transport-mtls-only\"}"
             << "}";

    const auto response = https_post(identity.coordinator, state_dir / "fleet-ca.crt",
                                     state_dir / "agent.crt", state_dir / "agent.key",
                                     "/api/v1/messages", envelope.str());
    if (response.status < 200 || response.status >= 300) {
        throw std::runtime_error("coordinator rejected NAP message with HTTP " +
                                 std::to_string(response.status) + ": " + response.body);
    }
    return response.body;
}

} // namespace

FleetIdentity FleetClient::enroll(const FleetEnrollmentOptions& options) {
    if (options.coordinator.empty()) throw std::runtime_error("--coordinator is required");
    if (options.fleet_ca.empty()) throw std::runtime_error("--fleet-ca is required");
    if (options.token.empty()) throw std::runtime_error("--token is required");
    if (!std::filesystem::exists(options.fleet_ca)) throw std::runtime_error("Fleet CA file does not exist");
    if (std::filesystem::exists(options.state_dir / "agent.key"))
        throw std::runtime_error("fleet identity already exists in " + options.state_dir.string());

    std::filesystem::create_directories(options.state_dir);
    auto key = generate_private_key();
    const std::string key_pem = private_key_pem(key.get());
    const std::string request_pem = csr_pem(key.get(), options.display_name);

    std::ostringstream body;
    body << "{"
         << "\"fleetId\":\"" << json_escape(options.fleet_id) << "\","
         << "\"token\":\"" << json_escape(options.token) << "\","
         << "\"displayName\":\"" << json_escape(options.display_name) << "\","
         << "\"csrPem\":\"" << json_escape(request_pem) << "\""
         << "}";

    const auto response = https_post(options.coordinator, options.fleet_ca,
                                     std::nullopt, std::nullopt,
                                     "/api/v1/enrollment", body.str());
    if (response.status != 201) {
        throw std::runtime_error("enrollment failed with HTTP " + std::to_string(response.status) +
                                 ": " + response.body);
    }

    FleetIdentity identity;
    identity.coordinator = options.coordinator;
    identity.fleet_id = json_string_value(response.body, "fleetId");
    identity.agent_id = json_string_value(response.body, "agentId");
    identity.certificate_sha256 = json_string_value(response.body, "certificateSha256");
    identity.state_dir = options.state_dir;
    const std::string certificate_chain = json_string_value(response.body, "agentCertificateChainPem");
    if (identity.agent_id.empty() || identity.certificate_sha256.empty() || certificate_chain.empty())
        throw std::runtime_error("coordinator enrollment response is incomplete");
    if (identity.fleet_id != options.fleet_id)
        throw std::runtime_error("coordinator enrollment response fleet mismatch");

    verify_certificate_matches_key(certificate_chain, key.get());
    write_file(options.state_dir / "agent.key", key_pem);
    write_file(options.state_dir / "agent.crt", certificate_chain);
    write_file(options.state_dir / "fleet-ca.crt", read_file(options.fleet_ca));
    write_file(options.state_dir / "identity.conf", identity_config(identity));
    write_file(options.state_dir / "sequence", "0\n");
    return identity;
}

FleetIdentity FleetClient::load_identity(const std::filesystem::path& state_dir) {
    const auto config = read_file(state_dir / "identity.conf");
    FleetIdentity identity;
    identity.coordinator = config_value(config, "coordinator");
    identity.fleet_id = config_value(config, "fleet_id");
    identity.agent_id = config_value(config, "agent_id");
    identity.certificate_sha256 = config_value(config, "certificate_sha256");
    identity.state_dir = state_dir;
    if (identity.coordinator.empty() || identity.fleet_id.empty() || identity.agent_id.empty() ||
        identity.certificate_sha256.empty())
        throw std::runtime_error("fleet identity configuration is incomplete");
    return identity;
}

std::string FleetClient::send_agent_hello(const std::filesystem::path& state_dir) {
    return send_payload(state_dir, "AgentHello",
                        "{\"agent_version\":\"0.1.0\",\"platform\":\"windows\"}");
}

std::string FleetClient::send_heartbeat(const std::filesystem::path& state_dir) {
    return send_payload(state_dir, "Heartbeat", "{\"status\":\"UP\"}");
}

std::string FleetClient::send_finding(const std::filesystem::path& state_dir,
                                      const FindingAnnouncementInput& finding) {
    if (finding.finding_id.empty()) throw std::runtime_error("finding_id is required");
    if (finding.host.empty() || finding.port == 0) throw std::runtime_error("finding target is required");
    if (finding.evidence_root.empty()) throw std::runtime_error("evidence_root is required");

    std::ostringstream changes;
    changes << '[';
    for (std::size_t i = 0; i < finding.changes.size(); ++i) {
        if (i != 0) changes << ',';
        changes << '"' << json_escape(finding.changes[i]) << '"';
    }
    changes << ']';

    std::ostringstream payload;
    payload << "{"
            << "\"finding_id\":\"" << json_escape(finding.finding_id) << "\",";
    if (!finding.finding_key.empty())
        payload << "\"finding_key\":\"" << json_escape(finding.finding_key) << "\",";
    payload << "\"target\":{"
            << "\"host\":\"" << json_escape(finding.host) << "\","
            << "\"port\":" << finding.port << ','
            << "\"transport\":\"" << json_escape(finding.transport) << "\"},"
            << "\"changes\":" << changes.str() << ','
            << "\"performance_verdict\":\"" << json_escape(finding.performance_verdict) << "\","
            << "\"trust_verdict\":\"" << json_escape(finding.trust_verdict) << "\","
            << "\"rule_set\":{\"id\":\"neta-rules\",\"version\":\"draft\",\"hash\":\"sha256:pending\"},"
            << "\"evidence_root\":\"" << json_escape(finding.evidence_root) << "\""
            << "}";
    return send_payload(state_dir, "FindingAnnouncement", payload.str());
}

} // namespace neta
