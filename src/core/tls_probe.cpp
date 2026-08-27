#include "neta/tls_probe.hpp"
#include "neta/crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <array>
#include <chrono>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace neta {
namespace {

struct OpenSslFree {
    void operator()(void* p) const noexcept { OPENSSL_free(p); }
};

std::uint64_t now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string digest_hex(const unsigned char* data, unsigned int length) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < length; ++i) out << std::setw(2) << static_cast<unsigned int>(data[i]);
    return out.str();
}

std::string x509_digest(X509* cert) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{};
    unsigned int length = 0;
    if (X509_digest(cert, EVP_sha256(), bytes.data(), &length) != 1) return {};
    return digest_hex(bytes.data(), length);
}

std::string spki_digest(X509* cert) {
    X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(cert);
    if (!pubkey) return {};
    unsigned char* encoded = nullptr;
    const int length = i2d_X509_PUBKEY(pubkey, &encoded);
    if (length <= 0 || !encoded) return {};
    std::unique_ptr<unsigned char, OpenSslFree> holder(encoded);

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    if (EVP_Digest(encoded, static_cast<std::size_t>(length), digest.data(), &digest_len,
                   EVP_sha256(), nullptr) != 1) return {};
    return digest_hex(digest.data(), digest_len);
}

std::string name_string(X509_NAME* name) {
    if (!name) return {};
    char* raw = X509_NAME_oneline(name, nullptr, 0);
    if (!raw) return {};
    std::unique_ptr<char, OpenSslFree> holder(raw);
    return raw;
}

std::string asn1_time_string(const ASN1_TIME* value) {
    if (!value) return {};
    BIO* raw = BIO_new(BIO_s_mem());
    if (!raw) return {};
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw, BIO_free);
    if (ASN1_TIME_print(bio.get(), value) != 1) return {};
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    return length > 0 ? std::string(data, static_cast<std::size_t>(length)) : std::string{};
}

} // namespace

TlsObservation TlsProbe::probe(const std::string& host, std::uint16_t port,
                               const std::string& ca_file) const {
    using CtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
    using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;

    CtxPtr ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!ctx) throw std::runtime_error("SSL_CTX_new failed");
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    if (!ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(ctx.get(), ca_file.c_str(), nullptr) != 1)
            throw std::runtime_error("failed to load CA file: " + ca_file);
    } else if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1) {
        throw std::runtime_error("failed to load system CA paths");
    }

    BioPtr bio(BIO_new_ssl_connect(ctx.get()), BIO_free_all);
    if (!bio) throw std::runtime_error("BIO_new_ssl_connect failed");

    SSL* ssl = nullptr;
    BIO_get_ssl(bio.get(), &ssl);
    if (!ssl) throw std::runtime_error("BIO_get_ssl failed");
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set1_host(ssl, host.c_str());

    const std::string endpoint = host + ":" + std::to_string(port);
    BIO_set_conn_hostname(bio.get(), endpoint.c_str());
    if (BIO_do_connect(bio.get()) <= 0 || BIO_do_handshake(bio.get()) <= 0)
        throw std::runtime_error("TLS connect/handshake failed for " + endpoint);

    CertPtr cert(SSL_get1_peer_certificate(ssl), X509_free);
    if (!cert) throw std::runtime_error("peer did not provide a certificate");

    TlsObservation result;
    result.target_host = host;
    result.target_port = port;
    result.observed_ns = now_ns();
    result.tls_version = SSL_get_version(ssl) ? SSL_get_version(ssl) : "";
    result.cipher = SSL_get_cipher_name(ssl) ? SSL_get_cipher_name(ssl) : "";

    const unsigned char* alpn = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
    if (alpn && alpn_len) result.alpn.assign(reinterpret_cast<const char*>(alpn), alpn_len);

    result.leaf_sha256 = x509_digest(cert.get());
    result.spki_sha256 = spki_digest(cert.get());
    result.subject = name_string(X509_get_subject_name(cert.get()));
    result.issuer = name_string(X509_get_issuer_name(cert.get()));
    result.not_before = asn1_time_string(X509_get0_notBefore(cert.get()));
    result.not_after = asn1_time_string(X509_get0_notAfter(cert.get()));
    result.chain_valid = SSL_get_verify_result(ssl) == X509_V_OK;
    result.hostname_valid = X509_check_host(cert.get(), host.c_str(), host.size(), 0, nullptr) == 1;

    std::ostringstream canonical;
    canonical << result.target_host << ':' << result.target_port << '|'
              << result.tls_version << '|' << result.cipher << '|' << result.alpn << '|'
              << result.leaf_sha256 << '|' << result.spki_sha256 << '|'
              << result.issuer << '|' << result.chain_valid << '|' << result.hostname_valid;
    result.sha256 = sha256_hex(canonical.str());
    return result;
}

} // namespace neta
