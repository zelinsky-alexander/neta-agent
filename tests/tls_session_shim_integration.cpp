#include "neta/platform.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

namespace {

struct CertificateMaterial {
    EVP_PKEY* key{nullptr};
    X509* certificate{nullptr};
    ~CertificateMaterial() {
        X509_free(certificate);
        EVP_PKEY_free(key);
    }
};

CertificateMaterial make_certificate() {
    CertificateMaterial material;
    EVP_PKEY_CTX* key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    assert(key_context);
    assert(EVP_PKEY_keygen_init(key_context) == 1);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(key_context, 2048) == 1);
    assert(EVP_PKEY_keygen(key_context, &material.key) == 1);
    EVP_PKEY_CTX_free(key_context);

    material.certificate = X509_new();
    assert(material.certificate);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(material.certificate), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(material.certificate), -60) != nullptr);
    assert(X509_gmtime_adj(X509_getm_notAfter(material.certificate), 3600) != nullptr);
    assert(X509_set_pubkey(material.certificate, material.key) == 1);
    X509_NAME* name = X509_get_subject_name(material.certificate);
    assert(name);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      reinterpret_cast<const unsigned char*>("localhost"),
                                      -1, -1, 0) == 1);
    assert(X509_set_issuer_name(material.certificate, name) == 1);
    assert(X509_sign(material.certificate, material.key, EVP_sha256()) > 0);
    return material;
}

int listening_socket(std::uint16_t& port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    int reuse = 1;
    assert(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    port = ntohs(address.sin_port);
    assert(::listen(fd, 1) == 0);
    return fd;
}

std::vector<neta::TlsSessionObservation> poll_events(
    const std::unique_ptr<neta::TlsSessionObserver>& observer,
    std::size_t minimum_count) {
    std::vector<neta::TlsSessionObservation> events;
    for (int attempt = 0; attempt < 10 && events.size() < minimum_count; ++attempt) {
        auto batch = observer->poll(std::chrono::milliseconds(100));
        events.insert(events.end(), batch.begin(), batch.end());
    }
    return events;
}

void actual_openssl_sessions_emit_exact_events() {
    auto observer = neta::platform::make_tls_session_observer();
    assert(observer->capability().available());

    const auto material = make_certificate();
    SSL_CTX* server_context = SSL_CTX_new(TLS_server_method());
    SSL_CTX* client_context = SSL_CTX_new(TLS_client_method());
    assert(server_context && client_context);
    assert(SSL_CTX_use_certificate(server_context, material.certificate) == 1);
    assert(SSL_CTX_use_PrivateKey(server_context, material.key) == 1);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_NONE, nullptr);

    std::uint16_t port = 0;
    const int listener = listening_socket(port);
    int server_result = 0;
    std::thread server([&] {
        const int accepted = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        assert(accepted >= 0);
        SSL* ssl = SSL_new(server_context);
        assert(ssl);
        assert(SSL_set_fd(ssl, accepted) == 1);
        server_result = SSL_accept(ssl);
        if (server_result == 1) static_cast<void>(SSL_shutdown(ssl));
        SSL_free(ssl);
        ::close(accepted);
    });

    const int client_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(client_fd >= 0);
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    remote.sin_port = htons(port);
    assert(::connect(client_fd, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) == 0);
    SSL* client = SSL_new(client_context);
    assert(client);
    assert(SSL_set_fd(client, client_fd) == 1);
    assert(SSL_set_tlsext_host_name(client, "localhost") == 1);
    const unsigned char alpn[] = {2, 'h', '2'};
    assert(SSL_set_alpn_protos(client, alpn, sizeof(alpn)) == 0);
    assert(SSL_connect(client) == 1);
    static_cast<void>(SSL_shutdown(client));
    SSL_free(client);
    ::close(client_fd);

    server.join();
    ::close(listener);
    assert(server_result == 1);

    const auto events = poll_events(observer, 2);
    const auto client_event = std::find_if(events.begin(), events.end(), [](const auto& event) {
        return event.local_role == neta::TlsSessionRole::Client;
    });
    const auto server_event = std::find_if(events.begin(), events.end(), [](const auto& event) {
        return event.local_role == neta::TlsSessionRole::Server;
    });
    assert(client_event != events.end());
    assert(server_event != events.end());
    assert(std::count_if(events.begin(), events.end(), [](const auto& event) {
        return event.local_role == neta::TlsSessionRole::Client;
    }) == 1);
    assert(std::count_if(events.begin(), events.end(), [](const auto& event) {
        return event.local_role == neta::TlsSessionRole::Server;
    }) == 1);
    assert(client_event->fidelity == neta::EvidenceFidelity::Exact);
    assert(client_event->peer_certificate_present);
    assert(!client_event->leaf_sha256.empty());
    assert(!client_event->spki_sha256.empty());
    assert(client_event->sni == "localhost");
    assert(client_event->socket_cookie);
    assert(client_event->local.port != 0 && client_event->remote.port == port);
    assert(server_event->fidelity == neta::EvidenceFidelity::Exact);
    assert(!server_event->peer_certificate_present);
    assert(server_event->socket_cookie);
    assert(server_event->local.port == port);
    assert(observer->health().rejected_events == 0);

    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);
}

void io_driven_handshake_emits_client_once() {
    auto observer = neta::platform::make_tls_session_observer();
    assert(observer->capability().available());

    const auto material = make_certificate();
    SSL_CTX* server_context = SSL_CTX_new(TLS_server_method());
    SSL_CTX* client_context = SSL_CTX_new(TLS_client_method());
    assert(server_context && client_context);
    assert(SSL_CTX_use_certificate(server_context, material.certificate) == 1);
    assert(SSL_CTX_use_PrivateKey(server_context, material.key) == 1);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_NONE, nullptr);

    std::uint16_t port = 0;
    const int listener = listening_socket(port);
    int server_result = 0;
    std::thread server([&] {
        const int accepted = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        assert(accepted >= 0);
        SSL* ssl = SSL_new(server_context);
        assert(ssl);
        assert(SSL_set_fd(ssl, accepted) == 1);
        server_result = SSL_accept(ssl);
        unsigned char received = 0;
        if (server_result == 1) {
            assert(SSL_read(ssl, &received, 1) == 1);
            const unsigned char response = 'r';
            assert(SSL_write(ssl, &response, 1) == 1);
            assert(SSL_read(ssl, &received, 1) == 1);
        }
        static_cast<void>(SSL_shutdown(ssl));
        SSL_free(ssl);
        ::close(accepted);
    });

    const int client_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(client_fd >= 0);
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    remote.sin_port = htons(port);
    assert(::connect(client_fd, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) == 0);
    SSL* client = SSL_new(client_context);
    assert(client);
    assert(SSL_set_fd(client, client_fd) == 1);
    SSL_set_connect_state(client);
    assert(SSL_set_tlsext_host_name(client, "localhost") == 1);

    const unsigned char request = 'q';
    std::size_t written = 0;
    // Do not call SSL_connect: SSL_write_ex drives the client handshake itself.
    assert(SSL_write_ex(client, &request, 1, &written) == 1 && written == 1);
    unsigned char response = 0;
    std::size_t read = 0;
    assert(SSL_read_ex(client, &response, 1, &read) == 1 && read == 1 && response == 'r');
    assert(SSL_write_ex(client, &request, 1, &written) == 1 && written == 1);
    static_cast<void>(SSL_shutdown(client));
    SSL_free(client);
    ::close(client_fd);

    server.join();
    ::close(listener);
    assert(server_result == 1);

    const auto events = poll_events(observer, 2);
    const auto client_events = std::count_if(events.begin(), events.end(), [](const auto& event) {
        return event.local_role == neta::TlsSessionRole::Client;
    });
    assert(client_events == 1);
    const auto client_event = std::find_if(events.begin(), events.end(), [](const auto& event) {
        return event.local_role == neta::TlsSessionRole::Client;
    });
    assert(client_event != events.end());
    assert(client_event->fidelity == neta::EvidenceFidelity::Exact);
    assert(client_event->peer_certificate_present);
    assert(client_event->sni == "localhost");
    assert(client_event->socket_cookie);
    assert(client_event->local.port != 0 && client_event->remote.port == port);
    assert(observer->health().rejected_events == 0);

    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);
}

} // namespace

int main() {
    actual_openssl_sessions_emit_exact_events();
    io_driven_handshake_emits_client_once();
    std::cout << "OpenSSL actual-session instrumentation test passed\n";
}
