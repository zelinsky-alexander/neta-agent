#include "tls_session_wire.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

namespace {

thread_local bool g_inside_wrapper = false;

std::mutex g_emitted_sessions_mutex;
std::unordered_set<SSL*> g_emitted_sessions;

// SSL_set_bio transfers ownership of its BIO arguments to the SSL object. Keep only
// direct socket BIOs supplied through that documented API: a socket BIO is useful
// only after this exact association has been established.
std::recursive_mutex g_ssl_bio_associations_mutex;
std::unordered_map<BIO*, SSL*> g_ssl_bio_associations;

class ErrorQueueGuard {
public:
    ErrorQueueGuard() : had_error_(ERR_peek_error() != 0) {
        if (had_error_) marked_ = ERR_set_mark() == 1;
    }
    ~ErrorQueueGuard() {
        if (marked_) {
            static_cast<void>(ERR_pop_to_mark());
        } else if (!had_error_) {
            ERR_clear_error();
        }
    }
    bool safe() const noexcept { return !had_error_ || marked_; }
private:
    bool had_error_{false};
    bool marked_{false};
};

std::uint64_t monotonic_now_ns() {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
           static_cast<std::uint64_t>(value.tv_nsec);
}

std::uint64_t process_start_ticks() {
    std::array<char, 4096> buffer{};
    const int fd = ::open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    const auto size = ::read(fd, buffer.data(), buffer.size() - 1);
    ::close(fd);
    if (size <= 0) return 0;
    buffer[static_cast<std::size_t>(size)] = '\0';
    char* current = std::strrchr(buffer.data(), ')');
    if (!current) return 0;
    ++current;
    for (int field = 3; field <= 22; ++field) {
        while (*current == ' ') ++current;
        if (*current == '\0') return 0;
        char* end = current;
        while (*end != '\0' && *end != ' ') ++end;
        if (field == 22) {
            std::uint64_t value = 0;
            const auto parsed = std::from_chars(current, end, value);
            return parsed.ec == std::errc{} ? value : 0;
        }
        current = end;
    }
    return 0;
}

std::uint64_t network_namespace_inode() {
    struct stat value {};
    return ::stat("/proc/self/ns/net", &value) == 0
        ? static_cast<std::uint64_t>(value.st_ino) : 0;
}

bool copy_text(char* destination, std::size_t capacity, const char* source) {
    if (!source || capacity == 0) return true;
    const auto length = std::strlen(source);
    const auto copied = length < capacity ? length : capacity - 1;
    std::memcpy(destination, source, copied);
    destination[copied] = '\0';
    return copied == length;
}

bool copy_bytes(char* destination, std::size_t capacity,
                const unsigned char* source, std::size_t length) {
    if (!source || capacity == 0) return length == 0;
    const auto copied = length < capacity ? length : capacity;
    std::memcpy(destination, source, copied);
    return copied == length;
}

bool endpoint_from_fd(int fd, bool peer, char* address, std::size_t address_size,
                      std::uint16_t& port) {
    sockaddr_storage storage{};
    socklen_t length = sizeof(storage);
    const int rc = peer ? ::getpeername(fd, reinterpret_cast<sockaddr*>(&storage), &length)
                        : ::getsockname(fd, reinterpret_cast<sockaddr*>(&storage), &length);
    if (rc != 0) return false;
    if (storage.ss_family == AF_INET) {
        const auto* item = reinterpret_cast<const sockaddr_in*>(&storage);
        if (!::inet_ntop(AF_INET, &item->sin_addr, address,
                         static_cast<socklen_t>(address_size))) return false;
        port = ntohs(item->sin_port);
        return true;
    }
    if (storage.ss_family == AF_INET6) {
        const auto* item = reinterpret_cast<const sockaddr_in6*>(&storage);
        if (!::inet_ntop(AF_INET6, &item->sin6_addr, address,
                         static_cast<socklen_t>(address_size))) return false;
        port = ntohs(item->sin6_port);
        return true;
    }
    return false;
}

std::string hex_digest(const unsigned char* bytes, unsigned int length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.resize(static_cast<std::size_t>(length) * 2U);
    for (unsigned int i = 0; i < length; ++i) {
        output[2U * i] = digits[(bytes[i] >> 4U) & 0x0fU];
        output[2U * i + 1U] = digits[bytes[i] & 0x0fU];
    }
    return output;
}

bool digest_certificate(const X509* certificate, bool public_key,
                        char* output, std::size_t output_size) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    const int rc = public_key
        ? X509_pubkey_digest(certificate, EVP_sha256(), digest.data(), &length)
        : X509_digest(certificate, EVP_sha256(), digest.data(), &length);
    if (rc != 1) return false;
    const auto hex = hex_digest(digest.data(), length);
    return copy_text(output, output_size, hex.c_str());
}

bool bio_to_buffer(BIO* bio, char* output, std::size_t output_size) {
    if (!bio || output_size == 0) return false;
    const auto pending = BIO_ctrl_pending(bio);
    if (pending == 0) return false;
    const auto requested = pending < output_size - 1 ? pending : output_size - 1;
    const int read = BIO_read(bio, output, static_cast<int>(requested));
    if (read <= 0) return false;
    output[static_cast<std::size_t>(read)] = '\0';
    return static_cast<std::size_t>(read) == pending;
}

bool name_to_buffer(const X509_NAME* name, char* output, std::size_t output_size) {
    if (!name) return false;
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    const int printed = X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    const bool complete = printed >= 0 && bio_to_buffer(bio, output, output_size);
    BIO_free(bio);
    return complete;
}

bool time_to_buffer(const ASN1_TIME* value, char* output, std::size_t output_size) {
    if (!value) return false;
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    const bool complete = ASN1_TIME_print(bio, value) == 1 &&
                          bio_to_buffer(bio, output, output_size);
    BIO_free(bio);
    return complete;
}

std::string default_endpoint() {
    const char* configured = std::getenv("NETA_TLS_CONTEXT_SOCKET");
    if (configured && *configured != '\0') return configured;
    return "@neta-agent-tls-uid-" + std::to_string(static_cast<unsigned long long>(::getuid()));
}

bool unix_address(const std::string& endpoint, sockaddr_un& address, socklen_t& length) {
    address = {};
    address.sun_family = AF_UNIX;
    if (endpoint.empty()) return false;
    if (endpoint.front() == '@') {
        const auto name = std::string_view(endpoint).substr(1);
        if (name.size() + 1 > sizeof(address.sun_path)) return false;
        address.sun_path[0] = '\0';
        std::memcpy(address.sun_path + 1, name.data(), name.size());
        length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());
        return true;
    }
    if (endpoint.size() >= sizeof(address.sun_path)) return false;
    std::memcpy(address.sun_path, endpoint.c_str(), endpoint.size() + 1);
    length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + endpoint.size() + 1);
    return true;
}

int evidence_socket() {
    static std::mutex mutex;
    static pid_t owner = -1;
    static int socket_fd = -1;
    std::lock_guard<std::mutex> lock(mutex);
    if (owner == ::getpid() && socket_fd >= 0) return socket_fd;
    if (socket_fd >= 0) ::close(socket_fd);
    socket_fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    owner = ::getpid();
    return socket_fd;
}

bool send_event(const neta_tls_session_wire_event& event) {
    const int fd = evidence_socket();
    if (fd < 0) return false;
    sockaddr_un address{};
    socklen_t length = 0;
    if (!unix_address(default_endpoint(), address, length)) return false;
    return ::sendto(fd, &event, sizeof(event), MSG_DONTWAIT,
                    reinterpret_cast<const sockaddr*>(&address), length) ==
           static_cast<ssize_t>(sizeof(event));
}

void fill_certificate(neta_tls_session_wire_event& event, X509* certificate) {
    if (!certificate) return;
    event.availability |= NETA_TLS_HAS_PEER_CERT;
    bool complete = true;
    complete = digest_certificate(certificate, false, event.leaf_sha256,
                                  sizeof(event.leaf_sha256)) && complete;
    complete = digest_certificate(certificate, true, event.spki_sha256,
                                  sizeof(event.spki_sha256)) && complete;
    if (name_to_buffer(X509_get_subject_name(certificate), event.subject,
                       sizeof(event.subject))) {
        event.availability |= NETA_TLS_HAS_SUBJECT;
    } else {
        complete = false;
    }
    if (name_to_buffer(X509_get_issuer_name(certificate), event.issuer,
                       sizeof(event.issuer))) {
        event.availability |= NETA_TLS_HAS_ISSUER;
    } else {
        complete = false;
    }
    if (time_to_buffer(X509_get0_notBefore(certificate), event.not_before,
                       sizeof(event.not_before))) {
        event.availability |= NETA_TLS_HAS_NOT_BEFORE;
    } else {
        complete = false;
    }
    if (time_to_buffer(X509_get0_notAfter(certificate), event.not_after,
                       sizeof(event.not_after))) {
        event.availability |= NETA_TLS_HAS_NOT_AFTER;
    } else {
        complete = false;
    }
    if (!complete) event.availability |= NETA_TLS_PARTIAL;
}

bool emit_session(SSL* ssl, std::uint8_t role_hint, int fd) {
    if (!ssl || fd < 0) return false;
    int socket_type = 0;
    socklen_t socket_type_length = sizeof(socket_type);
    if (::getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length) != 0 ||
        socket_type != SOCK_STREAM) {
        return false;
    }

    ErrorQueueGuard errors;
    if (!errors.safe()) return false;

    neta_tls_session_wire_event event{};
    event.version = NETA_TLS_SESSION_WIRE_VERSION;
    event.size = sizeof(event);
    event.role = role_hint;
    event.pid = static_cast<std::uint32_t>(::getpid());
    event.uid = static_cast<std::uint32_t>(::getuid());
    event.observed_ns = monotonic_now_ns();
    event.process_start_ticks = process_start_ticks();
    if (event.process_start_ticks != 0) event.availability |= NETA_TLS_HAS_START_TICKS;
    event.network_namespace_inode = network_namespace_inode();
    if (event.network_namespace_inode != 0) event.availability |= NETA_TLS_HAS_NETNS;
    static_cast<void>(::prctl(PR_GET_NAME, event.comm, 0, 0, 0));

#ifdef SO_COOKIE
    std::uint64_t cookie = 0;
    socklen_t cookie_length = sizeof(cookie);
    if (::getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &cookie_length) == 0 && cookie != 0) {
        event.socket_cookie = cookie;
        event.availability |= NETA_TLS_HAS_COOKIE;
    }
#endif
    if (endpoint_from_fd(fd, false, event.local_address, sizeof(event.local_address),
                         event.local_port)) {
        event.availability |= NETA_TLS_HAS_LOCAL;
    }
    if (endpoint_from_fd(fd, true, event.remote_address, sizeof(event.remote_address),
                         event.remote_port)) {
        event.availability |= NETA_TLS_HAS_REMOTE;
    }

    bool complete = true;
    complete = copy_text(event.tls_version, sizeof(event.tls_version), SSL_get_version(ssl)) && complete;
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    complete = copy_text(event.cipher, sizeof(event.cipher),
                         cipher ? SSL_CIPHER_get_name(cipher) : nullptr) && complete;

    const unsigned char* alpn = nullptr;
    unsigned int alpn_length = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_length);
    if (alpn && alpn_length != 0) {
        event.alpn_length = static_cast<std::uint16_t>(
            alpn_length < sizeof(event.alpn) ? alpn_length : sizeof(event.alpn));
        complete = copy_bytes(event.alpn, sizeof(event.alpn), alpn, alpn_length) && complete;
        event.availability |= NETA_TLS_HAS_ALPN;
    }

    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (sni) {
        complete = copy_text(event.sni, sizeof(event.sni), sni) && complete;
        event.availability |= NETA_TLS_HAS_SNI;
    }

    X509_VERIFY_PARAM* params = SSL_get0_param(ssl);
    const char* expected = params ? X509_VERIFY_PARAM_get0_host(params, 0) : nullptr;
    if (expected) {
        complete = copy_text(event.expected_peer_name, sizeof(event.expected_peer_name), expected) && complete;
        event.availability |= NETA_TLS_HAS_EXPECTED_PEER_NAME;
    }
    const char* matched = SSL_get0_peername(ssl);
    if (matched) {
        complete = copy_text(event.matched_peer_name, sizeof(event.matched_peer_name), matched) && complete;
        event.availability |= NETA_TLS_HAS_MATCHED_PEER_NAME;
    }

    event.verify_mode = static_cast<std::uint64_t>(SSL_get_verify_mode(ssl));
    event.verify_result = static_cast<std::int64_t>(SSL_get_verify_result(ssl));
    event.availability |= NETA_TLS_HAS_VERIFY_RESULT;
    if ((event.verify_mode & static_cast<std::uint64_t>(SSL_VERIFY_PEER)) != 0) {
        event.availability |= NETA_TLS_PEER_VERIFICATION_REQUIRED;
    }

    X509* peer = SSL_get1_peer_certificate(ssl);
    if (peer) {
        fill_certificate(event, peer);
        const bool server_role = role_hint == NETA_TLS_ROLE_SERVER;
        const bool client_role = role_hint == NETA_TLS_ROLE_CLIENT;
        const bool verified_chain = event.verify_result == X509_V_OK;
        const bool verified_client = server_role &&
            (event.availability & NETA_TLS_PEER_VERIFICATION_REQUIRED) != 0U && verified_chain;
        const bool verified_server_name = client_role && verified_chain && expected && matched;
        if (verified_client || verified_server_name) {
            event.availability |= NETA_TLS_PEER_AUTHENTICATED;
        }
        X509_free(peer);
    }
    if (!complete) event.availability |= NETA_TLS_PARTIAL;
    return send_event(event);
}

void maybe_emit_completed_session(SSL* ssl, std::uint8_t role_hint, int fd) {
    if (!ssl || SSL_is_init_finished(ssl) != 1) return;

    // Keep the SSL pointer reserved while collecting its immutable completed-session
    // facts. SSL_free removes it, so a later OpenSSL allocation at this address is
    // eligible to emit again.
    std::lock_guard<std::mutex> lock(g_emitted_sessions_mutex);
    if (g_emitted_sessions.contains(ssl)) return;
    if (emit_session(ssl, role_hint, fd)) g_emitted_sessions.insert(ssl);
}

void maybe_emit_completed_session(SSL* ssl, std::uint8_t role_hint) {
    maybe_emit_completed_session(ssl, role_hint, SSL_get_fd(ssl));
}

void forget_ssl_bio_associations(SSL* ssl) {
    if (!ssl) return;
    for (auto it = g_ssl_bio_associations.begin(); it != g_ssl_bio_associations.end();) {
        if (it->second == ssl) {
            it = g_ssl_bio_associations.erase(it);
        } else {
            ++it;
        }
    }
}

void remember_ssl_socket_bio(SSL* ssl, BIO* bio) {
    if (ssl && bio && BIO_method_type(bio) == BIO_TYPE_SOCKET) {
        g_ssl_bio_associations[bio] = ssl;
    }
}

void maybe_emit_completed_associated_socket_bio_session(BIO* bio) {
    if (!bio || BIO_method_type(bio) != BIO_TYPE_SOCKET) return;

    // SSL_free removes the association under this lock. Holding it while collecting
    // the completed-session facts prevents a concurrent free and pointer reuse from
    // turning a socket operation into evidence for a different SSL object.
    std::lock_guard<std::recursive_mutex> lock(g_ssl_bio_associations_mutex);
    const auto association = g_ssl_bio_associations.find(bio);
    if (association == g_ssl_bio_associations.end()) return;
    SSL* ssl = association->second;
    const auto role = SSL_is_server(ssl) ? NETA_TLS_ROLE_SERVER : NETA_TLS_ROLE_CLIENT;
    const long descriptor = BIO_get_fd(bio, nullptr);
    if (descriptor < 0 || descriptor > std::numeric_limits<int>::max()) return;
    maybe_emit_completed_session(ssl, role, static_cast<int>(descriptor));
}

void forget_session(SSL* ssl) {
    if (!ssl) return;
    std::lock_guard<std::recursive_mutex> association_lock(g_ssl_bio_associations_mutex);
    forget_ssl_bio_associations(ssl);
    std::lock_guard<std::mutex> lock(g_emitted_sessions_mutex);
    g_emitted_sessions.erase(ssl);
}

template <typename Function, typename... Arguments>
int call_and_observe(SSL* ssl, const char* symbol, std::uint8_t role_hint,
                     Arguments... arguments) {
    const int entry_errno = errno;
    auto* resolved = reinterpret_cast<Function>(::dlsym(RTLD_NEXT, symbol));
    if (!resolved) {
        errno = entry_errno;
        return -1;
    }
    const bool outer = !g_inside_wrapper;
    if (outer) g_inside_wrapper = true;
    const int result = resolved(ssl, arguments...);
    const int saved_errno = errno;
    if (outer) {
        try {
            maybe_emit_completed_session(ssl, role_hint);
        } catch (...) {
            // Instrumentation is observational only. Never let evidence collection
            // alter application control flow across the OpenSSL C ABI.
        }
    }
    if (outer) g_inside_wrapper = false;
    errno = saved_errno;
    return result;
}

template <typename Function, typename... Arguments>
int call_bio_and_observe(BIO* bio, const char* symbol, Arguments... arguments) {
    const int entry_errno = errno;
    auto* resolved = reinterpret_cast<Function>(::dlsym(RTLD_NEXT, symbol));
    if (!resolved) {
        errno = entry_errno;
        return -1;
    }
    const bool outer = !g_inside_wrapper;
    if (outer) g_inside_wrapper = true;
    const int result = resolved(bio, arguments...);
    const int saved_errno = errno;
    // SSL BIO internals call BIO_read/write on the downstream socket while this
    // wrapper is already active. Observe those nested exact socket calls too.
    {
        try {
            ErrorQueueGuard errors;
            if (errors.safe()) maybe_emit_completed_associated_socket_bio_session(bio);
        } catch (...) {
            // Instrumentation is observational only. Never let evidence collection
            // alter application control flow across the OpenSSL C ABI.
        }
    }
    if (outer) g_inside_wrapper = false;
    errno = saved_errno;
    return result;
}

} // namespace

extern "C" int SSL_connect(SSL* ssl) {
    using Function = int (*)(SSL*);
    return call_and_observe<Function>(ssl, "SSL_connect", NETA_TLS_ROLE_CLIENT);
}

extern "C" int SSL_accept(SSL* ssl) {
    using Function = int (*)(SSL*);
    return call_and_observe<Function>(ssl, "SSL_accept", NETA_TLS_ROLE_SERVER);
}

extern "C" int SSL_do_handshake(SSL* ssl) {
    using Function = int (*)(SSL*);
    const auto role = SSL_is_server(ssl) ? NETA_TLS_ROLE_SERVER : NETA_TLS_ROLE_CLIENT;
    return call_and_observe<Function>(ssl, "SSL_do_handshake", role);
}

extern "C" int SSL_read(SSL* ssl, void* buffer, int size) {
    using Function = int (*)(SSL*, void*, int);
    const auto role = SSL_is_server(ssl) ? NETA_TLS_ROLE_SERVER : NETA_TLS_ROLE_CLIENT;
    return call_and_observe<Function>(ssl, "SSL_read", role, buffer, size);
}

extern "C" int SSL_read_ex(SSL* ssl, void* buffer, std::size_t size,
                             std::size_t* bytes_read) {
    using Function = int (*)(SSL*, void*, std::size_t, std::size_t*);
    const auto role = SSL_is_server(ssl) ? NETA_TLS_ROLE_SERVER : NETA_TLS_ROLE_CLIENT;
    return call_and_observe<Function>(ssl, "SSL_read_ex", role, buffer, size, bytes_read);
}

extern "C" int SSL_write(SSL* ssl, const void* buffer, int size) {
    using Function = int (*)(SSL*, const void*, int);
    const auto role = SSL_is_server(ssl) ? NETA_TLS_ROLE_SERVER : NETA_TLS_ROLE_CLIENT;
    return call_and_observe<Function>(ssl, "SSL_write", role, buffer, size);
}

extern "C" int SSL_write_ex(SSL* ssl, const void* buffer, std::size_t size,
                              std::size_t* bytes_written) {
    using Function = int (*)(SSL*, const void*, std::size_t, std::size_t*);
    const auto role = SSL_is_server(ssl) ? NETA_TLS_ROLE_SERVER : NETA_TLS_ROLE_CLIENT;
    return call_and_observe<Function>(ssl, "SSL_write_ex", role, buffer, size, bytes_written);
}

extern "C" void SSL_set_bio(SSL* ssl, BIO* read_bio, BIO* write_bio) {
    using Function = void (*)(SSL*, BIO*, BIO*);
    const int entry_errno = errno;
    auto* resolved = reinterpret_cast<Function>(::dlsym(RTLD_NEXT, "SSL_set_bio"));
    if (!resolved) {
        errno = entry_errno;
        return;
    }

    int saved_errno = entry_errno;
    bool real_called = false;
    try {
        std::lock_guard<std::recursive_mutex> lock(g_ssl_bio_associations_mutex);
        // The real call can release the BIOs previously owned by ssl. Remove their
        // identities before an allocator can reuse them, then record precisely the
        // socket BIO arguments whose ownership has transferred to ssl.
        forget_ssl_bio_associations(ssl);
        resolved(ssl, read_bio, write_bio);
        real_called = true;
        saved_errno = errno;
        remember_ssl_socket_bio(ssl, read_bio);
        remember_ssl_socket_bio(ssl, write_bio);
    } catch (...) {
        // Allocation for optional bookkeeping must not cross the OpenSSL C ABI.
        // Do not retry a completed setup call; if bookkeeping failed before that
        // call, still preserve the application's requested OpenSSL operation.
        if (!real_called) {
            resolved(ssl, read_bio, write_bio);
            saved_errno = errno;
        }
    }
    errno = saved_errno;
}

extern "C" int BIO_read(BIO* bio, void* buffer, int size) {
    using Function = int (*)(BIO*, void*, int);
    return call_bio_and_observe<Function>(bio, "BIO_read", buffer, size);
}

extern "C" int BIO_read_ex(BIO* bio, void* buffer, std::size_t size,
                            std::size_t* bytes_read) {
    using Function = int (*)(BIO*, void*, std::size_t, std::size_t*);
    return call_bio_and_observe<Function>(bio, "BIO_read_ex", buffer, size, bytes_read);
}

extern "C" int BIO_write(BIO* bio, const void* buffer, int size) {
    using Function = int (*)(BIO*, const void*, int);
    return call_bio_and_observe<Function>(bio, "BIO_write", buffer, size);
}

extern "C" int BIO_write_ex(BIO* bio, const void* buffer, std::size_t size,
                             std::size_t* bytes_written) {
    using Function = int (*)(BIO*, const void*, std::size_t, std::size_t*);
    return call_bio_and_observe<Function>(bio, "BIO_write_ex", buffer, size, bytes_written);
}

extern "C" void SSL_free(SSL* ssl) {
    using Function = void (*)(SSL*);
    const int entry_errno = errno;
    auto* resolved = reinterpret_cast<Function>(::dlsym(RTLD_NEXT, "SSL_free"));
    if (!resolved) {
        errno = entry_errno;
        return;
    }
    forget_session(ssl);
    resolved(ssl);
    const int saved_errno = errno;
    errno = saved_errno;
}
