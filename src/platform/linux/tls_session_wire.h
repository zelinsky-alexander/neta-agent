#ifndef NETA_TLS_SESSION_WIRE_H
#define NETA_TLS_SESSION_WIRE_H

#include <stdint.h>

#define NETA_TLS_SESSION_WIRE_VERSION 1
#define NETA_TLS_SESSION_ADDRESS_LENGTH 46
#define NETA_TLS_SESSION_COMM_LENGTH 16
#define NETA_TLS_SESSION_VERSION_LENGTH 32
#define NETA_TLS_SESSION_CIPHER_LENGTH 128
#define NETA_TLS_SESSION_ALPN_LENGTH 64
#define NETA_TLS_SESSION_NAME_LENGTH 256
#define NETA_TLS_SESSION_HASH_LENGTH 65
#define NETA_TLS_SESSION_DN_LENGTH 384
#define NETA_TLS_SESSION_TIME_LENGTH 48

enum neta_tls_session_wire_role {
    NETA_TLS_ROLE_CLIENT = 1,
    NETA_TLS_ROLE_SERVER = 2,
};

enum neta_tls_session_wire_availability {
    NETA_TLS_HAS_START_TICKS = 1U << 0,
    NETA_TLS_HAS_NETNS = 1U << 1,
    NETA_TLS_HAS_COOKIE = 1U << 2,
    NETA_TLS_HAS_LOCAL = 1U << 3,
    NETA_TLS_HAS_REMOTE = 1U << 4,
    NETA_TLS_HAS_ALPN = 1U << 5,
    NETA_TLS_HAS_SNI = 1U << 6,
    NETA_TLS_HAS_EXPECTED_PEER_NAME = 1U << 7,
    NETA_TLS_HAS_MATCHED_PEER_NAME = 1U << 8,
    NETA_TLS_HAS_PEER_CERT = 1U << 9,
    NETA_TLS_PEER_VERIFICATION_REQUIRED = 1U << 10,
    NETA_TLS_HAS_VERIFY_RESULT = 1U << 11,
    NETA_TLS_PEER_AUTHENTICATED = 1U << 12,
    NETA_TLS_HAS_SUBJECT = 1U << 13,
    NETA_TLS_HAS_ISSUER = 1U << 14,
    NETA_TLS_HAS_NOT_BEFORE = 1U << 15,
    NETA_TLS_HAS_NOT_AFTER = 1U << 16,
    NETA_TLS_PARTIAL = 1U << 17,
};

struct neta_tls_session_wire_event {
    uint16_t version;
    uint16_t size;
    uint8_t role;
    uint8_t reserved[3];
    uint32_t availability;
    uint32_t pid;
    uint32_t uid;
    uint64_t observed_ns;
    uint64_t process_start_ticks;
    uint64_t network_namespace_inode;
    uint64_t socket_cookie;
    uint64_t verify_mode;
    int64_t verify_result;
    uint16_t local_port;
    uint16_t remote_port;
    uint16_t alpn_length;
    uint16_t reserved2;
    char comm[NETA_TLS_SESSION_COMM_LENGTH];
    char local_address[NETA_TLS_SESSION_ADDRESS_LENGTH];
    char remote_address[NETA_TLS_SESSION_ADDRESS_LENGTH];
    char tls_version[NETA_TLS_SESSION_VERSION_LENGTH];
    char cipher[NETA_TLS_SESSION_CIPHER_LENGTH];
    char alpn[NETA_TLS_SESSION_ALPN_LENGTH];
    char sni[NETA_TLS_SESSION_NAME_LENGTH];
    char expected_peer_name[NETA_TLS_SESSION_NAME_LENGTH];
    char matched_peer_name[NETA_TLS_SESSION_NAME_LENGTH];
    char leaf_sha256[NETA_TLS_SESSION_HASH_LENGTH];
    char spki_sha256[NETA_TLS_SESSION_HASH_LENGTH];
    char subject[NETA_TLS_SESSION_DN_LENGTH];
    char issuer[NETA_TLS_SESSION_DN_LENGTH];
    char not_before[NETA_TLS_SESSION_TIME_LENGTH];
    char not_after[NETA_TLS_SESSION_TIME_LENGTH];
};

#endif
