# Third-party notices

`neta-agent` intentionally keeps the dependency surface small.

## libbpf (optional Linux lifecycle build/runtime library)

libbpf is dual-licensed under BSD-2-Clause or LGPL-2.1. It is used for CO-RE/BTF relocation, BPF program/link management, and ring-buffer consumption. Polling-only builds do not link it. Static distributors must review and include notices for libbpf and its transitive static dependencies.

## SQLite

- License: Public Domain
- Purpose: embedded endpoint-local longitudinal evidence/history storage
- Project: https://sqlite.org/
- Notes: mature and actively maintained. `neta-agent` uses the SQLite C API only through its internal `HistoryStore` wrapper. Release builds may statically link SQLite.

## OpenSSL 3.x

- License: Apache License 2.0
- Purpose: TLS handshake and validation, certificate/SPKI SHA-256, evidence/rule hashing
- Project: https://www.openssl.org/
- Notes: actively maintained and security-sensitive. Production builds should track supported releases and security advisories. Release builds may statically link OpenSSL.

Before production/public redistribution, perform normal dependency, license, export-control, and vulnerability review for the exact versions included in a release artifact.
