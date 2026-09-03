# Third-party notices

`neta-agent` intentionally keeps the dependency surface small.

## libbpf (optional Linux lifecycle build/runtime library)

libbpf is dual-licensed under BSD-2-Clause or LGPL-2.1. It is used for CO-RE/BTF relocation, BPF program/link management, and ring-buffer consumption. Polling-only builds do not link it. Static distributors must review and include notices for libbpf and its transitive static dependencies.

## YARA-X (optional antimalware evidence provider)

- License: BSD-3-Clause
- Purpose: pattern/rule matching for executable/file artifacts and future selected-memory evidence
- Project: https://github.com/VirusTotal/yara-x
- Notes: actively maintained and the forward-development direction of the YARA ecosystem. The Linux provider uses the official `yara_x_capi` C/C++ API when available. `NETA_YARA_X=OFF` builds without linking YARA-X; `AUTO` degrades to an unsupported provider when the C API is not installed. Release builds that enable YARA-X must preserve the applicable upstream BSD notice and review the exact YARA-X version and transitive dependencies shipped in the release.

Third-party YARA rule sets have their own licenses and provenance. The YARA-X engine license does not grant redistribution rights for arbitrary community rules.

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
