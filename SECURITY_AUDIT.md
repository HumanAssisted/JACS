# Portable workspace security scope

The active root lock covers jacs-core, jacs-wasm, jacs-mobile, jacs-mcp and jacs-cli. It contains no legacy native JACS, database backend, email, keyring or HTTP transport integration. The root cargo-deny policy has no advisory ignores or proprietary license exceptions. Generated THIRD-PARTY-NOTICES derives from this active graph.

Historical native audits, exact exception owners/deadlines, lockfiles, and license-source contracts are retained under archive/native. The security workflow continues to audit those Rust locks separately, enforces their reviewed exception reachability and deadlines, and scans the full repository Git history for secrets. Archival does not waive those recorded obligations. Python, native Node, Go and storage publishing workflows are inactive archive material.

Biometric SDK tests cover cancellation/lifecycle rules, native package assembly and real platform storage policy checks on emulator/simulator. They do not prove physical sensor behavior, secure-hardware enforcement or enrollment changes on a supported device. See each platform README for release acceptance tests.

New agents use ML-DSA-87. Biometrics protect access to device-local software PQ keys; hardware ES256 signing is explicitly separate. The six-word encrypted transfer fallback provides 66 bits of generated-code entropy and must not be described as a 128-bit PQ confidentiality channel.
