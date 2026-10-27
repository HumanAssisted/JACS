# Portable workspace security scope

The active root lock covers jacs-core, jacs-wasm, jacs-mobile, jacs-mcp and jacs-cli. It contains no legacy native JACS, database backend, email, keyring or HTTP transport integration. The root cargo-deny policy has no advisory ignores or proprietary license exceptions. Generated THIRD-PARTY-NOTICES derives from this active graph.

The 2026-10-27 dependency review updated the vulnerable cryptography helpers to
`crypto-bigint 0.7.10` and `ctutils 0.4.6`. Root `cargo audit` and all-feature
cargo-deny advisory/license checks pass. UniFFI 0.32.2's Askama 0.16.1 dependency
still requires the unmaintained `basic-toml` in its published graph
(RUSTSEC-2026-0374). Source builds use Askama's merged replacement with `toml`,
pinned to upstream commit
[`3863808cf594054f7644979ed92caaafc878f378`](https://github.com/askama-rs/askama/commit/3863808cf594054f7644979ed92caaafc878f378).
The root lock contains no `basic-toml`; no advisory ignore was added. This was
a build tooling maintenance advisory, not a reported runtime vulnerability.

The Askama fix and the separate [SurrealDB backports](archive/native/SECURITY_AUDIT.md#source-backports-and-release-blockers-after-the-2026-10-27-updates)
are source-only dependency overrides. Cargo does not propagate workspace
patches to crates.io consumers. `scripts/rust_release.py` therefore rejects
candidate preparation, packaging and publication with unpublished third-party
dependencies. Replace these overrides with reviewed published fixes and
regenerate the locks before qualifying a crates.io release; source audit success
does not establish that the published dependency graph is fixed.

Historical native audits, exact exception owners/deadlines, lockfiles, and license-source contracts are retained under archive/native. The security workflow continues to audit those Rust locks separately, enforces their reviewed exception reachability and deadlines, and scans the full repository Git history for secrets. Archival does not waive those recorded obligations. Python, native Node, Go and storage packages retain their separate build and publication gates.

Biometric SDK tests cover cancellation/lifecycle rules, native package assembly and real platform storage policy checks on emulator/simulator. They do not prove physical sensor behavior, secure-hardware enforcement or enrollment changes on a supported device. See each platform README for release acceptance tests.

New agents use ML-DSA-87. Biometrics protect access to device-local software PQ keys; hardware ES256 signing is explicitly separate. The six-word encrypted transfer fallback provides 66 bits of generated-code entropy and must not be described as a 128-bit PQ confidentiality channel.
