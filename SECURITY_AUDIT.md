# Portable workspace security scope

The active root lock covers jacs-core, jacs-wasm, jacs-mobile, jacs-mcp and jacs-cli. It contains no legacy native JACS, database backend, email, keyring or HTTP transport integration. The root cargo-deny policy has no advisory ignores or proprietary license exceptions. Generated THIRD-PARTY-NOTICES derives from this active graph.

The 2026-10-27 dependency review updated the vulnerable cryptography helpers to
`crypto-bigint 0.7.10` and `ctutils 0.4.6`. Root `cargo audit` and all-feature
cargo-deny advisory/license checks pass. UniFFI 0.32.2's binding generator
depends on Askama 0.16.1, whose published releases still require the
unmaintained `basic-toml` (RUSTSEC-2026-0374). `jacs-mobile` therefore uses the
UniFFI runtime without default features: neither the root lock nor the
published crate resolves the generator, Askama or `basic-toml`. The generator is
the unpublished `tools/jacs-mobile-bindgen` crate. Its separate lock builds
Askama's merged replacement with `toml` from upstream commit
[`3863808cf594054f7644979ed92caaafc878f378`](https://github.com/askama-rs/askama/commit/3863808cf594054f7644979ed92caaafc878f378),
and CI audits it with cargo-audit and cargo-deny. No advisory ignore was added.
This was a build tooling maintenance advisory, not a reported runtime
vulnerability.

The root workspace has no source-only dependency overrides. The separate
[SurrealDB backports](archive/native/SECURITY_AUDIT.md#source-backports-and-release-blockers-after-the-2026-10-27-updates)
are, and Cargo does not propagate workspace patches to crates.io consumers.
`scripts/rust_release.py` rejects candidate preparation, packaging and
publication with unpublished third-party dependencies, so `jacs-surrealdb` is
held from releases (`HELD_CRATES` in `scripts/release_catalog.py`) and keeps its
last published version until reviewed published fixes exist. Source audit
success does not establish that the published dependency graph is fixed.

Historical native audits, exact exception owners/deadlines, lockfiles, and license-source contracts are retained under archive/native. The security workflow continues to audit those Rust locks separately, enforces their reviewed exception reachability and deadlines, and scans the full repository Git history for secrets. Archival does not waive those recorded obligations. Python, native Node, Go and storage packages retain their separate build and publication gates.

Biometric SDK tests cover cancellation/lifecycle rules, native package assembly and real platform storage policy checks on emulator/simulator. They do not prove physical sensor behavior, secure-hardware enforcement or enrollment changes on a supported device. See each platform README for release acceptance tests.

New agents use ML-DSA-87. Biometrics protect access to device-local software PQ keys; hardware ES256 signing is explicitly separate. The six-word encrypted transfer fallback provides 66 bits of generated-code entropy and must not be described as a 128-bit PQ confidentiality channel.
