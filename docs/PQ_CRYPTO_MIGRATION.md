# Potential Post-Quantum Cryptography Migration

Current source uses pure-Rust `fips204` **0.5.0** in portable core for ML-DSA-87. Native `pq2025` signing delegates to core; the unused native `fips204` 0.4.6 dependency was removed. The live native ML-KEM-768 implementation uses `fips203` **0.5.0**, updated from 0.4.3 for [upstream key-import and decompression correctness fixes](https://docs.rs/crate/fips203/0.5.0/source/CHANGELOG.md). Canonical JSON uses `serde_json_canonicalizer` **0.4.1**, including native tests. These source changes are not a statement about already published packages.

Both cryptographic crates target the final NIST standards. Their version numbers alone do not establish security assurance. Future backend migrations should be based on current maintenance, vulnerability disclosures, independent audit evidence and compatibility testing. Preserve existing JACS keys, signatures, documents, WASM behavior and cross-language verification when evaluating alternatives.

## Plan

1. Monitor RustSec advisories, upstream maintenance, independent audit reports, and final-standard compatibility for the current crates, RustCrypto, and libcrux.
2. Require a candidate to support final FIPS 203 and FIPS 204, pure Rust, `wasm32`, JACS-supported platforms, and the repository's MSRV, with a credible maintenance and disclosure policy.
3. Prefer a published third-party audit of the exact candidate versions; otherwise document why its assurance evidence is materially stronger than the current implementations.
4. Build a migration spike that preserves existing serialized keys and verifies signatures, documents, and ML-KEM artifacts across old and new backends.
5. Run NIST vectors, malformed-input and negative tests, cross-language fixtures, timing checks, fuzzing, dependency auditing, and the complete JACS test suite.
6. Ship only after documenting compatibility and rollback behavior, then retain the previous verifier/decoder until all supported persisted artifacts remain readable.
