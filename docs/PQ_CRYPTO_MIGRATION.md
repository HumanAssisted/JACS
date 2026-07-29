# Potential Post-Quantum Cryptography Migration

JACS currently uses the pure-Rust `fips203` 0.4.3 implementation for ML-KEM-768 and `fips204` 0.4.6 for ML-DSA-87; both implement the final NIST standards and remain the latest releases, but neither has a published independent security audit. There is no immediate migration trigger: the July 2026 Anthropic findings concern HAWK and reduced-round AES rather than ML-KEM or ML-DSA, and currently available Rust-native alternatives such as RustCrypto `ml-kem`/`ml-dsa` and libcrux also lack a published audit covering both algorithms. A future migration should therefore be driven by demonstrably stronger maintenance or implementation assurance—not package age alone—and must preserve JACS key, signature, document, WASM, and cross-language compatibility.

## Plan

1. Monitor RustSec advisories, upstream maintenance, independent audit reports, and final-standard compatibility for the current crates, RustCrypto, and libcrux.
2. Require a candidate to support final FIPS 203 and FIPS 204, pure Rust, `wasm32`, JACS-supported platforms, and the repository's MSRV, with a credible maintenance and disclosure policy.
3. Prefer a published third-party audit of the exact candidate versions; otherwise document why its assurance evidence is materially stronger than the current implementations.
4. Build a migration spike that preserves existing serialized keys and verifies signatures, documents, and ML-KEM artifacts across old and new backends.
5. Run NIST vectors, malformed-input and negative tests, cross-language fixtures, timing checks, fuzzing, dependency auditing, and the complete JACS test suite.
6. Ship only after documenting compatibility and rollback behavior, then retain the previous verifier/decoder until all supported persisted artifacts remain readable.
