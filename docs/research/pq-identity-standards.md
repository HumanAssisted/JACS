# Native post-quantum identity: checked standards

Standards checked against primary sources on **2026-10-27**; implementation
and dependency notes updated **2026-10-28**. Research only; this note does not claim implementation or publication of JACS changes.

JACS can retain its persistent final-FIPS-204 ML-DSA-87 key and export a standards-based public JWK, DID verification method, and signed A2A Agent Card. ES256 is an explicit compatibility option for peers without PQ support. A conforming representation does not guarantee support in every verifier.

## Finalized JOSE and the native key

[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html), published May 2026 on the IETF Standards Track, defines ML-DSA-44/65/87 for JOSE and COSE. Its public JWK is `{ "kty": "AKP", "alg": "ML-DSA-87", "pub": "<base64url(raw-public-key)>" }`. The public key is 2592 bytes and signature 4627 bytes. A public export must omit private information. Private JWK `priv` is exclusively a 32-byte seed, not the 4896-byte expanded secret.

JACS's public-key profile requires a supplied `kid` to equal its thumbprint;
general JOSE does not impose that choice. CID's thumbprint naming guidance is
a recommendation, not a requirement to rename every existing verification
method. Relative fragment references in DID documents are allowed when resolved
against the document identifier.

AKP thumbprints use exactly `alg`, `kty`, and `pub`, in that lexicographic order; `kid` is not included. Signing uses pure ML-DSA (FIPS 204 Algorithm 2), empty context, and raw signature bytes encoded base64url for JWS. HashML-DSA is not the registered JOSE algorithm. See RFC 9964 sections 3–7. JOSE implementation support is optional. Appendix A.1, Figure 5 supplies an ML-DSA-87 public JWK and signed JOSE example suitable for known-vector verification.

## W3C identity and VC boundaries

* [DID Core 1.0](https://www.w3.org/TR/2022/REC-did-core-20220719/), W3C Recommendation, 2022-07-19, allows extensible verification methods with public JWK material. Use appropriate `authentication` / `assertionMethod` references. DID Core does not prescribe signing the DID document itself; DID method resolution/control is a separate concern.
* [Controlled Identifiers 1.0](https://www.w3.org/TR/2025/REC-cid-1.0-20250515/), W3C Recommendation, 2025-05-15, defines the modern type **`JsonWebKey`** and context `https://www.w3.org/ns/cid/v1`. That context can be appended to a DID v1 document. Prefer it over a fabricated PQ-specific verification-method type. Legacy `JsonWebKey2020` appears in older DID examples; it is not needed for native AKP representation.
* [DID 1.1](https://www.w3.org/TR/2026/CR-did-1.1-20260305/) is a Candidate Recommendation Snapshot dated 2026-03-05, not a final Recommendation.
* [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/) is a W3C Recommendation dated 2026-10-13. Section 4.2 requires `JsonWebKey` / `publicKeyJwk` when using controlled identifier documents. This offers a finalized JOSE route for VCs; JACS documents do not automatically become VCs merely because they have signatures.
* [Quantum-Resistant Cryptosuites v1.0](https://www.w3.org/TR/2026/WD-vc-di-quantum-resistant-1.0-20260616/) remains an explicitly experimental First Public Working Draft dated 2026-06-16. Its named ML-DSA Data Integrity suites include `mldsa44-rdfc-2024`, `mldsa44-jcs-2024`, and `mldsa44-sd-2024`. It does not define `mldsa87-jcs-2024`; do not invent that name or claim final W3C PQ Data Integrity conformance.

## A2A version and Agent Card signing

The latest published [A2A release is v1.0.1](https://github.com/a2aproject/A2A/releases/tag/v1.0.1), released 2026-05-28 (release-note heading dated May 26). The `/latest` documentation banner still says `1.0.0`; use the [versioned v1.0.1 specification](https://a2a-protocol.org/v1.0.1/specification/). Wire protocol negotiation uses `1.0`, excluding patch numbers.

Agent Card signatures are JWS. Section 8.4 requires protobuf-aware field presence/default handling, removal of `signatures`, and RFC 8785 JCS. Preserve required fields and explicitly set optional defaults; omit defaults otherwise. Protected headers contain `alg` and `kid`, with `typ` recommended as `JOSE`; `jku` is optional. Sign the ASCII concatenation `base64url(protected-header-bytes) + "." + base64url(canonical-card-bytes)` and place encoded header/signature in `signatures[]`. ML-DSA-87 is permitted by the standard JOSE mechanism; peers must implement it. The ES256 example is not an algorithm allowlist.

Existing JACS signing helpers are appropriate only when they sign those exact input bytes without an additional JACS digest, domain string, or envelope. JACS currently labels its legacy Agent Card model `0.4.0`; it must not simply be labeled `1.0`. A2A v1 uses `supportedInterfaces` and other changed fields. JACS also has an opt-in, finite A2A 1.0 report example. Native signatures on the legacy discovery surface do not upgrade that surface to A2A 1.0.

## Libraries checked

| Library | Latest verified version and date | Practical consequence |
| --- | --- | --- |
| [`fips204`](https://docs.rs/crate/fips204/latest) | 0.5.0, 2026-10-23 | Pure Rust, final FIPS 204, all parameter sets. JACS production ML-DSA-87 uses core; native signing delegates to it. |
| [RustCrypto `ml-dsa`](https://docs.rs/crate/ml-dsa/0.1.1) | 0.1.1, 2026-06-05 | Pure Rust final-FIPS-204 implementation; README explicitly says it has not been independently audited. |
| [`aws-lc-rs`](https://docs.rs/crate/aws-lc-rs/1.18.2) | 1.18.2, 2026-10-12 | Stable ML-DSA APIs in `signature`; accepts seed or expanded secret imports. [Expanded import cannot recover the original seed](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/struct.PqdsaKeyPair.html). |
| [`oqs`](https://github.com/open-quantum-safe/liboqs-rust/blob/main/CHANGELOG.md) | 0.11.0, 2025-05-01 | Rust bindings to liboqs, including ML-DSA, with native build dependencies. |

The current [portable core manifest](../../jacs-core/Cargo.toml) selects
`fips204` **0.5.0** for production ML-DSA-87 and
`serde_json_canonicalizer` **0.4.1**. Native `pq2025` signing delegates to that
core implementation; the unused native `fips204` 0.4.6 dependency has been
removed. The native test-only canonicalizer now also uses **0.4.1**.
The [native library](../../archive/native/jacs/Cargo.toml) separately uses
`fips203` **0.5.0** for its live ML-KEM-768 implementation. These source updates
do not establish availability in published packages. Dependency changes require
renewed RFC-vector, SDK interoperability and malformed-input checks; standards
conformance alone does not establish implementation assurance or release readiness.

## Source dependency refresh: 2026-10-28

The current locks select these versions for the relevant direct dependency
lines. This is a scoped source inventory, not a claim that every transitive
package has been upgraded to its newest major version.

| Dependency | Selected version | Reason or boundary |
| --- | --- | --- |
| `fips203` | 0.5.0 | [Upstream changelog](https://docs.rs/crate/fips203/0.5.0/source/CHANGELOG.md): correct nearest-integer Decompress rounding required by FIPS 203 equation 4.8; reject secret coefficients at or above q during key import |
| `jsonschema` / `referencing` | 0.60.2 | [Upstream release](https://github.com/Stranger6667/jsonschema/releases/tag/rust-v0.60.2): fix validator-construction stack overflow for `unevaluated*` schemas with `$ref` cycles across `$id` resources |
| `base64` / `sha2` | 0.23.1 / 0.11.1 | Align native direct encoding with core and refresh the compatible hash dependency line |
| `zeroize` / `rand` | 1.9.1 / 0.10.3 | Compatible resolved patch updates; existing platform RNG and secret-owner contracts remain in force |
| `aws-lc-rs` | 1.18.2 | Native transport dependency update; JACS ML-DSA signing continues to use core's `fips204` 0.5.0 |
| JavaScript smoke `jose` / Express | 6.2.13 / 5.3.0 | Exact test dependencies, installed with scripts disabled; official A2A SDK remains 1.3.0 |

Older transitive `base64`, `sha2` and `rand` major-version lines remain where
other native dependencies require them. Removing the unused native `fips204`
declaration does not replace a production cryptographic backend. On 2026-10-28,
a temporary dual-version ML-KEM-768 harness checked 64 keypairs generated by
`fips203` 0.4.3: 0.5.0 decapsulated their old ciphertexts to identical shared
secrets, and 0.4.3 likewise opened new 0.5.0 ciphertexts made with those public
keys. Ephemeral test keys stayed in memory. This is sampled primitive/key/wire
compatibility evidence, not an exhaustive corpus guarantee or a test of
persisted JACS encrypted-file migration.

## Current official SDK integration

The [JavaScript SDK 1.3.0 signing API](https://github.com/a2aproject/a2a-js/blob/v1.3.0/src/signature.ts)
uses its standard Agent Card canonicalizer and `jose` verification. With
`jose` 6.2.13, ML-DSA-87 runs through Node WebCrypto. [Node 24.7.0 introduced
ML-DSA WebCrypto support](https://nodejs.org/download/release/v24.7.0/docs/api/webcrypto.html);
Node's generic SDK minimum of 20 is insufficient for this signature path.
The test pins the SDK and `jose` rather than assuming the runtime supports an
algorithm merely because the JWK parses.

The [Python SDK 1.3.0 signing backend](https://github.com/a2aproject/a2a-python/blob/v1.3.0/src/a2a/utils/signing.py)
uses PyJWT, which does not provide ML-DSA verification in the checked version.
Its integration therefore selects ES256 explicitly and verifies the delegated
key's native-root binding separately. This is a peer capability constraint,
not an A2A algorithm restriction or a reason to rotate the native PQ root.
See the [runnable SDK checks](../../archive/native/examples/a2a_v1_sdk/README.md)
for exact dependencies, runtime requirements and the tested exchange.

## Verification and trust

The managed environment has OpenSSL **3.5.7** and advertises `ML-DSA-87` in `openssl list -signature-algorithms`. The RFC 9964 Appendix A.1 Figure 5 ML-DSA-87 vector was independently verified here: its AKP SHA-256 thumbprint matches `kid`; OpenSSL `pkeyutl -verify -rawin` succeeds; Node **v24.19.0** `crypto.verify(null, input, key, signature)` returns true and returns false after input tampering. No dependency installation was needed.

Wrap the raw public key in SubjectPublicKeyInfo using ML-DSA-87 OID `2.16.840.1.101.3.4.3.19` and no algorithm parameters. For a 2592-byte key, the DER prefix is hex `30820a32300b060960864801650304031303820a2100`, followed by the raw key. [OpenSSL ML-DSA documentation](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/); [RFC 9881 key encoding](https://www.rfc-editor.org/rfc/rfc9881.html).

Bind accepted keys to a trusted DID/provider; a self-supplied JWK proves possession, not external identity. Check algorithm/key consistency, lengths, relevant verification relationship, revocation, and unsupported critical headers. Do not silently downgrade after PQ errors. Arbitrary `jku` retrieval requires a trusted-source policy. PQ signatures do not make HTTPS, DID resolution, or the complete A2A channel post-quantum.

## DNS discovery is a separate trust layer

Publish the raw public-key SHA-256 fingerprint and an optional HTTPS discovery
pointer, then verify the fetched key and the complete signed document. Neither
a self-declared domain nor a registry response enrolls a trusted identity.
[The implementation guide](../key-discovery.md) distinguishes DNS digests,
frozen signed document references and transport hashes.

[RFC 9715](https://www.rfc-editor.org/rfc/rfc9715.html) discusses DNS/UDP
fragmentation avoidance; 1232 bytes is not an absolute DNS TXT or message size
limit. Fingerprint-plus-HTTPS discovery avoids unnecessarily large DNS answers.
[RFC 7583](https://www.rfc-editor.org/rfc/rfc7583.html) analyzes DNSSEC key
rollovers, not a universal JACS application-key overlap of twice the TTL.
Rotation must account for the deployment's caches, retained signed documents,
revocation policy and historical-key availability.
