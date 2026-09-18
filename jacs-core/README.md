# jacs-core

**Portable JACS protocol layer — no I/O.**

`jacs-core` is the compile-anywhere protocol crate for [JACS](https://github.com/HumanAssisted/JACS).
It holds the cryptographic primitives, canonical JSON serializer, embedded
schemas, encrypted-key envelope codec, and agreement payload helpers that
the active browser, mobile, CLI and MCP boundaries share. The archived native
facade can also depend on this core for compatibility.

## What it is

- A pure-Rust library that compiles for both native targets and
  `wasm32-unknown-unknown`.
- The single source of truth for canonical JACS bytes — signatures and
  agreements produced by `jacs_core::CoreAgent::sign_message` round-trip
  through native `jacs::Agent::verify_string` and back.
- The strict raw-JSON decoder (`strict_json`) used before cryptographic
  processing. It rejects duplicate decoded object names recursively and
  mathematical integers outside ±(2^53−1), including exponent spellings;
  repeated array values are valid. Existing parsing keeps RFC 8785 binary64
  rounding for nonintegral decimals.
- The home of `Ed25519DalekSigner`, `Pq2025Signer`, `P256Signer`, the `DetachedSigner`
  trait, `CoreAgent`, the AES-256-GCM + Argon2id encrypted-key envelope,
  the embedded JSON schema set (Draft 7), and the multi-party agreement
  payload logic.

## What it is not

- **Not a filesystem layer.** No `std::fs`, no path resolution, no
  config loading.
- **Not a network layer.** No DNS, no HTTP, no remote registry.
- **Not an observability layer.** No env-var-driven logging,
  no `tracing` subscriber wiring, no metrics export.
- **Not a CLI or MCP server.** Those live in
  [`jacs-cli`](../jacs-cli/README.md) and
  [`jacs-mcp`](../jacs-mcp/README.md), both using this portable core.

The active workspace builds the portable primitive and thin platform boundaries.
Historical storage, A2A, email and other native integrations are retained in
[`archive/native`](../archive/native/README.md), outside the active dependency
graph and publication set. Build browser bindings from source; see the current
[release status](../docs/release-status.md) before relying on registry packages.

## Quick start

```rust,ignore
use jacs_core::{CoreAgent, SigningAlgorithm};
use serde_json::json;

let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Pq2025)?;
let signed = agent.sign_message(&json!({ "hello": "world" }))?;
let outcome = agent.verify(&signed)?;
assert!(outcome.valid);
```

For multi-party agreements:

```rust,ignore
use jacs_core::{CoreAgent, SigningAlgorithm, agreements};
use serde_json::json;

let mut alice = CoreAgent::ephemeral(SigningAlgorithm::Pq2025)?;
let mut bob = CoreAgent::ephemeral(SigningAlgorithm::Pq2025)?;
let alice_id = alice.export_agent()["jacsId"].as_str().unwrap().to_string();
let bob_id = bob.export_agent()["jacsId"].as_str().unwrap().to_string();

let mut doc = agreements::create(
    &json!({ "topic": "merge proposal" }),
    &[alice_id.clone(), bob_id.clone()],
    Some("Approve?"),
    None,
)?;
agreements::sign(&mut alice, &mut doc, "alice")?;
agreements::sign(&mut bob, &mut doc, "bob")?;

let signers: Vec<(&str, &[u8], SigningAlgorithm)> = vec![
    (alice_id.as_str(), alice.public_key(), SigningAlgorithm::Pq2025),
    (bob_id.as_str(),   bob.public_key(),   SigningAlgorithm::Pq2025),
];
let outcome = agreements::verify(&doc, &signers)?;
assert!(outcome.all_valid);
```

## Portable identities and platform signers

Use `Pq2025` (ML-DSA-87) for new portable identities. Browser and mobile convenience
constructors select it without a classical fallback. The same Rust implementation
signs in WASM, Android, and iOS. Ed25519 and ES256 are explicit compatibility
choices; an ES256 hardware key is not a post-quantum signing key.

`CoreAgent::ephemeral` creates a self-signed identity for `Ed25519`, `Pq2025`
(ML-DSA-87), or `Es256` (P-256/SHA-256). `update_agent(&metadata)` merges identity
metadata, creates a new UUID version, and signs with the existing key. Identity
and key fields are protected; denied or failed signatures leave the previous
identity unchanged.

`CoreAgent::from_signer(Box<dyn DetachedSigner>, agent_json)` accepts a platform
signing provider. Existing signed identities are verified against the provider's
public key. Unsigned input is a **new identity creation request**, filled with
initial headers and self-signed. A platform provider can keep its key permanently
in hardware: `export_private_key_bytes` defaults to `CoreError::NotExportable`.
Such keys cannot participate in private-key transfer; use a software signing key
protected by the OS when the same key must move between devices.

ES256 wire encodings are strict: 65-byte uncompressed SEC1 public key, 64-byte
IEEE-P1363 `r || s` signature with low-S normalization, and a 32-byte big-endian
private scalar for exportable software keys. Platform adapters must convert
DER signatures to this canonical form. Signing takes message bytes and hashes
with SHA-256 once. `public_key_pem` is the native registration presentation:
Ed25519/ML-DSA raw-key PEM armor, ES256 SPKI PEM. Identity pinning compares raw
key bytes, never PEM text.

`from_encrypted_material` requires a valid self-signed identity and checks its
key, algorithm, ID, version and optional checksum. Signature stripping is an
error. Old unsigned exports require the explicit
`from_legacy_encrypted_material` migration API **after independently confirming
the agent ID and public key**; an existing invalid signature is never ignored.
New exports are self-signed. Valid signed native documents retain support for
their historical public-key hash convention.

The `transfer` module generates a six-word transfer code, validates a received
bundle against an independently pinned registration, and reencrypts it under a
separate destination secret. It performs no HTTP or device authentication; the
relay transport supplies authenticated, expiring, one-use sessions.

The six-word code has 66 bits of generated entropy. It is a human-entered
transfer secret, not a claim of 128-bit post-quantum confidentiality. Encryption
uses AES-256-GCM with Argon2id; its protection also depends on the wrapping
secret. ML-DSA signatures do not upgrade TLS, passkeys, or a weak password.

## Staged key rotation

`CoreAgent::prepare_key_rotation(None)` creates a new PQ2025 key and a signed
candidate without changing the active identity. An explicit algorithm is
supported; a PQ2025 identity cannot downgrade to Ed25519 or ES256. The opaque
`PreparedKeyRotation` exposes its public identity/proof and password-encrypted
material. It never exposes a private key. `prepare_key_rotation_with_signer`
accepts hardware/platform callbacks, including non-exportable keys.

Persist the encrypted candidate atomically and obtain any required registry
admission before calling `commit_key_rotation`. Commit rejects a stale or foreign
stage, verifies the complete transition again, checks that the candidate provider
still controls the prepared key, then clears and drops the old signer. Dropping
an uncommitted stage clears its candidate signer. Registry HTTP, filesystem
transactions and recovery policy belong to the caller.

The embedded `jacsKeyRotationProof` uses **`jacs-key-rotation-v2`**. The old key
signs a domain-separated canonical context binding the stable agent ID, both
identity versions, both canonical raw public-key hashes, both algorithms, the
exact old identity, the complete unsigned new identity and its timestamp. The
new key signs the complete candidate, including that proof. The new version
links to `jacsPreviousVersion`; original identity provenance is preserved.

`verify_key_rotation` requires an independently trusted old identity, key and
algorithm. `CoreAgent::verify_key_rotation` uses its existing trusted identity
and remains available while locked. Do not derive the old trust anchor from
self-asserted proof data. The archived native `JACS_KEY_ROTATION:` proof did not
bind both versions or the complete candidate; V2 deliberately rejects it.
Registries must explicitly adopt the V2 verifier rather than falling back to
legacy verification when V2 fails. The archived native verifier is unchanged.

## Numeric compatibility profiles

`parse_strict_json` and its byte/typed counterparts use
`jacs-json-rfc8785-binary64-v1`. Historical nonintegral decimals remain readable:
for example, `333333333.33333329` canonicalizes to `333333333.3333333`, as in
RFC 8785. Mathematical unsafe integers remain rejected whether written as
plain integers, `.0`, or exponent notation. This integer rule is narrower than
RFC 8785 itself; represent larger exact quantities as strings.

New protocols may explicitly select `NumericProfile::ExactDecimalV1`
(`jacs-json-safe-binary64-v1`) with
`parse_strict_json_with_numeric_profile` or its byte/typed counterparts. This
profile additionally requires exact decimal preservation after binary64/JCS
conversion and limits number tokens to 128 bytes, coefficients to 100 digits,
and exponent magnitude to 10,000. A strict-profile rejection is final for that
decision; callers must not retry it with the compatibility profile.

Choose the profile from the protocol or independently selected verification
policy before parsing raw input. An already-decoded `serde_json::Value` cannot
prove the original decimal spelling was preserved. `canonicalize_json_try`
continues to validate safe integral values and serialize finite decimals using
RFC 8785; it does not recover discarded input precision.

## Encrypted private-key envelopes

`jacs-core::envelope` reads two on-disk formats — the same two the native
`jacs` CLI has shipped:

1. **V2 JSON envelope (current writer)** — AES-256-GCM cipher, Argon2id
   key derivation. Default for all newly-encrypted keys. Always starts
   with `{`.
2. **Legacy raw-binary PBKDF2 envelope** — `salt(16) || nonce(12) ||
   ciphertext`, PBKDF2-HMAC-SHA256 @ 600k iterations with a 100k legacy
   fallback. Read-only — no new writes.

### Reserved magic prefixes

Inputs whose first 4 bytes match the ASCII pattern `^J[A-Z]{2}[0-9]$`
(for example `JAA1`, `JAC2`, `JAS9`) are reserved for future envelope
formats — memory-hard KDF variants, post-quantum AEAD wrappers, and the
like. `decrypt_private_key` rejects them up front with
`CoreError::UnsupportedAlgorithm("<prefix>")` so they aren't misclassified
as malformed legacy PBKDF2 noise.

## Compile-target guarantees

- `cargo check -p jacs-core --target wasm32-unknown-unknown` passes.
- `bash scripts/forbidden-deps.sh jacs-core wasm32-unknown-unknown` is
  the CI gate: it fails the build if `ring`, `tokio`, `reqwest`,
  `hickory-resolver`, `object_store`, `rusqlite`, `duckdb`, `surrealdb`,
  `keyring`, `rpassword`, `dirs`, `jacs-media`, `mail-parser`,
  `html5ever`, or `opentelemetry-otlp` ever appear in `jacs-core`'s
  dependency graph.

## Where to go next

- [`jacs-mobile`](../jacs-mobile/README.md) — mobile bindings and biometric vaults.
- [`jacs-cli`](../jacs-cli/README.md) and [`jacs-mcp`](../jacs-mcp/README.md) — thin host boundaries.
- [`archive/native`](../archive/native/README.md) — historical native compatibility source.
- [`jacs-wasm`](../jacs-wasm/README.md) — browser bindings that wrap `jacs-core` with a TypeScript API.

## License

Apache-2.0. See [`LICENSE-APACHE`](../LICENSE-APACHE).

### Human identity and durable recovery

`CoreAgent::create_human()` creates an ML-DSA-87 identity whose first self-signed
version has `jacsAgentType: "human"`. Existing AI constructors are unchanged.
The type is metadata; applications must independently bind a human to an account.

`recovery::export_recovery(&agent)` generates 128 CSPRNG bits, formatted as eight
four-digit hexadecimal groups, and returns `RecoveryExport { code, material }`.
It uses the ordinary `AgentMaterial` and Argon2id/AES-GCM envelope. It does not
change the active identity, persist a backup, or lock the caller's handle.
`recovery::import_recovery(material, code, expected_id, expected_key, algorithm)`
accepts case-insensitive pasted codes with ASCII whitespace/hyphens, verifies the
independently trusted registration pins and restores the same signed identity.
Wrong secrets, pins or malformed material fail. The six-word, 66-bit transfer
code is a separate short-lived protocol and is not a durable recovery code.

Keep the code separate from its ciphertext, never log either, and clear displayed
codes and unlocked handles on background/logout. Server backup generations,
read-back, save acknowledgment and key replacement are application responsibilities.

`recovery::verify_recovery` returns only verified identity JSON and clears the
temporary imported key; it does not persist a record or change the source handle.
The application must compare the identity's version to current registration.
`CoreAgent::sign_document(content)` uses the existing native-header preparation
and verified completion pipeline to produce fresh signed document/version IDs,
exact `content` and `jacsSha256`. It confers no application authority and leaves
`sign_message` behavior unchanged.

Encrypted rotation stages resume through `CoreAgent::resume_key_rotation` using
an existing `AgentMaterial` envelope. It verifies the V2 predecessor/candidate
proof and private/public-key match before returning `PreparedKeyRotation`.
That stage can `sign_document` for candidate possession and `export_recovery`
before activation. `commit_encrypted_key_rotation` requires the exact accepted
identity and public key, validates encrypted bytes even on an idempotent replay,
and leaves the current signer intact on failure. Acceptance pins must come from
an authenticated registry: the library does not establish network acceptance.
