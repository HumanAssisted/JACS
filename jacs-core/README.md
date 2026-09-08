# jacs-core

**Portable JACS protocol layer — no I/O.**

`jacs-core` is the compile-anywhere protocol crate for [JACS](https://github.com/HumanAssisted/JACS).
It holds the cryptographic primitives, canonical JSON serializer, embedded
schemas, encrypted-key envelope codec, and agreement payload helpers that
both the native [`jacs`](https://crates.io/crates/jacs) crate and the
browser-side source-built [`jacs-wasm`](../jacs-wasm/README.md) wrapper share.

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
- The home of `Ed25519DalekSigner`, `Pq2025Signer`, the `DetachedSigner`
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
  [`jacs-cli`](https://crates.io/crates/jacs-cli) and
  [`jacs-mcp`](https://crates.io/crates/jacs-mcp), both built on `jacs`.

If you want the full native JACS experience (storage backends, A2A,
attestation, MCP, observability), use `jacs`. If you want to sign or verify a
JACS document in the browser, build `@jacs/wasm` from source; it was not yet
published on npm at the 2026-07-09 distribution baseline.

## Quick start

```rust,ignore
use jacs_core::{CoreAgent, SigningAlgorithm};
use serde_json::json;

let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519)?;
let signed = agent.sign_message(&json!({ "hello": "world" }))?;
let outcome = agent.verify(&signed)?;
assert!(outcome.valid);
```

For multi-party agreements:

```rust,ignore
use jacs_core::{CoreAgent, SigningAlgorithm, agreements};
use serde_json::json;

let mut alice = CoreAgent::ephemeral(SigningAlgorithm::Ed25519)?;
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
    (alice_id.as_str(), alice.public_key(), SigningAlgorithm::Ed25519),
    (bob_id.as_str(),   bob.public_key(),   SigningAlgorithm::Pq2025),
];
let outcome = agreements::verify(&doc, &signers)?;
assert!(outcome.all_valid);
```

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

- [`jacs`](../jacs/README.md) — native facade. Filesystem, DNS, HTTP, MCP, CLI, storage.
- [`jacs-wasm`](../jacs-wasm/README.md) — browser bindings that wrap `jacs-core` with a TypeScript API.
- [PRD](../docs/jacs/JACS_WASM_PRD.md) — full design + scope of the native/wasm split (HAI internal).

## License

Apache-2.0. See [`LICENSE-APACHE`](../LICENSE-APACHE).
