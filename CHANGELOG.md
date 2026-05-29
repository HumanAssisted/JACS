## 0.11.2

(unreleased)

### Security

- Fixed `jacs document verify` so it verifies the document signature, not just schema and `jacsSha256`; forged documents with recomputed hashes now fail verification.

MCP/CLI hardening from a focused security review of the `jacs-mcp` and `jacs-cli` layers (each fix is test-covered):

- **MCP verify-trust bypass via `key_dir` closed.** `jacs_verify_text` / `jacs_verify_image` accepted a caller-supplied `key_dir` that bypassed the path policy and was consulted ahead of the trust store, letting a malicious client shadow a trusted signer's public key and forge provenance. The override is now disabled by default (returns a clear error); set `JACS_MCP_ALLOW_KEY_DIR=true` to opt in, and even then the directory is confined to the MCP base dir by the path policy.
- **Destructive MCP key rotation is now opt-in.** `jacs_rotate_keys` was dispatchable in the default profile with no gate; a prompt-injected client could force-rotate (and thus re-key) the agent's identity, invalidating every remote that pinned the old key. It now default-denies and requires `JACS_MCP_ALLOW_KEY_ROTATION=true`, mirroring the existing registration/untrust/inline-secrets gates, and logs a structured warning when blocked.
- **A2A first-contact is no longer presented as proven identity.** A `Verified`-policy first contact pins the key trust-on-first-use but only proves control of the card origin, not the claimed `jacsId`. `TrustAssessment` now carries a `first_contact` flag (surfaced through the `jacs_assess_a2a_agent` MCP result), the human-readable reason gains an explicit caveat, and a structured `a2a_first_contact_pinned` warning is emitted, so callers can refuse to treat origin-control as identity. (Also fixed the MCP assess result reading the trust level from the camelCase `trustLevel` field.)
- **W3C request-proof verification no longer overstates its guarantee.** `jacs_w3c_verify_request` verifies the proof against a caller-supplied DID document that is never independently resolved or trust-pinned, so a success is proof-of-possession, not proof of identity. The result now includes `did_document_trusted: false` and a reworded message making that explicit.
- **Observability on the serve path (CLAUDE.md norm).** The `jacs mcp` server now installs a STDERR tracing subscriber before serving, so verification/trust/auth warnings are no longer dropped to a no-op dispatcher. STDERR (never STDOUT) is used so the JSON-RPC transport stays byte-clean, and `jacs mcp` emits a structured startup line. (Scoped to the serve path so one-shot CLI commands that emit machine-readable envelopes to stderr are unaffected.)

### Dependencies

Resolved the open Dependabot alerts across the Python and Node binding manifests. The published `jacs` wheel declares no runtime dependencies (`dependencies = []`); every advisory was in a transitive dev/optional-extra dependency or an example lockfile, not in the shipped library.

- **Python (`jacspy/uv.lock`).** Added patched-version floors to `[tool.uv] constraint-dependencies` in `jacspy/pyproject.toml` and re-resolved the lock: idna ≥3.15, urllib3 ≥2.7.0, requests ≥2.33.0, pillow ≥12.2.0, langchain-core ≥1.3.3, langsmith ≥0.8.0, langgraph ≥1.0.10, authlib ≥1.6.12, PyJWT ≥2.12.0, python-multipart ≥0.0.27, python-dotenv ≥1.2.2, uv ≥0.11.6. The re-resolution also dropped `diskcache` (no patched release) from the tree.
- **Node (`jacsnpm`, `jacsnpm/examples`).** Raised the `qs` override to ≥6.15.2 and regenerated both lockfiles (`npm audit` reports 0 vulnerabilities).
- **WASM smoke example (`jacs-wasm/examples/vite-smoke`).** Bumped `vite` to ≥6.4.2.
- **chromadb (GHSA-f4j7-r4q5-qw2c).** No patched release exists (latest 1.5.9 is still in range; pinned `~=1.1.0` by the optional `crewai` extra) and it is absent from the published wheel, so the alert was dismissed as tolerable risk rather than patched.

## 0.11.1

(unreleased)

### Added

- Added W3C DID interop helpers for additive `did:wba` projection, agent description and `.well-known` discovery artifacts, request-bound DID authentication proofs, and cross-language CLI/MCP/Python/Node/Go smoke coverage.

### Security

Key-management hardening from a focused security review (each fix is test-covered):

- **A2A key-substitution defense (TOFU pinning).** A verified self-published JWKS only proves control of the Agent Card's origin, not the claimed `jacsId`. `assess_a2a_agent` now pins the verifying A2A key trust-on-first-use, keyed by `jacsId:jacsVersion`; a later card for the same id/version that presents a different key is downgraded to `Untrusted` (refused under the `Verified`/`Strict` policies). Legitimate key rotation bumps the version and produces a fresh pin, so it is not flagged. Pin-store failures degrade gracefully (the agent stays `JacsVerified`).
- **A2A JWKS transport hardening.** JWKS used for trust decisions must now be served over `https`; plaintext `http` is rejected for non-loopback origins (`agent_card_origin`), closing a network-MITM key-substitution vector. `http` is still permitted for loopback hosts (local development).
- **Legacy v1 signature content is no longer silently trusted.** A legacy v1 signature (no `signatureContentVersion`) does not authenticate its signature metadata (`agentID`, `date`, `jti`, `signingAlgorithm`). It is still verified by default for backward compatibility, but acceptance now emits a loud, structured `SECURITY` event carrying the agent ID, and deployments can refuse legacy documents entirely by setting `JACS_REJECT_LEGACY_SIGNATURE_CONTENT=true`.
- **Hardened key re-encryption across the binding/MCP surface.** `binding-core`'s `reencrypt_key` (reachable from Python, Node, and the `jacs_reencrypt_key` MCP tool) previously wrote the re-encrypted private key with a bare `std::fs::write` (process-umask permissions, symlink-following, non-atomic). It now routes through the shared `reencrypt_private_key_file` primitive that writes atomically with owner-only `0o600` and refuses to follow symlinks, and validates the config-derived key filename against path traversal.
- **Private-key password no longer leaks via `Debug`.** `Config` and `Agent` now carry hand-written `Debug` impls that redact the at-rest key password (and, for `Config`, the database URL and raw config JSON), so the password can no longer reach logs or panic output through `{:?}`.
- **Decrypted signing key is zeroized.** The plaintext private key copied into the signing path (`sign_string` / `sign_bytes` / `sign_batch`) is now held in a `zeroize::Zeroizing` buffer and wiped after each operation, closing a memory-scraping window.
- **Key rotation marks the retired key obsolete and warns.** The old encrypted private key is still retained on disk after rotation (audit/recovery), but `FsEncryptedStore::rotate` now writes an owner-only obsolescence marker (`*.obsolete.json`) recording the superseded version, exposes `archived_key_obsolescence` / `is_archived_key_obsolete` for tooling, and logs a warning that the retained key is obsolete and still decryptable with the old password.

## 0.11.0

(unreleased)

## Unreleased

### Added

- New crate `jacs-core` (portable JACS protocol layer) that compiles for both native and `wasm32-unknown-unknown`. Holds the canonical-JSON serializer, embedded schema set, AES-256-GCM + Argon2id encrypted-key envelope (V2) plus the legacy PBKDF2 reader, `DetachedSigner` trait + Ed25519 (`ed25519-dalek`) and pq2025 (`fips204`) backends, `CoreAgent` sign/verify, and multi-party agreement payload helpers. No I/O — pure protocol.
- New crate `jacs-wasm` with the browser bindings (`wasm-bindgen` wrapper around `jacs-core`). Exports `initJacsWasm`, `createEphemeral`, `importEncryptedAgent`, `importEncryptedAgentFiles`, `createVerifier`, plus the `CoreAgentHandle` methods (`signMessageJson`, `verifyJson`, `verifyWithKeyJson`, `exportAgent`, `getPublicKeyBase64`, `algorithm`, `isUnlocked`, `clearSecrets`, `signAgreementJson`, `verifyAgreementJson`), the `createAgreementJson` free function, the `localStore.*` browser-storage helpers (with `RefusedPayload` / `StorageUnavailable` / `QuotaExceeded` / `KeyNotFound` error codes and a defense-in-depth secret-leak tripwire), the `workerHandleMessage` dispatcher used by the `@jacs/wasm/worker` subpath, and a hand-written TypeScript wrapper (`index.ts`) that single-sources `localStore` from the camelCase exports. Published to npm as `@jacs/wasm` via the new `release-wasm.yml` workflow triggered by `wasm-vX.Y.Z` tags.
- Web Worker bridge (`@jacs/wasm/worker`): `worker/index.ts` (main-thread API: `createEphemeralInWorker`, `importEncryptedAgentInWorker`, `WorkerAgentHandle`, `terminateWorker`) + `worker/jacs-worker.ts` (worker-side bootstrap routing `postMessage` events through Rust). Replies are always structured `{ id, ok, result | error }` — never thrown exceptions — so `id` correlation survives error paths.
- `jacs-wasm/scripts/finalize-pkg.sh` (idempotent post-`wasm-pack build` step): derives the version from `jacs-wasm/Cargo.toml`, merges `package.template.json` into `pkg/package.json`, sandbox-compiles the TS wrapper + worker glue, copies README. Fixture: `scripts/tests/finalize-pkg.test.sh`.
- `jacs-wasm/examples/vite-smoke/` (Vite + Playwright smoke that loads the locally built `pkg/`, signs, verifies, asserts `valid === true`) and `jacs-wasm/examples/worker-smoke/` (creates an ephemeral pq2025 agent in a Web Worker and signs + verifies a message).
- Cross-compat tests in `jacs/tests/wasm_compat_cross.rs` confirming that documents signed by native `jacs::Agent::signing_procedure` verify through `jacs_core::CoreAgent::verify_with_key` and vice versa.
- `SigningAlgorithm::from_wire_str` recognises both `"ed25519"`/`"pq2025"` and the legacy native `"ring-Ed25519"` form so signed documents from either platform verify on the other.
- `scripts/forbidden-deps.sh` extended for `jacs-wasm`; new Make targets `build-wasm`, `test-wasm`, `publish-jacs-wasm`, `release-jacs-wasm`, `retry-jacs-wasm`. `make versions` / `check-versions` now cover `jacs-core` and `jacs-wasm`.
- Documentation: new READMEs for `jacs-core` and `jacs-wasm`; `jacsnpm/README.md` carries a callout pointing browser users to `@jacs/wasm`; `CLAUDE.md` Version Bump Checklist updated for the two new crates.

### Verification status

- **Verified on every CI build (and locally):** `cargo test -p jacs --lib` (836 tests, no regression), `cargo test -p jacs-core` (74 tests across 10 suites), `cargo test -p jacs-wasm` (32 native tests + 7 `#[wasm_bindgen_test]` tests gated as `ignored` for non-browser runs), `jacs/tests/wasm_compat_cross.rs` (native ↔ jacs-core cross-compat), `RUSTFLAGS="-D warnings" cargo check -p jacs -p jacs-core -p jacs-binding-core -p jacs-mcp -p jacs-cli -p jacs-wasm`, `scripts/forbidden-deps.sh jacs-core wasm32-unknown-unknown`, `scripts/forbidden-deps.sh jacs-wasm wasm32-unknown-unknown`, `jacs-wasm/scripts/tests/finalize-pkg.test.sh`.
- **Verified only on CI (`release-wasm.yml` browser lane), not on local developer machines by default:** `wasm-pack test --headless --chrome` (the 7 browser-only `#[wasm_bindgen_test]` cases under `jacs-wasm/tests/web.rs`, `local_store.rs`, `worker.rs`, `agreement.rs`), the `jacs-wasm/examples/vite-smoke/` Vite + Playwright sign/verify smoke, and the `jacs-wasm/examples/worker-smoke/` Web Worker example. CI uses `browser-actions/setup-chrome@v1` which installs a matched Chrome + chromedriver pair; locally these require manually matching chromedriver to the installed Chrome major.

### Security

- Added `jacs-signature-v2` signature-content binding so new signatures cover the placement key, signed field names and values, and signature metadata; legacy unsigned-version documents verify only through the warning-emitting legacy path.
- Removed RSA/RSA-PSS from supported JACS key creation, signing, A2A/JWS examples, bindings, fixtures, generated docs, and default algorithm lists; tests that previously exercised RSA now cover Ed25519 instead.
- Switched new encrypted private-key writes to an Argon2id + AES-256-GCM JSON envelope while keeping legacy PBKDF2 raw envelopes decrypt-only.
- Upgraded Hickory DNS dependencies to `0.26.1` with `dnssec-ring`.
- Split `jacs-surrealdb` out of the default workspace so the default dependency graph and `cargo audit` path no longer pull the SurrealDB transitive RSA dependency.
- Added per-request nonces to JACS Authorization headers emitted by `build_auth_header`, matching replay-protected HAI API credentials.

### Added

- Added JACS email transport detection and typed verification results for migration from attachment-backed signatures to HTML-inline signed email.
- Added HTML-inline email helpers for PNG logo header embedding/extraction, topmost hidden-envelope parsing, artifact stripping, HTML equivalence normalization, and inline pre-image payload construction.
- Added `verify_signed_email` and `verify_html_inline_email_content` entrypoints so callers can route attachment and HTML-inline email through one JACS-owned verification surface during migration.
- Exposed `verify_html_inline_email_document` for HAI API callers that need verified inline document bytes plus parsed MIME parts for field-level forensics.

### Changed

- Consolidated the schema surface around generic signed documents, agreements, signatures, agents, A2A, and config.
- Removed retired workflow schemas and generated docs for message, task, commitment, todo, agentstate, program, node, eval, and the action/service/tool/unit/contact/embedding/todoitem components.
- Updated A2A, bindings, CLI/MCP contracts, examples, docs, and generated schema reference output for generic document payloads and explicit A2A skills while preserving the legacy `sign_message` / signed-email `jacsType: "message"` compatibility label.

### Fixed

- HTML-inline email verification now reports generated-HTML presentation tamper as `html_equivalence_failed`, returning `Failed` in strict mode and `PartiallyVerified` in degraded mode after the signed text body, headers, and user attachments verify.

## 0.10.2

Released 2026-05-07

## 0.10.1

(unreleased)

### Security

- Hardened config, key, trust, rotation journal, text, and media file IO against symlink and hard-link write races.
- Reworked `secure_io` on Unix to use opened parent-directory capabilities with fd-relative operations; strict JACS-owned state rejects parent symlinks by default.
- Added a `secure_io` guard in pre-commit and CI for newly introduced raw filesystem writes/reads in sensitive modules.

### Fixed

- Inline markdown/text signing now writes a full signed JACS document YAML footer between the existing `BEGIN/END JACS SIGNATURE` markers. Re-signing edited content by the same agent preserves `jacsId`, creates a new `jacsVersion`, and sets `jacsPreviousVersion`; legacy mini YAML blocks still verify.
- Generic document verification now recognizes inline-signed markdown/text by marker or `text/plain` / `text/markdown` MIME and dispatches to the inline verifier instead of failing as non-JSON.
- Added regression tests confirming image signatures, including robust LSB payloads, continue to embed/extract full signed JACS document JSON that verifies through normal JACS document verification.

### Release

- Local Rust publish targets now publish `jacs-media` before dependent crates, matching CI.

### Documentation

- Refreshed the repo, crate, CLI, Python, Node, and jacsbook landing docs around JACS as an open source provenance layer for agents and artifacts.
- Simplified quickstart and use-case guidance, removed stale release-note framing, and made `jacs mcp` the canonical user-facing MCP server path.
- Expanded visible docs to emphasize JSON/files, Markdown/text, images, and Rust email signing while keeping HAI.AI positioned as the hosted platform path for verified documents and agent behavior.
- Added API migration notes for consuming the new full inline-text footer shape and keeping the old synthetic inline metadata path as a legacy fallback.

## 0.10.0

### New

- **Inline text signatures.** `jacs sign-text <file>` / `jacs verify-text <file>` append YAML-bodied JACS signature blocks to the end of markdown and text files. The file *on disk* is preserved byte-for-byte (no PGP-style wrapping, no dash-escaping); the *hash input* is LF-normalised with trailing whitespace trimmed under the `canonicalization: jacs-text-v1` tag. Unordered multi-signer (matches the existing agreement model). Full language parity: Python `sign_text` / `verify_text`, Node `signText` / `verifyText`, Go `SignText` / `VerifyText`, and MCP tools `jacs_sign_text` / `jacs_verify_text`. Signature block body is valid YAML 1.2 between clear `-----BEGIN/END JACS SIGNATURE-----` markers — skimmable by humans, parseable by any YAML library. Signatures use a domain-separated pre-image (`JACS-INLINE-TEXT-V1\nsha256:<hash>`) so they cannot be replayed against other JACS surfaces. Schema hardening: `signatureBlockVersion: 1`, `publicKeyHash`, explicit `algorithm` / `hashAlgorithm` / `canonicalization` fields, `deny_unknown_fields`, 16 KiB body cap, 256-block file cap, no YAML anchors/tags/aliases. Marker-collision protection (lib + CLI layer): `sign-text` refuses (hard error) to sign input that contains a column-zero `-----BEGIN JACS SIGNATURE-----` line that is not part of a fully-valid block (BEGIN + END pair whose YAML body parses as `SignatureBlockYaml`); authors writing about the format indent the marker or use another documented workaround. The signature payload is emitted as a YAML literal-block scalar (`signature: |`) wrapped at 64 columns for human-readable on-disk inspection.
- **Image signatures — PNG, JPEG, WebP.** New `jacs-media` crate provides 100% Rust, Apache-2.0 / MIT embedding via PNG iTXt, JPEG APP11, and WebP XMP/EXIF chunks. Embedded payload is base64url-encoded JACS signed-document JSON (deliberately JSON, not YAML — images are binary containers). Signed claim carries `mediaSignatureVersion: 1`, `format`, `canonicalization: "jacs-media-v1"`, `hashAlgorithm: "sha256"`, `contentHash`, `embeddingChannels`, `robust`, and optional `pixelHash`. `jacs sign-image <in> --out <out>` / `jacs verify-image <file>` / `jacs extract-media-signature <file>`. `extract-media-signature` prints decoded JSON by default; `--raw-payload` gives the base64url wire form. Optional `--robust` LSB fallback for PNG/JPEG (OFF by default; WebP robust LSB is deferred). Single-signer semantics: re-signing overwrites; `--refuse-overwrite` opts into first-signer-wins. Payload size caps (64 KiB) surface `PayloadTooLarge` cleanly. Full language and MCP parity. Clean-room: zero AGPL code, `cargo deny` gate, cites prior-art without copying.
- **Strict vs permissive verify mode.** Every verify surface accepts a `--strict` flag (CLI) / `strict=True` (Python) / `{ strict: true }` (Node) / `VerifyTextOpts{Strict: true}` (Go). Default is **permissive** — a missing signature is a typed status (CLI exit 2, no throw). Strict opt-in treats missing-signature as a real failure (CLI exit 1, throws / rejects / returns `Err`). For both text and image: only file-level failures (`MissingSignature`, file-level `Malformed`) escalate in strict mode; per-block outcomes (`KeyNotFound`, `InvalidSignature`, `HashMismatch`, `UnsupportedAlgorithm`, per-block `Malformed`) stay as statuses inside the result envelope.
- **Key-dir override.** `--key-dir <dir>` on `verify-text` / `verify-image` lets callers supply a directory of `<signer_id>.public.pem` files without importing them into the local trust store. Resolution order: self → `--key-dir` (when provided) → local trust store → DNS. When `--key-dir` is provided, a matching `<signer_id>.public.pem` wins over the trust store for that specific signer; signers not present in the directory fall through to the trust store.
- **DNS-published key resolution.** The `DefaultKeyResolver` now plugs `jacs/src/dns/` into its inline resolver: when a signer's key is not in `--key-dir` or the local trust store, JACS performs a TXT lookup at `_v1.agent.jacs.<signer_domain>` for any embedded `jacsAgentDomain` and verifies the published `jac_public_key_hash`. Soft-fails to `KeyNotFound` if DNS is unreachable, the record is missing, or the digest does not match — same semantics as the rest of the resolver chain. Gated by the `dns-lookup` capability bit.
- **`ErrorKind::MissingSignature`.** New typed error kind. Permissive mode returns it as a status; strict mode raises it. Exposed as `MissingSignatureError` (Python), message-pattern (Node), and `ErrMissingSignature` sentinel (Go).
- **MCP path policy.** `jacs-mcp/src/path_policy.rs` ships a centralised six-layer file-path policy (base-dir + canonicalisation, absolute-path rejection, traversal-sequence rejection, symlink rejection by default, output-overwrite gate, backup-file placement). All Wave-3 MCP tools route through it; Python and Node MCP adapters delegate to the Rust helper via PyO3 / NAPI bindings.
- **Shared `write_backup_or_err` helper.** Single `<path>.bak` writer used by both inline-text and image sign paths. Refuses symlink targets, defaults to mode `0o600`, and honours `unsafe_bak_mode` opt-out on both `SignTextOptions` and `SignImageOptions`.

### Changed

- `SimpleAgentWrapper` surface grows from 27 to 32 methods. Method-parity fixtures updated accordingly.
- CLI grows from 33 to 38 commands.
- MCP server exposes 5 new tools; total 48 (was 43). Python and Node MCP adapters register the same 5 tools day-one (Q6 parity).
- `ResolvedKey.public_key_pem` doc comment now states the dual-shape contract explicitly: Ed25519 / pq2025 hold raw key bytes, RSA-PSS holds full PEM bytes.

### Migration

- No breaking changes. All existing APIs unchanged.
- Consumers of `ErrorKind` must extend match statements to handle the new `MissingSignature` variant (or add a catch-all `_`).
- A JACS inline signature proves "agent X signed these canonical bytes at their claimed time." It does **not** prove first creation or legal ownership — wording in user-facing docs is deliberately narrower than in earlier drafts.

## 0.9.15

### Refactoring

- `binding-core::SimpleAgentWrapper`: extracted `serialize_json`, `encode_base64`, `decode_base64`, `conversion_error`, `Self::from_agent` helpers; removes repeated constructor/error boilerplate
- `jacspy::SimpleAgent` (PyO3): extracted `py_runtime_err`, `map_py_runtime_result`, `simple_agent_with_info`, `signed_document_result`, `verification_result` helpers
- `jacs-cli/src/main.rs` split: new `agent_loader.rs` (config load + DNS policy overrides) and `password_bootstrap.rs` (env/file/legacy password resolution), each with unit tests; `main.rs` -342 lines
- Storage backends: shared helpers in `jacs/src/storage/common.rs` (key parsing, document reconstruction, signature extraction, field-filter shaping) consumed by DuckDB / PostgreSQL / Redb / SurrealDB / SQLite / Rusqlite

### Tests

- New `jacs/tests/fixtures/keys/agent-ed25519.{private.pem.enc,public.pem}` and matching committed agent JSON; RSA-PSS fixtures retained for legacy read-compat
- `jacs-mcp/tests/support/mod.rs`: added `prepare_temp_workspace_ed25519()` + `AGENT_ID_ED25519` alongside the existing RSA-PSS helper; signing-path tests (`audit`, `memory`, `search`, `integration`) use the Ed25519 variant
- `jacs/tests/agent_tests.rs`: split into `test_rsa_fixture_load_exposes_algorithm` (RSA load-only) and `test_update_ed25519_agent_and_verify_versions` (Ed25519 update round-trip); both `#[serial]` to prevent env-var races
- `jacs/tests/lifecycle_tests.rs`: lifecycle env now forces `JACS_AGENT_KEY_ALGORITHM=ring-Ed25519`; low-level creation test switched to Ed25519
- `jacsgo/simple_test.go`, `jacsnpm/test/simple.test.js`: hardcoded `RSA-PSS` flipped to `ring-Ed25519`
- `jacspy/tests/test_simple_agent_binding_shapes.py`: 9 new tests locking PyO3 return shapes
- `jacspy/tests/test_simple.py`: `TestAllAlgorithms.test_full_flow` parametrize drops `RSA-PSS` (still covered in `test_a2a*.py`)

### Makefile

- Deleted `release-all`; `release-everything` now directly tags crates / PyPI / npm / CLI / storage backends

## 0.9.14

### Config Signing and Key Rotation Hardening

- Config signing/verification: configs signed on create, rotation, and migration; tamper detection on load
- `rotate_with_mutex()` replaces per-binding rotation logic — CLI, binding-core, and MCP share the full pipeline (journal, save, config re-sign)
- Write-ahead journal for crash-safe key rotation with rollback recovery
- `jacsKeyRotationProof` in agent schema — cryptographically verifiable transition proofs signed with old key
- `verify_transition_proof()` on Agent

### Security

- Bounded gzip inflation during embedded-file export (prevents decompression bombs via `JACS_MAX_DOCUMENT_SIZE`)
- Atomic owner-only password file creation (0600); reject group/world-readable `.jacs_password` files
- Symlink-safe journal writes
- Upgraded fastmcp 2.14.0 -> 3.2.0 (CVE-2026-32871 SSRF/path traversal, CVE-2026-27124 OAuth confused deputy)
- Removed transitive lupa vulnerability (CVE-2026-34444) by eliminating pydocket/fakeredis dep chain
- Bumped hono 4.12.12, @hono/node-server 1.19.13, aiohttp 3.13.5, cryptography 46.0.7, Pygments 2.20.0
- Removed vendored fastmcp 2.x submodule

### Breaking

- License simplified: dual Apache-2.0/MIT -> Apache-2.0 only
- `JACSMCPServer` uses `http_app()` instead of `sse_app()` (fastmcp 3.x); deploy with `mcp.http_app()` for uvicorn

### Bindings

- `rotate_keys` wired through all bindings (Python, Node.js, Go, MCP)
- `sign_file` / `signFileSync` now raise on non-existent files (Python + Node.js)

### Fixes

- Fixed `DocumentService` mock missing `verify` method (CI compile error)
- Fixed example imports: `from mcp.server.fastmcp` -> `from fastmcp`
- DNS TXT record parsing: filter for `v=jacs` records among SPF/DKIM/DMARC
- Version-date ordering preferred over mtime for document versions

### Tests

- 10 rotation edge-case integration tests, proptest-based crypto fuzzing
- Config signing integration tests (814 lines)
- Cross-binding parity and MCP contract snapshot updates

## 0.9.13

### Cross-Language Feature Parity Enforcement

Added an automated parity enforcement system that catches binding drift across Rust, Python, Node.js, and Go through canonical JSON fixtures and snapshot tests.

**New fixtures (single source of truth for all languages):**
- `binding-core/tests/fixtures/method_parity.json` — 26 `SimpleAgentWrapper` public methods
- `binding-core/tests/fixtures/parity_inputs.json` — added `error_kinds` array (13 `ErrorKind` variants) and `sign_message_invalid_json_behavior` behavioral note
- `binding-core/tests/fixtures/adapter_inventory.json` — framework adapter modules and exported functions
- `binding-core/tests/fixtures/cli_mcp_alignment.json` — CLI-to-MCP tool mapping (16 aligned, 15 CLI-only, 27 MCP-only)
- `jacs-cli/contract/cli_commands.json` — 29 CLI commands + 4 feature-gated, with `mcp_tool` and `mcp_excluded_reason` fields

**New tests:**
- Rust: `method_parity.rs` (3), `parity.rs` error kind tests (2), `adapter_inventory.rs` (5), `cli_command_snapshot.rs` (4), `cli_mcp_alignment.rs` (5) — 19 new tests
- Python: `test_method_parity.py` (4), `test_error_parity.py` (9 incl. runtime triggers), `test_adapter_inventory.py` (5+) — 18+ new tests
- Node.js: `method-parity.test.js` (5), `error-parity.test.js` (4), `adapter-inventory.test.js` (5) — 14 new tests
- Go: `method_parity_test.go` (3), `error_parity_test.go` (4), `mcp_contract_drift_test.go` (3) — 10 new tests

### CLI

- Re-enabled `task create` command handler (was commented out; may be used by a2a)
- Extracted `build_cli()` public function from `main()` so snapshot tests can walk the Clap tree programmatically

### Documentation

- Added `DEVELOPMENT.md` — full API reference for Rust, Python, Node.js, and Go with examples, feature flags, storage backends, security, and framework adapters
- Added "Feature Parity Enforcement" section to `AGENTS.md` with fixture inventory and what-to-update-when guide
- Added "Feature Parity" section to `DEVELOPMENT.md` linking to `AGENTS.md`
- Updated `README.md` with refreshed messaging and streamlined content
- Updated binding READMEs (`jacspy`, `jacsnpm`, `jacsgo`, `jacs-cli`, `jacs-mcp`) — consolidated to reference `DEVELOPMENT.md`

## 0.9.12

(unreleased)

## 0.9.11

(unreleased)

## 0.9.10

(unreleased)

## 0.9.9

(unreleased)

## 0.9.7 (unreleased)

### Features

- **OS Keychain Integration**: Store and retrieve private key passwords from the OS credential store (macOS Keychain, Linux Secret Service via D-Bus). Eliminates the need for environment variables or plaintext password files on developer workstations.
  - New CLI commands: `jacs keychain set`, `jacs keychain get`, `jacs keychain delete`, `jacs keychain status`
  - Automatic password resolution: env var -> password file -> OS keychain
  - New config field `jacs_keychain_backend` (`"auto"`, `"macos-keychain"`, `"linux-secret-service"`, `"disabled"`)
  - Set `JACS_KEYCHAIN_BACKEND=disabled` for CI/headless environments
  - Feature-gated behind `keychain` Cargo feature (enabled by default in `jacs-cli`, optional in `jacs` core)
- **Memory-pinned key storage**: Decrypted private key bytes are now held in `mlock()`-pinned memory (`LockedVec`) that is excluded from core dumps (`MADV_DONTDUMP` on Linux) and zeroized before `munlock()` on drop.
- **Key directory safety**: `quickstart` and `create_with_params` now generate `.gitignore` and `.dockerignore` files in the key directory to prevent accidental exposure of private keys and password files.

### Security

- New `KeyBackend::OsKeychain` variant for desktop OS credential stores
- `resolve_private_key_password()` is now the single source of truth for password resolution across all encryption/decryption paths
- Platform integration tests for macOS Keychain (real backend) and Linux Secret Service

---

## 0.9.6

### Fixes

- Fix jacs-cli publish failure: remove unused `SimpleAgent` imports that caused `-D warnings` compile errors in CI
- Fix crates.io release workflow: add explicit `cargo check -D warnings` step before publish so compile failures are caught early
- Include `deprecation.js` and `deprecation.d.ts` in npm package bundle (was missing from `files` in package.json)

### Docs

- Add `RELEASING.md` with complete version bump checklist and release process

## 0.9.4

### API and core

- **`update_agent()`**: New API to update in-place agent data and re-sign as a new version (Rust `SimpleAgent` and free function).
- **`migrate_agent()`**: New API to patch legacy agent documents (e.g. add `iat`/`jti` in `jacsSignature`) and re-sign; returns `MigrateResult` with `jacs_id`, `old_version`, `new_version`, `patched_fields`.
- **`get_public_key()` / `get_public_key_pem()`**: Public key is read via agent/config abstraction; PEM output normalized via new `normalize_public_key_pem()` in `jacs::crypt` (handles raw bytes and existing PEM).
- **Non-strict `verify()`**: When document load fails (e.g. hash mismatch), non-strict mode returns a `VerificationResult` with `valid: false` and errors instead of a hard error.

### Storage and config

- **Filesystem storage**: Paths are resolved against a stored base directory; relative paths are joined to the base, absolute paths used as-is.
- **jacspy / jacsnpm**: Nested `config_path` / `configPath` and storage path resolution fixed; create() no longer leaves generated password in process env; installer integrity checks (checksums, safe archive members); `verify_by_id`/`verifyById` use native storage lookup.

### MCP and CLI

- **MCP state file access**: State file operations restricted to configured roots (`JACS_DATA_DIRECTORY`, `jacs_data`); optional env `JACS_MCP_ALLOW_ARBITRARY_STATE_FILES` and `JACS_MCP_ALLOW_INLINE_SECRETS`.
- **A2A trust**: `TrustLevel` display strings now PascalCase (`JacsVerified`, `ExplicitlyTrusted`); optional agent-card origin and JWS verification for trust assessment.

### Documentation

- **jacsbook**: Installation and setup updated for Node, Python, Go, Rust, and MCP; decision-tree, quick-start, and examples refreshed.
- **W3C**: New `jacs/docs/W3C_AI_AGENT_PROTOCOL_NOTES.md` with public position on W3C AI Agent Protocol alignment and interoperability.
- **Security**: `docs/security/jacspy-jacsnpm-hardening-tasks.md` added; READMEs (jacsnpm, jacspy, jacsgo) and attestation/A2A contract test expectations updated.

---

## 0.9.3 (2026-03-08)

- **crates.io**: User-Agent header on API calls; release workflow uses curl retries and tolerates exit 101.
- **Dependencies**: Bumps for ajv, minimatch, hono, @hono/node-server (jacsnpm), authlib (jacspy). Release v0.9.3 (#49).

---

## 0.9.2 (2026-03-06)

- **Release**: Version bump 0.9.2; release configs and CLI release workflow updates; paper update; cargo workspace alignment.

---

## 0.9.1 (2026-03-06)

- **Unified CLI**: Single `jacs` binary provides CLI and MCP (`jacs mcp`). Install via `cargo install jacs-cli`. Deprecated shims: `jacs mcp install`, `jacs mcp run`.
- **CI**: rust.yml tests jacs-cli and jacs-mcp; release-cli.yml builds jacs-cli; release-crate.yml includes jacs-cli in version check and publish. setup.sh and .mcp.json updated for unified jacs mcp.
- **jacs-mcp**: Spawns `jacs mcp` via jacs-cli; removed empty `http = []` stub. Contract snapshot 0.9.0 → 0.9.1.
- **Dependencies**: Bumps for ajv, minimatch, hono, @hono/node-server (jacsnpm), authlib (jacspy).
- **Build**: Windows build fix; CLI retry behavior; compiler warnings fixed (including attestation feature). Publish components and CLI docs.

---

## 0.9.0

### Attestation

- **Attestation module**: Feature-gated (`--features attestation`) system for creating evidence-based trust proofs on top of cryptographic signing. Attestations bind claims, evidence references, derivation chains, and policy context to signed JACS documents.
- **Core types**: `AttestationSubject`, `Claim`, `EvidenceRef`, `Derivation`, `PolicyContext`, `DigestSet` in `jacs/src/attestation/types.rs` with full JSON Schema at `schemas/attestation/v1/attestation.schema.json`.
- **Create attestation**: `create_attestation()` API with subject, claims, optional evidence/derivation/policy. Claims support `confidence` (0.0-1.0) and `assuranceLevel` (self-reported, verified, audited, formal).
- **Verify attestation**: Two-tier verification -- local (signature + hash, <1ms) and full (evidence digests, freshness, derivation chain, <10ms). Structured `AttestationVerificationResult` output.
- **Lift to attestation**: `lift_to_attestation()` upgrades existing signed documents to attestations by wrapping them as the attestation subject with additional claims.
- **DSSE export**: `export_attestation_dsse()` wraps attestations as in-toto Statements in DSSE envelopes for SLSA/Sigstore/in-toto compatibility. Predicate type: `https://jacs.dev/attestation/v1`.
- **Evidence adapters**: Pluggable `EvidenceAdapter` trait with built-in adapters for A2A artifacts and email evidence. Custom adapter support via `normalize()` / `verify_evidence()` contract.
- **Derivation chains**: Track multi-step transformations with input/output digests, transform metadata, and configurable depth limits (default 10).
- **CLI**: `jacs attest create` and `jacs attest verify` subcommands with `--full`, `--json`, `--from-document`, and output file support.
- **Digest utilities**: Shared `compute_digest_set()` / `compute_digest_set_bytes()` using JCS canonicalization (RFC 8785). 64KB auto-embed threshold for evidence.

### Attestation Bindings

- **Rust SimpleAgent**: `create_attestation()`, `verify_attestation()`, `verify_attestation_full()`, `lift_to_attestation()`, `export_attestation_dsse()`.
- **binding-core**: JSON-in/JSON-out attestation API for all language bindings.
- **Python (jacspy)**: `JacsClient.create_attestation()`, `verify_attestation()`, `lift_to_attestation()`, `export_attestation_dsse()` with keyword arguments. Feature-gated behind `--features attestation`.
- **Node.js (jacsnpm)**: Async attestation methods on `JacsClient` class plus sync convenience functions in `simple.ts`. Feature-gated behind `--features attestation`.
- **MCP server (jacs-mcp)**: Three new tools -- `jacs_attest_create`, `jacs_attest_verify`, `jacs_attest_lift`. Graceful degradation when attestation feature not compiled.

### Attestation Testing

- **Benchmarks**: Criterion benchmarks for create (~86us), verify-local (~46us), verify-full (~73us), lift (~80us). All well under performance targets.
- **Cross-language tests**: Rust generates attestation fixtures (Ed25519 + pq2025), Node.js verifies them. 14 cross-language attestation tests.
- **Hello-world examples**: `examples/attestation_hello_world.{py,js,sh}` for Python, Node.js, and CLI.

### Documentation

- **What Is an Attestation?**: Concept page explaining signing vs attestation (`getting-started/attestation.md`).
- **Sign vs Attest Decision Guide**: When to use each API (`guides/sign-vs-attest.md`).
- **Attestation Tutorial**: Step-by-step from agent creation to verified attestation (`guides/attestation-tutorial.md`).
- **Verification Results Reference**: Full error catalog for `AttestationVerificationResult` (`reference/attestation-errors.md`).

## 0.6.0

### Security audit (MVP)

- **`audit()`**: New read-only security audit and health checks. Returns structured report (risks, health_checks, summary); checks config/directories, secrets/keys, trust store, storage paths, quarantine/failed files, and optionally re-verifies N recent documents. Exposed in Rust (`jacs::audit`), binding-core, jacspy (`jacs.audit()`), jacsnpm (`jacs.audit(options?)`), and MCP tool `jacs_audit`. Documented in jacsbook (Security Model) and READMEs.

### DX Improvements

- **Programmatic `create()` API**: New `CreateAgentParams` struct and `create_with_params()` method for non-interactive agent creation across all bindings (Rust, Python, Node.js, Go)
- **Programmatic create hardening**: `create_with_params()` now generates schema-valid agent payloads (including required service metadata), writes complete config key filename fields, and restores caller environment overrides after creation instead of mutating process env state.
- **Python create() password UX**: `jacspy.simple.create()` now guarantees immediate post-create load using the provided password even when `JACS_PRIVATE_KEY_PASSWORD` was initially unset.
- **`verify_by_id()` method**: Load and verify documents by ID from storage, with helpful error when `verify()` is called with non-JSON input
- **Key re-encryption**: New `reencrypt_key(old_password, new_password)` API and `jacs key reencrypt` CLI command
- **Password requirements documentation**: `password_requirements()` function, requirements shown before password prompts, clearer error messages
- **`pq-dilithium` deprecated**: Use `pq2025` (ML-DSA-87, FIPS-204) instead. `pq-dilithium` still works but emits deprecation warnings
- **Go default algorithm fix**: Changed default from `ed25519` to `pq2025`
- **Improved error messages**: `user_message()` method on errors, categorized `From<Box<dyn Error>>` conversion
- **Version alignment**: All packages (jacs-mcp, binding-core, jacspy, jacsnpm) aligned to 0.6.0

### Packaging and Release Hardening

- **jacsnpm install behavior**: Removed install-time native build (`npm install` no longer runs `napi build`), so consumers do not need a Rust toolchain at install time.
- **jacsnpm publish contents**: Added `mcp.d.ts` to published package files so `@hai.ai/jacs/mcp` TypeScript types resolve correctly from npm tarballs.
- **npm release checks**: Added release-time validation that required `.node` binaries exist and `npm pack --dry-run` contains all exported API files before `npm publish`.
- **Expanded npm binary coverage**: npm release workflow builds and validates hosted Linux/macOS targets (including Linux `arm64` musl) with best-effort builds for additional Linux/FreeBSD architectures; Windows artifacts are currently optional while checkout path compatibility is being remediated.
- **jacspy sdist portability**: Excluded `jacspy/examples/**` from crate packaging so `maturin sdist` no longer fails on colon-containing fixture filenames.
- **jacspy packaging source of truth**: Removed stale `jacspy/setup.py`; `pyproject.toml` + `maturin` now define Python package metadata and build behavior.
- **jacspy PyO3 compatibility fix**: Replaced deprecated PyO3 conversion APIs (`*_bound`, `into_py`) with current APIs in Rust bindings so `uv run maturin build --release` succeeds under strict warning-as-error CI settings.
- **CI early failure checks**: Added PR/push-time sdist build verification in Python CI, plus a uv-based wheel smoke test and npm tarball smoke install/import test.
- **Expanded wheel coverage**: PyPI release and CI wheel workflows now cover additional hosted targets (including Linux musl variants) with platform-specific build paths.
- **Python test correctness**: Updated unreachable-key-service test to use a valid UUID so it exercises the intended network error path.
- **Rust toolchain pinning for Python builds**: Python wheel CI and PyPI wheel release jobs now pin Rust `1.93` (matching workspace `rust-version`) to reduce toolchain drift.
- **Python CI trigger reliability**: Removed path filters from `Python (jacs)` workflow so Python tests always run on `push`/`pull_request` to `main` and are not silently skipped by unrelated file changes.
- **Python wheel CI on PRs**: `build-jacs-wheels` now runs for pull requests as well as pushes, so wheel build coverage is no longer shown as a skipped job in PR checks.
- **Temporary Windows CI bypass**: Windows runner jobs were removed from active CI/release matrices because GitHub Windows checkout cannot handle existing colon-named tracked fixtures. Linux/macOS coverage remains fully enabled to unblock releases; Windows automation will return after fixture/path normalization.

### A2A Interoperability Hardening

- **Foreign A2A signature verification (Rust core)**: `verify_wrapped_artifact()` now resolves signer keys using configured key resolution order (`local`, `dns`, `hai`) and performs cryptographic verification when key material is available. Unresolvable keys now return explicit `Unverified` status instead of optimistic success.
- **Parent signature verification depth (Node.js/Python)**: A2A wrappers now recursively verify `jacsParentSignatures` and report `parent_signatures_valid` based on actual verification outcomes.
- **Well-known document parity**: Node.js and Python A2A helpers now include `/.well-known/jwks.json` in generated well-known document sets, matching Rust integration expectations.
- **JWKS correctness improvements**: Removed placeholder EC JWK data in core A2A key helpers and added explicit Ed25519 JWK/JWS support (`EdDSA`) for truthful key metadata.
- **Node.js create() 12-factor UX**: `@hai.ai/jacs/simple.create()` now accepts password from `JACS_PRIVATE_KEY_PASSWORD` when `options.password` is omitted, with explicit error if neither is provided.

### Security

- **Middleware auth replay protection (Node + Python adapters)**: Added opt-in replay defenses for auth-style signed requests in Express/Koa (`authReplay`) and FastAPI (`auth_replay_protection`, `auth_max_age_seconds`, `auth_clock_skew_seconds`). Enforcement includes signature timestamp freshness checks plus single-use `(signerId, signature)` dedupe via in-memory TTL cache.
- **Replay hardening test coverage**: Added lower-level replay tests for middleware future-timestamp rejection paths (Express, Koa, FastAPI) and explicit cache-instance isolation semantics in shared replay helpers (Node + Python), documenting current per-process cache behavior.
- **Path traversal hardening**: Data and key directory paths built from untrusted input (e.g. `publicKeyHash`) are now validated via a single shared `require_relative_path_safe()` in `validation.rs`. Used in loaders (`make_data_directory_path`, `make_key_directory_path`) and trust store; prevents document-controlled path traversal (e.g. `../../etc/passwd`).
- **Schema directory boundary hardening**: Filesystem schema loading now validates normalized/canonical path containment instead of string-prefix checks, preventing directory-prefix overlap bypasses (e.g. `allowed_evil` no longer matches `allowed`).
- **Cross-platform path hardening**: `require_relative_path_safe()` now also rejects Windows drive-prefixed paths (e.g. `C:\...`, `D:/...`, `E:`) while still allowing UUID:UUID filenames used by JACS.
- **HAI verification transport hardening**: `verify_hai_registration_sync()` now enforces HTTPS for `HAI_API_URL` (with `http://localhost` and `http://127.0.0.1` allowed for local testing), preventing insecure remote transport configuration.
- **Verification-claim schema alignment**: Agent schema now accepts canonical `verified-registry` and keeps legacy `verified-hai.ai` alias for backward compatibility; added regression coverage to ensure both claims validate.
- **DNS TXT version regression coverage**: DNS tests now assert canonical `v=jacs` emission while preserving legacy `v=hai.ai` parsing support with explicit regression tests.
- **HAI key lookup endpoint default**: Remote key fetch now defaults to `https://hai.ai` (instead of `https://keys.hai.ai`) and normalizes trailing slashes before building `/jacs/v1/agents/{jacs_id}/keys/{version}` URLs; added regression tests for env precedence and URL construction.
- **Trust-store canonical ID handling**: `trust_agent()` now accepts canonical agent documents that provide `jacsId` and `jacsVersion` as separate fields, canonicalizes to `UUID:VERSION_UUID`, and keeps strict path-safe validation.
- **Config and keystore logging**: Removed config debug log in loaders; keystore key generation no longer prints to stderr by default (uses `tracing::debug`).
- **Example config**: `jacs.config.example.json` no longer contains `jacs_private_key_password`; use `JACS_PRIVATE_KEY_PASSWORD` environment variable only.
- **Password redaction in diagnostics**: `check_env_vars()` now prints `REDACTED` instead of the actual `JACS_PRIVATE_KEY_PASSWORD` value, consistent with `Config::Display`.

### MCP State Access Management

- **MCP state verify/load/update now JACS-document-first**: `jacs_verify_state`, `jacs_load_state`, and `jacs_update_state` now route through JACS document IDs (`jacs_id`, `uuid:version`) and JACS storage/document APIs rather than MCP-level direct filesystem reads/writes.
- **Path-based state access disabled at MCP layer**: File-path-only calls for verify/load/update now return `FILESYSTEM_ACCESS_DISABLED` in MCP handlers, reducing exposed filesystem attack surface while preserving JACS-internal filesystem behavior.
- **State lifecycle now persisted for MCP follow-up ops**: `jacs_sign_state` and `jacs_adopt_state` now persist signed state documents in JACS storage (instead of no-save flow) and default to embedded content for MCP document-centric lifecycle operations.
- **binding-core support added**: New `AgentWrapper::get_document_by_id()` API loads documents by `jacs_id` via agent/storage abstractions for MCP and wrapper reuse.
- **MCP state schema/docs updated**: `UpdateStateParams` now includes `jacs_id`; README/state tool docs updated to describe `jacs_id`-centric usage and file-path deprecation for verify/load/update.
- **Coverage added**: MCP tests now assert rejection of file-path-only verify/load/update calls and validate new `jacs_id` update parameter schema.

### Documentation

- **SECURITY.md**: Added short "Security model" subsection (password via env only, keys encrypted at rest, path validation, no secrets in config).
- **README**: First-run minimal setup, verification and key resolution (`JACS_KEY_RESOLUTION`), supported algorithms, troubleshooting, dependency audit instructions, runtime password note.
- **jacsnpm**: Documented that `overrides` for `body-parser` and `qs` are for security (CVE-2024-45590). Added `npm audit` step in CI.
- **jacspy**: Aligned key resolution docstring with Rust (comma-separated `local,dns,hai`); added note to run `pip audit` when using optional deps.
- **A2A documentation refresh**: Added detailed jacsbook guide at `integrations/a2a.md`, corrected stale A2A quickstart endpoints/imports (`agent-card.json`, `jwks.json`, `@hai.ai/jacs/a2a`), and aligned Node.js package references to `@hai.ai/jacs` across docs.
- **Agreement testing guidance**: Expanded jacsbook advanced testing docs with strict agreement-completion semantics and two-agent harness patterns for Python and Node.js.
- **README clarity**: Added explicit note that `check_agreement` is strict and fails until all required signers have signed.
- **Rust agreement test strictness**: Core `agreement_test` now explicitly asserts that `check_agreement` fails after the first signature and only succeeds after both required agents sign.


## 0.5.2

### Security

- **[CRITICAL] Fixed trust store path traversal**: Agent IDs used in trust store file operations are now validated as proper UUID:UUID format and resulting paths are canonicalized to prevent directory traversal attacks via malicious agent IDs.

- **[CRITICAL] Fixed URL injection in HAI key fetch**: `agent_id` and `version` parameters in `fetch_public_key_from_hai()` and `verify_hai_registration_sync()` are now validated as UUIDs before URL interpolation, preventing path traversal in HTTP requests.

- **[HIGH] Added configurable signature expiration**: Signatures can now be configured to expire via `JACS_MAX_SIGNATURE_AGE_SECONDS` env var (e.g., `7776000` for 90 days). Default is `0` (no expiration) since JACS documents are designed to be idempotent and eternal.

- **[HIGH] Added strict algorithm enforcement mode**: Set `JACS_REQUIRE_EXPLICIT_ALGORITHM=true` to reject signature verification when `signingAlgorithm` is missing, preventing heuristic-based algorithm detection.

- **[HIGH] Fixed memory leak in schema domain whitelist**: Replaced `Box::leak()` with `OnceLock` for one-time parsing of `JACS_SCHEMA_ALLOWED_DOMAINS`, preventing unbounded memory growth.

- **[MEDIUM] Improved signed content canonicalization**: Fields are now sorted alphabetically before signing, non-string fields use canonical JSON serialization, and verification fails if zero fields are extracted.

- **[MEDIUM] Added HTTPS enforcement for HAI key service**: `HAI_KEYS_BASE_URL` must use HTTPS (localhost exempted for testing).

- **[MEDIUM] Added plaintext key warning**: Loading unencrypted private keys now emits a `tracing::warn` recommending encryption.

- **[LOW] Increased PBKDF2 iterations to 600,000**: Per OWASP 2024 recommendation (was 100,000). Automatic migration fallback: decryption tries new count first, then falls back to legacy 100,000 with a warning to re-encrypt.

- **[LOW] Deprecated `decrypt_private_key()`**: Use `decrypt_private_key_secure()` which returns `ZeroizingVec` for automatic memory zeroization.

- **[LOW] Added rate limiting on HAI key fetch**: Outgoing requests to the HAI key service are now rate-limited (2 req/s, burst of 3) using the existing `RateLimiter`.

- **[LOW] Renamed `JACS_USE_SECURITY` to `JACS_ENABLE_FILESYSTEM_QUARANTINE`**: Clarifies that this setting only controls filesystem quarantine of executable files, not cryptographic verification. Old name still works with a deprecation warning.

### Migration Notes

- Keys encrypted with pre-0.5.2 PBKDF2 iterations (100k) are automatically decrypted via fallback, but new encryptions use 600k iterations. Re-encrypt existing keys for improved security.

# PLANNED
-  machine fingerprinting v2
- passkey-client integration
- encrypt files at rest
- refine schema usage
- more getters and setters for documents recognized by schemas
- WASM builds
 - https://github.com/verus-lang/verus?tab=readme-ov-file
- use rcgen to sign certs, and register with ACME
 https://opentelemetry.io/docs/languages/rust/
. ai.pydantic.dev
- secure storage of private key for shared server envs https://crates.io/crates/tss-esapi, https://docs.rs/cryptoki/latest/cryptoki/
- qr code integration
- https://github.com/sourcemeta/one

## 0.4.0
- Domain integration
- [] sign config
 - [] RBAC enforcement from server. If shared, new version is pinned. 

  - more complete python implementation
   - pass document string or document id - with optional version instead of string
   - load document whatever storage config is
   - function test output metadata about current config and current agent

- [] add more feature flags for modular integrations
- [] a2a integration
- [] acp integration


## jacs-mcp 0.1.0

 - [] use rmcp
 - [] auth or all features
 - [] integration test with client
 - [] https://github.com/modelcontextprotocol/specification/discussions

### devrel
- [] github actions builder for auto build/deploy of platform specific versions
--------------------

- [] cli install for brew
- [] cli install via shell script
- [] open license
 - [] api for easier integratios data processing 

 - [] clickhous demo
 - [] test centralized logging output without file output 
 
--------------------

## 0.3.7

### internals

- [x] Updated A2A integration to protocol v0.4.0: rewrote AgentCard schema (protocolVersions array, supportedInterfaces, embedded JWS signatures, SecurityScheme enum, AgentSkill with id/tags), updated well-known path to agent-card.json, and aligned Rust, Python, and Node.js bindings with passing tests across all three.
- [] remove in memory map if users don't request it. Refactor and DRY storage to prep for DB storage
- [] test a2a across libraries
- [] store in database
- [] awareness of branch, merge, latest for documents. 

### hai.ai

- integration with 

 1. register
 2. 


### jacsnpm

 - [] BUG with STDIO in general
      fix issues with Stdio mcp client and server log noise - relates to open telemetry being used at rust layer.

 - [] npm install jacs (cli and available to plugin)
 - [] a2a integration
 - [] integrate cli

### jacspy
 - [] mcp make sure "list" request is signed?
 - [] some integration tests
 - [] fastapi, django, flask, guvicorn specific pre-built middleware
 - [] auto generate agent doc from MCP server list, auto versions (important for A2A as well)
 - [] fastmcp client and server websocket
 - [] BUG? demo fastmcp client and server stdio 
 - [] a2a integration
  - [] have jacs cli installed along with wheel
   - [] python based instructions for how to create - cli create agent 
      1. cli create agent 
      2. config jacspy to load each agent
 - [] github actions builder for linux varieties
 - [] switch to uv from pip/etc

### JACS core
 
 - [] brew installer, review installation instrucitons,  cli install instructions. a .sh command?
 - [] more a2a tests
 - [] ensure if a user wants standard logging they can use that

 
 - [] register agent
 - [] remove requirement to store public key type? if detectable
 - [] upgrade pqcrypto https://github.com/rustpq/pqcrypto/issues/79
 - [] diff versions
 - [] bucket integration
 - [] RBAC integration with header
 - [] clean io prepping for config of io

 ### minor core
- [] don't store  "jacs_private_key_password":  in config, don't display
- [] minor feature - no_save = false should save document and still return json string instead of message on create document
 - [] default to dnssec if domain is present - or WARN

### jacsmcp

 - [] prototype

### jacspy

- [] refactor api
- [] publish to pipy 
- [] tracing and logging integration tests


### jacsnpm

- [] publish to npm
- [] tracing and logging integration tests


==== 
## 0.3.6

### Security

- **[CRITICAL] Fixed key derivation**: Changed from single SHA-256 hash to proper PBKDF2-HMAC-SHA256 with 100,000 iterations for deriving encryption keys from passwords. The previous single-hash approach was vulnerable to brute-force attacks.

- **[CRITICAL] Fixed crypto panic handling**: Replaced `.expect()` with proper `.map_err()` error handling in AES-GCM encryption/decryption. Crypto failures now return proper errors instead of panicking, which could cause denial of service.

- **[HIGH] Fixed foreign signature verification**: The `verify_wrapped_artifact` function now properly returns `Unverified` status for foreign agent signatures when the public key is not available, rather than incorrectly indicating signatures were verified. Added `VerificationStatus` enum to explicitly distinguish between `Verified`, `SelfSigned`, `Unverified`, and `Invalid` states.

- **[HIGH] Fixed parent signature verification**: The `verify_parent_signatures` function now actually verifies parent signatures recursively. Previously it always returned true regardless of verification status.

- Added `serial_test` for test isolation to prevent environment variable conflicts between tests.

- Added `regenerate_test_keys.rs` utility example for re-encrypting test fixtures with the new KDF.

- **[MEDIUM] Fixed jacsnpm global singleton**: Refactored from global `lazy_static!` mutex to `JacsAgent` NAPI class pattern. Multiple agents can now be used concurrently in the same Node.js process. Legacy functions preserved for backwards compatibility but marked deprecated.

- **[MEDIUM] Fixed jacspy global singleton**: Refactored from global `lazy_static!` mutex to `JacsAgent` PyO3 class pattern. Multiple agents can now be used concurrently in the same Python process. The `Arc<Mutex<Agent>>` pattern ensures thread-safety and works with Python's GIL as well as future free-threading (Python 3.13+). Legacy functions preserved for backwards compatibility.

- **[MEDIUM] Added secure file permissions**: Private keys now get 0600 permissions (owner read/write only) and key directories get 0700 (owner rwx only) on Unix systems. This prevents other users on shared systems from reading private keys.

### devex
- [x] add updates to book
- [x] add observability demo

### jacs
 - [x] a2a integration
- [x] clean up observability
   - Observability: added feature-gated backends (`otlp-logs`, `otlp-metrics`, `otlp-tracing`) and optional `observability-convenience`. Default build is minimal (stderr/file logs only), no tokio/OpenTelemetry; clear runtime errors if a requested backend isn’t compiled. Docs now include a feature matrix and compile recipes. Tests updated and all pass with features.

 - [x] dns verification of pubic key hash
      - DNS: implemented fingerprint-in-DNS (TXT under `_v1.agent.jacs.<domain>.`), CLI emitters for BIND/Route53/Azure/Cloudflare, DNSSEC validation with non-strict fallback, and config flags (`jacs_agent_domain`, `jacs_dns_validate`, `jacs_dns_strict`, `jacs_dns_required`). Added CLI flags `--require-dns`, `--require-strict-dns`, `--ignore-dns`, and `--no-dns` (alias preserved). Improved error messages, updated docs, and added policy/encoding tests.

 
 - [x] scaffold private key bootstrapping with vault, kerberos - filesystem





--------------------

## 0.3.5

- [x] Update documentation.

### JACS core

 - [x] add timestamp to prevent replay attacks to request/response features
 - [x] make cli utils available to other libs
 - [x] *** start effort to channel all logging to jacs -> open telemetry -> fs or elsewhere that doesn't write to stdio on 
    1. the main traffic for sign and verify
    2. all logs generated

### jacspy

 - [x] install python mcp libs with the python wheel, use python loader to extend/export jacs.so

## jacsnpm

proof of concept

 - [x] scaffold
 - [x] use refactored agent trait instead of replicating
 - [x] typescript mcp client and server tests
 - [x]  test sse mcp client and server
 - [x]  node express middleware


--------------------

# COMPLETED

## 0.3.4

## integrated demo

 - [x] sign request/response (any python object -> payload)
 - [x] verify response/request (any payload json string -> python object)
 - [x] integrate with fastMCP, MCP, and Web for request response
 - [x] have identity available to business logic
 - [x] have logs available for review (no writing to file, ephemoral)

## jacspy

 - [x] make decorator for easy use in @tools
 - [x] new local builder
 - [x] fastmcp client and server sse
 - [x] jacspy test -  sign(content) -> (signature, agentid, agentversion, documentid, documentversion)
 - [x] jacspy test - verify(content, signature, agentid, agentversion) -> bool, error

 
 ### General 

 - init √
 - [x] load(config) -> Agent
 
### detailed
 - [x] make sure config directory is in isolated location, like with key
 - [x] make config and security part of Agent
 - [x] don't use env  everywhere- dep jacspy
   - [x] load multistorage into agent object to re-use
   - [x] BUG keys directory isolation broken when re-using Multistorage. TODO wrap key saving in different function
   - [x] don't use set_env_vars() by default - may be more than one agent in system    
   - [x] change config to have storagetype string, add to config schema
   - write tests for no env vars usage of config
   - load by id from default store
   - [x] don't store passwords in config
   - [x] all old tests and some new tests pass
- [x] cli init function
 - [x] clean up fs defaults in init/config/ 
 - [x] bug with JACS_SCHEMA_AGENT_VERSION didn't have default on cli init
 - [x] separate JACS readme repo readme
 - [x] minimal github actions
 - [x] autodetect public key type
 - [x] refactor API so easier to use from higher level libraries  - create agent, load agent, save document, create document, update document, sign 
   init, load agent, verify agent, verify document, 
   - [x] single init, also signs agent
   - [x] load from config
   - [x] have load agent from config also load keys IF SIGNED

 
 

---------------

# 0.3.3

## jacs 0.3.3
 - [x] change project to workspace
 - [x] basic python integration
 - [x] upgraded to edition = "2024" rust-version = "1.85"
 - [x] separate public key location from private key location
 - [x] cli review and tests 
 - [x] TEST init agent without needing configs in filesystem by checking that needed ENV variables are set

## 0.3.2
 - [x] add common clause to Apache 2.0
 - [x] use a single file to handle file i/o for all storage types
 - [x] use an ENV wrapper to prep for wasm
 - [x] complete migration away from fs calls except for config, security, tests, cli 
 - [x] create tests using custom schemas - verify this is working


## 0.3.1
- [x] upgraded many dependencies using 
    cargo install cargo-edit
    cargo upgrade
    
## 0.3.0
- added jacsType - free naming, but required field for end-user naming of file type, with defaults to "document"
- TODO update jsonschema library
- updated strum, criterion
- updated reqwest library
- fixed bug EmbeddedSchemaResolver not used for custom schemas
- added load_all() for booting up  
- WIP move all fileio to object_store 
- WIP way to mark documents as not active - separate folder, or just reference them from other docs
- fixed issue with filepaths for agents and keys
- added jacsType to to jacs document as required
- added archive old version, to move older versions of docs to different folder
- added experimental vector metadata to headers for JACS documents.
- default to only loading most recent version of document in load_all
- fixed bug with naming file on update
- updated the then-current signed payload schema to always include the header
- add jacsLevel to track general type of document and its mutability

## 0.2.13
- save public key to local fs
- restricted signingAlgorithm in schema
- refresh then-current workflow schemas

## 0.2.12

- Let Devin.ai have a go at looking for issues with missing documentation, unsafe calles, and uncessary copies of data, updated some libs
- Fixed an issue with the schema resolver to handle more cases in tests.


## 0.2.11

- bringing some documentation up to date
- adding evaluations schemas
- adding agree/disagree to signature
- adding evaluation helpers **
- incremental documentation work **
- make github repo public **
- proper cargo categories

## 0.2.10

- decouple message from task so they can arrive out of order. can be used to create context for task
- parameteraize agreement field
- task start and end agreements functions
- fixed issue with schema path not being found, so list of fields returned incorrect
- retrieve long and short schema name from docs - mostly for task and agent


## 0.2.9

- tests for task and actions creation
- handle case of allOf in JSON schema when recursively retrieving "hai" print level
- add message to task
- fixed issue with type=array/items in JSON schema when recursively retrieving "hai" print level


## 0.2.8

 - add question and context to agreement, useful to UIs and prompting
 - adding "hai", fields to schema denote which fields are useful for agents "base", "meta", "agent"

## 0.2.7

 - crud operations for agent, service, message, task - lacking tests
 - more complete agent and cli task creation

## 0.2.6
 - doc include image


## 0.2.5
 - filesystem security module
 - unit, action, tool, contact, and service schemas
 - tasks and message schemas

## 0.2.4

- add jacsRegistration signature field
- add jacsAgreement field
- tests for issue with public key hashing because of \r
- add agreement functions in trait for agent
- fixes with cli for agent and config creation


## 0.2.3

 - add config creation and viewing to CLI
 - added gzip to content embedding
 - added extraction for embedded content
 - started mdbook documentation


## 0.2.2 - April 12 2024

 - prevent name collisions with jacs as prefix on required header fields
 - add "jacsFiles" schema to embed files or sign files that can't be embedded



## 0.2.1

 - build cli app (bulk creation and verification) and document
 - encrypt private key on disk

## 0.2.0

 - encrypt private key in memory, wipe
 - check and verify signatures
 - refactors
 - allow custom json schema verification
