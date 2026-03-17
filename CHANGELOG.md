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
- added jacsEmbedding to headers, which allow persistance of vector embeddings iwth jacs docs. 
- default to only loading most recent version of document in load_all
- fixed bug with naming file on update
- changes to message schema to always include header
- add jacsLevel to track general type of document and its mutability

## 0.2.13
- save public key to local fs
- restricted signingAlgorithm in schema
- refresh schema for program, program node/consent/action/tool

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
