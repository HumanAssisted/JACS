# RMCP 3 Upgrade Spike

Date: 2026-07-28

This is the historical July upgrade record. The September follow-up below
records the current SDK, profile boundaries and verification evidence.

## Outcome

Ship the RMCP 3 upgrade.

JACS now uses stable `rmcp 3.0.0` while retaining its stdio-only transport and
legacy MCP compatibility. A raw wire-level test proves that the same server
supports the MCP `2026-07-28` discovery lifecycle, cached tool catalogs, and
tool calls without an `initialize` handshake.

No JACS tool names, schemas, profiles, security gates, storage formats, or
signed artifacts changed.

## Tested Protocol Paths

| Path | Result |
|------|--------|
| Legacy `2025-11-25` `initialize` / `initialized` over stdio | Pass |
| Legacy profile-filtered `tools/list` | Pass |
| Legacy response omits `resultType` | Pass |
| `2026-07-28` `server/discover` without initialize | Pass |
| Discovery advertises tools and the JACS server identity | Pass |
| Discovery advertises `2026-07-28` among supported versions | Pass |
| Modern `tools/list` returns `resultType: complete` | Pass |
| Modern `tools/list` returns a five-minute public cache hint | Pass |
| Modern `jacs_sign_document` tool call | Pass |

The pre-upgrade TDD run established the expected compatibility boundary:
the legacy test passed on RMCP 1.8, while `server/discover` failed because that
server required `initialize`. Both tests pass on RMCP 3.0.0.

## Migration Changes

- Updated `rmcp` and `rmcp-macros` from 1.8.0 to 3.0.0.
- Adapted the manual `ServerHandler::call_tool` implementation to return
  `CallToolResponse`, which permits complete and future MRTR outcomes.
- Constructed non-exhaustive `ToolsCapability` through `Default`.
- Constructed `ListToolsResult` through its RMCP 3 builder.
- Added `ttlMs: 300000` and `cacheScope: public` to `tools/list`.

RMCP 3 derives `server/discover` from the existing `get_info()` implementation,
so JACS did not need a custom discovery handler. RMCP 3 advertises all known
protocol versions and defaults discovery itself to a non-cacheable private
result.

## Cache Decision

The tools catalog is immutable for the lifetime of a JACS MCP process:
compile-time features and the runtime `core` or `full` profile are fixed at
startup. It also does not vary by caller. A public five-minute TTL is therefore
safe and avoids repeated schema loading while remaining conservative.

If JACS later supports changing tools during a process, it must set
`listChanged: true`, emit tool-list change notifications, and revisit this TTL.

## Contract and Feature Audit

The checked-in MCP contract remains unchanged:

- Default profile: 25 tools.
- Full profile: 42 tools.
- Full contract snapshot matches the checked-in artifact.

The anticipated output-schema projection change was unnecessary. Stable RMCP
3.0.0 still represents `Tool::output_schema` as an optional JSON object, so the
existing JACS projection remains correct and required no edit.

The RMCP dependency enables only:

- `client`
- `server`
- `macros`
- `transport-child-process`
- `transport-io`
- RMCP's implied async read/write support

No RMCP Streamable HTTP, SSE, or OAuth transport feature is enabled. Other JACS
dependencies may independently use HTTP clients; they are unrelated to the MCP
transport.

## Verification

- Full `jacs-mcp` suite with `full-tools`: 145 passed, 0 failed.
- Raw legacy and modern stdio protocol tests: 2 passed, 0 failed.
- CLI MCP profile and observability tests: 11 passed, 0 failed.
- Default and full profile/tool/contract snapshot tests: pass.
- `RUSTFLAGS="-D warnings"` check for `jacs-mcp` and `jacs-cli`: pass.
- Repository fast Rust PR lane (`make test-rust-pr`): pass.

The official MCP `2026-07-28` server conformance runner was not used because it
currently accepts an HTTP URL rather than launching a stdio server. Adding an
HTTP bridge would test a transport JACS intentionally does not ship. The raw
stdio tests avoid same-SDK client/server assumptions and assert the relevant
wire shapes directly.

## Known Limitation

`cargo test` reports an existing future-incompatibility warning for an
ambiguous local variable named `tools` in a test module with multiple glob
imports. The line is unchanged by this spike, `-D warnings` passes, and fixing
the unrelated import ambiguity is outside this upgrade's scope.

## Rollback

Revert the RMCP manifest and lockfile updates, the RMCP 3 handler adaptations,
the protocol test, and this report. No data migration or signed-artifact
rollback is required.

## 2026-09-13: RMCP 3.3 and Local Signing Follow-up

The manifest now requires [RMCP 3.3.0](https://github.com/modelcontextprotocol/rust-sdk/releases/tag/rmcp-v3.3.0).
The starting lockfile already resolved RMCP and its macros to 3.2.0 despite
the manifest's 3.0.0 minimum. Protocol versions remain dates: stable
[`2026-07-28`](https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning)
is not a protocol named "MCP 2". Legacy initialization remains supported.

RMCP defaults are now explicitly disabled. The production dependency enables
only `server`, `transport-io` and `macros`, plus their implied `schemars`,
`transport-async-rw` and `uuid` features. Client and child-process features moved
to dev-dependencies; the SDK-required `process-wrap` 9.1.0 → 10.0.0 update is
test-only. The affected MCP/CLI test crates also update `serial_test` 3.5.0 →
4.0.1, whose [MSRV is below this workspace's Rust 1.97 requirement](https://github.com/palfrey/serial_test/releases/tag/v4.0.0).
Other supporting libraries were already current in the lockfile. Crypto,
keychain and schema-validation major migrations were deferred to separate
compatibility work.

The July profile counts above are historical. Current startup defaults to
explicit-key verification without loading private keys. Signing requires the
existing `local-sign` profile and an explicitly selected signed config; five
existing file tools additionally require `JACS_MCP_BASE_DIR`. Administrative
profiles remain unavailable. This update adds no authority, signing format,
tool, schema or transport endpoint.

Two concrete guidance/observability defects were corrected:

- A caller-controlled `jacsVisibility: public` label produced "freely shared"
  guidance. All visibility hints now describe advisory labels and preserve
  independent sharing consent. Signing and verification results distinguish
  provenance/integrity from human approval, authorization and truth.
- Calls outside the active inventory bypassed the local handler's WARN, and
  unknown tool names were echoed in JSON-RPC errors that RMCP logs at WARN.
  Dispatch now emits `mcp_tool_scope_denied` with a known tool name or `unknown`,
  and its returned error uses that same safe name. The raw test reproduced
  the unknown-name disclosure before this correction. Verification failures
  emit `mcp_verification_failed` with a static reason. Bodies, arguments, keys
  and passwords are not fields of these events; CLI logs remain on stderr.

Raw-wire tests preserve the distinct error layers: unavailable tools return
JSON-RPC `-32602`; malformed arguments return MCP `isError: true`; dispatched
JACS failures retain their existing JSON text envelope. Clients must check
the JACS `success`/`valid` fields even after MCP transport completion.

The added regressions exercise a real `jacs mcp` child over JSON lines, without
an RMCP client: modern discovery and protocol/metadata recovery, local JSON
sign/explicit-key verify/tamper/recovery, scope and argument rejection,
default verification with an unusable configured-key password, and opted-in
file path rejection followed by text sign/verify and backup preservation.

### Follow-up Verification

Final runs used macOS arm64, Cargo/rustc 1.97.0 explicitly first on PATH, one
sequential build lane, and `CARGO_TARGET_DIR=/private/tmp/jacs-sept13-target`
with two build jobs, debug info/incremental compilation disabled. An initial
Homebrew rustc 1.98 path mismatch was detected and the final runs repeated on
1.97; preliminary results are not the MSRV evidence.

| Check | Result |
|---|---|
| `cargo build --locked -p jacs-cli` | Pass |
| Raw `stdio_protocol` suite | 7 passed |
| `cargo test --locked -p jacs-mcp --features full-tools --lib --tests` | 156 passed, 0 failed, 7 existing ignored |
| `make -j1 -k test-rust-pr` | 2,489 passed, 18 existing ignored; five loopback socket binds denied by sandbox |
| Isolated `make test-jacs-secure-fetch` with scoped loopback permission | All 12 passed; resolves the five sandbox failures |
| `RUSTFLAGS="-D warnings" cargo check --locked -p jacs-mcp -p jacs-cli` | Pass |
| `cargo check --locked -p jacs-mcp --no-default-features` | Pass (binding path-policy use) |
| Same check with `--features mcp,core-tools` | Pass (minimal server) |
| `cargo clippy --locked -p jacs-mcp -p jacs-cli --all-targets -- -D warnings` | Pass |
| Production CLI RMCP feature tree | Only the six server/implied features listed above |
| Fresh RustSec audit | 0 vulnerabilities and warnings |
| Repository cargo-deny advisory/license gates | Pass; existing unmatched exceptions warn |
| Schema, no-bare-serial, secure-IO and changed-file formatting/whitespace guards | Pass |

The full make invocation exited nonzero solely because the sandbox rejected
`TcpListener::bind("127.0.0.1:0")` at `jacs/src/secure_fetch.rs:776` with
`PermissionDenied: Operation not permitted`. The isolated rerun used the same
source/toolchain and changed only the execution permission; no production or
test behavior was weakened. Other fast-lane targets continued and passed.

The seven MCP ignores predate this batch and cover the removed `full` runtime
profile pending a capability broker. They are not claimed as verified active
features. Official conformance-runner certification, other operating systems,
live keychains, native language-binding rebuilds and broad storage/PQ suites
were not run for this scoped update. No release or artifact migration occurred.
