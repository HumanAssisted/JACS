# RMCP 3 Upgrade Spike

Date: 2026-07-28

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
