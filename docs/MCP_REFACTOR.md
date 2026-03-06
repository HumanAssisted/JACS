# JACS Rust MCP Refactor Plan

## Purpose

This document defines the near-term refactor required in `jacs-mcp` so the
Rust MCP server can be reused in-process by `haisdk`.

The immediate consumer is `hai-mcp` in `~/personal/haisdk`. Today that server
cannot correctly extend the JACS MCP server because `jacs-mcp` is packaged as a
binary crate and is therefore consumed through a subprocess bridge. That bridge
is the wrong architecture for a local-only, stdio-only MCP server that must be
complete, DRY, and heavily tested in Rust.

The goal of this refactor is to make the Rust JACS MCP server reusable as a
library without changing ownership boundaries:

1. `jacs` still owns identity, signatures, verification, provenance, trust,
   A2A, and related crypto-backed workflows.
2. `jacs-mcp` still owns the canonical MCP packaging of those JACS operations.
3. `haisdk` will extend `jacs-mcp` in-process with HAI connectivity operations
   such as registration, authenticated API access, and agent email.

## Why HAISDK Needs This

`haisdk` needs to run a single MCP server process that:

1. is local only
2. is stdio only
3. exposes the full JACS MCP tool surface
4. adds HAI-specific tools in the same server
5. does not spawn `jacs-mcp` as a child process
6. does not duplicate JACS MCP protocol logic

Without a reusable JACS MCP library, `hai-mcp` is forced into one of two bad
options:

1. subprocess bridging to `jacs-mcp`, which creates extra process management,
   duplicated MCP wiring, weak tests, and state fragmentation
2. reimplementing JACS tools inside `haisdk`, which violates DRY and ownership
   boundaries

This refactor removes both failure modes.

## Current Problem

Current Rust layout:

1. `~/personal/JACS/jacs-mcp` is a binary crate.
2. `JacsMcpServer` exists and is already a real RMCP server implementation.
3. The tool router is internal to `JacsMcpServer`.
4. `hai-mcp` currently uses a subprocess bridge instead of importing JACS MCP
   directly.

That means the best Rust MCP implementation cannot be extended directly even
though the source is available locally.

## Non-Negotiable Requirements

### Functional Requirements

1. `jacs-mcp` must be usable as a Rust library crate.
2. The library must export the canonical `JacsMcpServer`.
3. The existing `jacs-mcp` binary must remain available as a thin stdio entry
   point.
4. The refactor must not change the meaning of existing `jacs_*` tools.
5. The refactor must preserve current environment-based agent loading behavior.

### Architecture Requirements

1. No HAI-specific behavior should be added to `jacs-mcp`.
2. No JACS crypto or provenance logic should move into `haisdk`.
3. The reusable surface should be small and stable.
4. The binary should become a thin wrapper over library code.

### Testing Requirements

1. The library surface must have direct tests.
2. The binary must keep a smoke test over stdio.
3. Tool listing and tool dispatch behavior must remain stable.
4. The refactor must improve, not weaken, the confidence of downstream MCP
   embedding.

## Recommended Near-Term Design

The near-term design is to make `jacs-mcp` a reusable library and keep
`JacsMcpServer` as the canonical concrete server type.

This is intentionally the least invasive change that unlocks HAISDK.

### Why This Is The Right Near-Term Design

1. `JacsMcpServer` already exists and already implements `ServerHandler`.
2. The JACS tool router is already complete and tested in Rust.
3. HAISDK can wrap the concrete `JacsMcpServer` in-process immediately.
4. This avoids a larger generic-tooling refactor before it is actually needed.

### What This Does Not Require

This plan does not require:

1. extracting JACS MCP tools into a separate generic crate right away
2. redesigning all RMCP routing abstractions
3. exposing internal router implementation details publicly

Those may become worthwhile later, but they are not required to unblock HAISDK.

## Required Public Library Surface

The library target should export a small public API, roughly equivalent to:

```rust
pub use crate::jacs_tools::JacsMcpServer;

pub fn load_agent_from_config_env() -> anyhow::Result<AgentWrapper>;
pub fn load_agent_from_config_path(path: &Path) -> anyhow::Result<AgentWrapper>;

#[cfg(feature = "mcp")]
pub async fn serve_stdio(server: JacsMcpServer) -> anyhow::Result<()>;
```

Notes:

1. Exact naming may differ, but the intent should remain the same.
2. `JacsMcpServer` should remain the canonical implementation.
3. Agent/config loading should move out of `main.rs` and into reusable library
   code.
4. The stdio serving helper should keep binary setup DRY.

## Detailed Refactor Plan

## Phase 1: Add A Library Target

### Deliverables

1. Add `src/lib.rs` to `jacs-mcp`.
2. Move reusable code out of `src/main.rs` into library modules.
3. Re-export `JacsMcpServer` from the library.
4. Re-export or define the config-loading helpers in the library.
5. Keep `src/main.rs` as a thin binary wrapper.

### Suggested File Layout

1. `src/lib.rs`
2. `src/jacs_tools.rs`
3. `src/config.rs` or equivalent helper module
4. `src/main.rs`

### Main Binary Responsibilities After Refactor

`src/main.rs` should only do:

1. initialize logging
2. load the agent from config
3. construct `JacsMcpServer`
4. serve it over stdio

It should not own business logic.

## Phase 2: Stabilize The Embedding Surface

### Deliverables

1. Make `JacsMcpServer::new(agent)` the canonical constructor.
2. Keep `JacsMcpServer::tools()` as the canonical tool inventory helper.
3. Ensure downstream crates can import and instantiate the server without
   depending on the binary entrypoint.
4. Document the supported embedding pattern.

### Embedding Pattern To Support

Downstream crates such as `hai-mcp` should be able to do this:

```rust
use jacs_mcp::JacsMcpServer;

let agent = jacs_mcp::load_agent_from_config_env()?;
let jacs = JacsMcpServer::new(agent);
```

The downstream server can then delegate `list_tools` and `call_tool` to this
in-process JACS server.

## Phase 3: Keep The Binary Thin

### Deliverables

1. Preserve `cargo run -p jacs-mcp` behavior.
2. Preserve stdio transport as the binary mode.
3. Preserve environment-variable based config loading.
4. Keep server info, tool definitions, and instructions consistent with the
   existing implementation.

## Optional Phase 4: Generic Tooling Extraction

This is not required for the near-term HAISDK integration, but it may be a good
follow-up if multiple downstream Rust MCP servers need to compose JACS routes on
their own state type.

Possible future direction:

1. extract JACS MCP business logic behind traits over shared JACS state
2. allow a downstream `ToolRouter<CustomServer>` to include JACS routes directly
3. keep `JacsMcpServer` as the canonical assembled server for simple use cases

Do not block the near-term library refactor on this.

## DRY Constraints

The refactor must preserve these DRY rules:

1. one canonical implementation of each `jacs_*` tool
2. one canonical source of server instructions and tool metadata
3. one canonical agent/config loading path for the binary and embedders
4. no duplicated MCP JSON-RPC handling outside RMCP

## API Stability Expectations

The initial public API can be explicitly marked as "embedding support for
HAISDK, subject to refinement", but the following should be treated as stable
enough for immediate downstream use:

1. `JacsMcpServer`
2. the agent/config loading helpers
3. the stdio serve helper

Avoid exposing internal router fields publicly unless there is a clear need.

## TDD Plan

This refactor should be done test-first.

## Stage 1: Library Construction Tests

Write failing tests first for:

1. constructing `JacsMcpServer` from a loaded `AgentWrapper`
2. importing `JacsMcpServer` through the library crate root
3. loading agent config through the new library helpers

Green condition:

1. the library API compiles and the tests pass without using `main.rs`

## Stage 2: Tool Surface Regression Tests

Write failing tests first for:

1. `JacsMcpServer::tools()` returns the expected canonical tool names
2. tool count does not regress unexpectedly
3. server metadata still identifies itself as `jacs-mcp`

Green condition:

1. the refactor preserves the current tool surface

## Stage 3: Binary Smoke Tests

Write failing tests first for:

1. the binary still starts over stdio
2. the binary still loads agent config from the expected environment
3. the binary still answers basic MCP initialize/list-tools flow

Green condition:

1. the binary remains a thin wrapper with unchanged external behavior

## Stage 4: Embedding Smoke Test

Write a failing test that mimics the downstream use case:

1. instantiate `JacsMcpServer` from library code
2. call `list_tools` or equivalent handler path without launching a subprocess

Green condition:

1. there is a direct proof that the server is embeddable in-process

## Suggested Test Inventory

1. `tests/library_exports.rs`
2. `tests/config_loading.rs`
3. `tests/tool_surface.rs`
4. `tests/binary_stdio_smoke.rs`
5. `tests/embedding_smoke.rs`

Exact filenames may differ, but this separation should be preserved.

## Acceptance Criteria

This refactor is complete when:

1. `jacs-mcp` builds as both a library and a binary
2. `JacsMcpServer` is importable from another Rust crate
3. the binary is a thin stdio wrapper over library code
4. existing `jacs_*` tool behavior is preserved
5. downstream code no longer needs to shell out to `jacs-mcp`

## Explicit Non-Goals

This refactor is not intended to:

1. add HAI API logic to JACS
2. redesign JACS ownership boundaries
3. expand the JACS tool surface
4. switch the JACS MCP binary away from stdio

## Downstream Consumer Expectation

Once this refactor lands, `haisdk` will:

1. depend on the `jacs-mcp` library directly from source
2. construct `JacsMcpServer` in-process
3. expose all `jacs_*` tools unchanged
4. add `hai_*` tools in the same MCP server process
5. remove the current subprocess bridge entirely

That is the near-term path to the correct Rust MCP architecture.
