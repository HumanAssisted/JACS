Welcome.

You may use the top level Cargo.toml to understand the repo.
jacs/ is the directory with the core library.
./jacspy is the python wrapper with functionality for integrations
./jacsnpm is the npm/node wrapper with functionality for integrations

Look for examples in tests for how to use the library.
README.md and CHANGELOG.md may be useful to understand some future goals and what has been done.

## Where Binding Methods Belong

`binding-core/src/simple_wrapper.rs::SimpleAgentWrapper` is the **public binding API**. All language bindings (PyO3, napi-rs, CGo) call into it. New methods that need to be exposed to Python/Node/Go go here, and you must update `binding-core/tests/fixtures/method_parity.json` (see Feature Parity Enforcement below) or four snapshot tests fail.

`binding-core/src/lib.rs::AgentWrapper` is an **internal** `Arc<Mutex<Agent>>` wrapper used by `SimpleAgentWrapper` and the optional `a2a` / `attestation` feature impls. Do not add new public binding methods directly to `AgentWrapper`.

## Sibling Repos

- **haisdk** at `~/personal/haisdk` — wraps JACS, pins exact JACS versions in `rust/Cargo.toml`, `python/pyproject.toml`, and `node/package.json`. Local dev: haisdk's `rust/Cargo.toml` patches to `../../JACS/jacs`, `../../JACS/binding-core`, `../../JACS/jacs-mcp`. After a JACS bump, run `make check-versions` in haisdk before publishing JACS.
- **hai (API)** at `~/personal/hai/api` — verifies JACS signatures via middleware. Will fail at startup if the JACS auth contract changes.

## Standard Test Recipe

```bash
cargo test -p <pkg> --test <file> -- --nocapture <pattern> 2>&1 | tail -80
```

The `--` separator is required; without it cargo reports `unexpected argument`. Don't reformat the recipe on each run.

## Feature Parity Enforcement

Cross-language feature parity is enforced through canonical JSON fixtures that serve as the single source of truth. When you add or remove a method, error kind, CLI command, MCP tool, or adapter, you must update the relevant fixture — snapshot tests in all languages will fail otherwise.

### Canonical fixtures

| Fixture | What it tracks | Consumed by |
|---------|---------------|-------------|
| `binding-core/tests/fixtures/method_parity.json` | 26 `SimpleAgentWrapper` public methods | Rust, Python, Node, Go |
| `binding-core/tests/fixtures/parity_inputs.json` | 13 `ErrorKind` variants + behavioral notes | Rust, Python, Node, Go |
| `binding-core/tests/fixtures/adapter_inventory.json` | Framework adapter modules and public functions | Rust, Python, Node |
| `binding-core/tests/fixtures/cli_mcp_alignment.json` | CLI-to-MCP tool mapping (aligned, CLI-only, MCP-only) | Rust |
| `jacs-cli/contract/cli_commands.json` | 29 CLI commands + 4 feature-gated | Rust (extracted from Clap tree) |
| `jacs-mcp/contract/jacs-mcp-contract.json` | 42 MCP tools with parameter schemas | Python, Node, Go |

### What to update when

| Change | Update these fixtures | Tests that will catch you |
|--------|----------------------|--------------------------|
| Add/remove a `SimpleAgentWrapper` method | `method_parity.json` | `method_parity.rs`, `test_method_parity.py`, `method-parity.test.js`, `method_parity_test.go` |
| Add/remove an `ErrorKind` variant | `parity_inputs.json` (error_kinds array) | `parity.rs`, `test_error_parity.py`, `error-parity.test.js`, `error_parity_test.go` |
| Add/remove a CLI command | `cli_commands.json` + `cli_mcp_alignment.json` | `cli_command_snapshot.rs`, `cli_mcp_alignment.rs` |
| Add/remove an MCP tool | `jacs-mcp-contract.json` + `cli_mcp_alignment.json` | `mcp_contract.test.js`, `test_mcp_contract.py`, `mcp_contract_drift_test.go`, `cli_mcp_alignment.rs` |
| Add/remove a framework adapter | `adapter_inventory.json` | `adapter_inventory.rs`, `test_adapter_inventory.py`, `adapter-inventory.test.js` |

Each language defines its own exclusions and name mappings (e.g., `to_yaml` is excluded from Python/Go because those bindings don't expose it). The fixture is always the source of truth.

## Releasing

See **[RELEASING.md](./RELEASING.md)** for the complete release process, including
the full file checklist, tag-based CI workflow, and troubleshooting failed releases.

## Version Bump Checklist

When bumping the JACS version, **all** of the following locations must be updated to the same version. The publish order matters — crates.io requires dependencies to be published before dependents.

### Makefile commands

```bash
# Version bump (updates ALL files automatically, including storage crates)
make bump-patch      # 0.9.6 -> 0.9.7
make bump-minor      # 0.9.6 -> 0.10.0
make bump-major      # 0.9.6 -> 1.0.0

make versions        # show all detected versions from source files
make check-versions  # fail if any main-track versions don't match

# Pre-publish compile check (catches -D warnings failures before publish)
RUSTFLAGS="-D warnings" cargo check -p jacs -p jacs-binding-core -p jacs-mcp -p jacs-cli

# CI-triggered releases (via git tags)
make release-jacs          # crates.io (jacs, binding-core, jacs-mcp, jacs-cli)
make release-jacspy        # PyPI
make release-jacsnpm       # npm
make release-cli           # GitHub Release binaries
make release-jacs-storage  # storage backend crates
make release-everything    # all of the above

# Retry failed releases (deletes tag, retags, pushes)
make retry-jacspy
make retry-jacsnpm
make retry-cli

# Local publish (requires credentials)
make publish-jacs          # all Rust crates in dependency order
make publish-jacspy        # PyPI
make publish-jacsnpm       # npm
```

### Publish Order (crates.io)

Crates must be published in this order with ~30s delays between each for crates.io indexing:

1. `jacs` (core library — no JACS dependencies)
2. `jacs-binding-core` (depends on `jacs`)
3. `jacs-mcp` (depends on `jacs` + `jacs-binding-core`)
4. `jacs-cli` (depends on `jacs` + `jacs-mcp`)

The CI workflow (`release-crate.yml`) and `make publish-jacs` handle this order automatically.

### JACS Repo — Cargo.toml files (package version)

| File | Field |
|------|-------|
| `jacs/Cargo.toml` | `version` |
| `binding-core/Cargo.toml` | `version` |
| `jacs-mcp/Cargo.toml` | `version` |
| `jacs-cli/Cargo.toml` | `version` |
| `jacspy/Cargo.toml` | `version` |
| `jacsnpm/Cargo.toml` | `version` |
| `jacsgo/lib/Cargo.toml` | `version` |

### JACS Repo — Cargo.toml files (dependency version pins)

| File | Dependency |
|------|------------|
| `binding-core/Cargo.toml` | `jacs = { version = "X.Y.Z", path = ... }` |
| `jacs-mcp/Cargo.toml` | `jacs = { version = "X.Y.Z", path = ... }` |
| `jacs-mcp/Cargo.toml` | `jacs-binding-core = { version = "X.Y.Z", path = ... }` |
| `jacs-cli/Cargo.toml` | `jacs = { version = "X.Y.Z", path = ... }` |
| `jacs-cli/Cargo.toml` | `jacs-mcp = { version = "X.Y.Z", path = ... }` |

### Storage backend crates

**IMPORTANT:** These depend on the `jacs` core crate. When you bump the main
JACS version, you **must also bump the storage crate versions** (at least a
patch bump) because their `jacs` dep version changes and crates.io won't let
you re-publish the same version. `make release-jacs-storage` will skip them
if the tag already exists.

| File | Fields |
|------|--------|
| `jacs-duckdb/Cargo.toml` | `version` (bump!), `jacs = { version = "X.Y.Z" }` |
| `jacs-redb/Cargo.toml` | `version` (bump!), `jacs = { version = "X.Y.Z" }` |
| `jacs-surrealdb/Cargo.toml` | `version` (bump!), `jacs = { version = "X.Y.Z" }` |
| `jacs-postgresql/Cargo.toml` | `version` (bump!), `jacs = { version = "X.Y.Z" }` |

### JACS Repo — Non-Rust package manifests

| File | Field |
|------|-------|
| `jacspy/pyproject.toml` | `version` |
| `jacsnpm/package.json` | `version` |

### JACS Repo — Contract / metadata

| File | Field |
|------|-------|
| `jacs-mcp/contract/jacs-mcp-contract.json` | `server.version` |

### JACS Repo — Documentation version strings

| File | What to update |
|------|----------------|
| `README.md` | Footer version line |
| `jacs/README.md` | Footer version line |
| `jacs-cli/README.md` | Footer version line |
| `CHANGELOG.md` | Add new `## X.Y.Z` section at top |

### haisdk Repo — JACS version pins

These pin the exact JACS version used by haisdk. Update after publishing JACS to crates.io.

| File | Dependencies |
|------|-------------|
| `rust/haisdk/Cargo.toml` | `jacs = { version = "=X.Y.Z" }` and `jacs_local_path` |
| `rust/hai-mcp/Cargo.toml` | `jacs`, `jacs-binding-core`, `jacs-mcp` version pins |
| `rust/haisdk-cli/Cargo.toml` | `jacs-mcp` version pin |
| `python/pyproject.toml` | `jacs==X.Y.Z` |

## Verification

After bumping, verify with:

```bash
# Check all JACS versions match
make check-versions

# Verify workspace compiles cleanly (same flags as CI)
RUSTFLAGS="-D warnings" cargo check -p jacs -p jacs-binding-core -p jacs-mcp -p jacs-cli

# Regenerate lockfile
cargo generate-lockfile

# Run tests
make test-rust-pr
```

## Install Commands

The canonical install command for users is:

```bash
cargo install jacs-cli
```

This installs a single `jacs` binary with CLI + MCP server built in. The MCP server is started with `jacs mcp` (stdio transport only, no HTTP).

Do NOT reference any of these deprecated patterns in docs:
- `cargo install jacs --features cli`
- `jacs mcp install`
- `jacs mcp run`
- A separate `jacs-mcp` binary for end users
