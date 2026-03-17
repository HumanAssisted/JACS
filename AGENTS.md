Welcome.

You may use the top level Cargo.toml to understand the repo.
jacs/ is the directory with the core library.
./jacspy is the python wrapper with functionality for integrations
./jacsnpm is the npm/node wrapper with functionality for integrations

Look for examples in tests for how to use the library.
README.md and CHANGELOG.md may be useful to understand some future goals and what has been done.

## Releasing

See **[RELEASING.md](./RELEASING.md)** for the complete release process, including
the full file checklist, tag-based CI workflow, and troubleshooting failed releases.

## Version Bump Checklist

When bumping the JACS version, **all** of the following locations must be updated to the same version. The publish order matters — crates.io requires dependencies to be published before dependents.

### Makefile commands

```bash
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

These have their own version track (e.g. `0.1.0`). Bump their package `version`
only when they have actual changes. **Always** keep their `jacs` dependency
version in sync with the main release.

| File | Fields |
|------|--------|
| `jacs-duckdb/Cargo.toml` | `version` (own track), `jacs = { version = "X.Y.Z" }` |
| `jacs-redb/Cargo.toml` | `version` (own track), `jacs = { version = "X.Y.Z" }` |
| `jacs-surrealdb/Cargo.toml` | `version` (own track), `jacs = { version = "X.Y.Z" }` |
| `jacs-postgresql/Cargo.toml` | `version` (own track), `jacs = { version = "X.Y.Z" }` |

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
