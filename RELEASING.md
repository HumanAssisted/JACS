# Releasing JACS

## Files to update when bumping versions

All main crates share a single version (e.g. `0.9.6`). Storage backend crates
(`jacs-duckdb`, `jacs-redb`, `jacs-surrealdb`, `jacs-postgresql`) have their
own version track but their `jacs` dependency version must match the main version.

### Package versions (the `version = "X.Y.Z"` line)

| File | Field |
|------|-------|
| `jacs/Cargo.toml` | `version` |
| `binding-core/Cargo.toml` | `version` |
| `jacs-cli/Cargo.toml` | `version` |
| `jacs-mcp/Cargo.toml` | `version` |
| `jacsnpm/Cargo.toml` | `version` |
| `jacspy/Cargo.toml` | `version` |
| `jacsgo/lib/Cargo.toml` | `version` |
| `jacsnpm/package.json` | `"version"` |
| `jacspy/pyproject.toml` | `version` |
| `jacs-mcp/contract/jacs-mcp-contract.json` | `"version"` |

### Inter-crate dependency versions

| File | Dependency |
|------|-----------|
| `binding-core/Cargo.toml` | `jacs = { version = "..." }` |
| `jacs-cli/Cargo.toml` | `jacs = { version = "..." }` |
| `jacs-cli/Cargo.toml` | `jacs-mcp = { version = "..." }` |
| `jacs-mcp/Cargo.toml` | `jacs = { version = "..." }` |
| `jacs-mcp/Cargo.toml` | `jacs-binding-core = { version = "..." }` |
| `jacs-duckdb/Cargo.toml` | `jacs = { version = "..." }` |
| `jacs-redb/Cargo.toml` | `jacs = { version = "..." }` |
| `jacs-surrealdb/Cargo.toml` | `jacs = { version = "..." }` |
| `jacs-postgresql/Cargo.toml` | `jacs = { version = "..." }` |

### Documentation version references

| File | Line pattern |
|------|-------------|
| `README.md` | `vX.Y.Z \| [Apache-2.0 ...` |
| `jacs/README.md` | `**Version**: X.Y.Z \| ...` |
| `jacs-cli/README.md` | `vX.Y.Z \| [Apache 2.0 ...` |
| `CHANGELOG.md` | Add new `## X.Y.Z` section at top |

## Quick version check

```bash
make versions        # show all detected versions
make check-versions  # fail if versions don't match
```

## Release process

### 1. Bump versions

Update all files listed above. Then verify:

```bash
make check-versions
cargo generate-lockfile
RUSTFLAGS="-D warnings" cargo check -p jacs -p jacs-binding-core -p jacs-mcp -p jacs-cli
```

### 2. Commit and push

```bash
git add -A
git commit -m "Bump version to X.Y.Z"
git push
```

### 3. Release via tags

Release all registries (crates.io + PyPI + npm) plus CLI binaries:

```bash
make release-everything
```

Or release individually:

```bash
make release-jacs       # crates.io (jacs, binding-core, jacs-mcp, jacs-cli)
make release-jacspy     # PyPI
make release-jacsnpm    # npm
make release-cli        # GitHub Release binaries
make release-jacs-storage  # storage backend crates
```

### 4. Verify

Check each registry:
- https://crates.io/crates/jacs
- https://crates.io/crates/jacs-cli
- https://crates.io/crates/jacs-binding-core
- https://crates.io/crates/jacs-mcp
- https://pypi.org/project/jacs/
- https://www.npmjs.com/package/@hai.ai/jacs

### Retrying failed releases

```bash
make retry-jacspy      # delete tag, retag, push
make retry-jacsnpm
make retry-cli
```

For crates.io, if a crate already published but a later one failed, just re-run
`make release-jacs` — the workflow skips already-published crates.

### Storage backend crates

**IMPORTANT:** Storage backend crates (`jacs-duckdb`, `jacs-redb`, `jacs-surrealdb`,
`jacs-postgresql`) depend on the `jacs` core crate. When you bump the main JACS
version, you **must also bump the storage crate versions** (at least a patch bump)
because:

1. Their `jacs = { version = "X.Y.Z" }` dependency changes
2. crates.io won't let you re-publish the same version
3. `make release-jacs-storage` will skip them if the tag already exists

So on every main version bump: update their `jacs` dep version **and** bump their
own package version (e.g. `0.1.0` -> `0.1.1`).

| File | What to bump |
|------|-------------|
| `jacs-duckdb/Cargo.toml` | `version` + `jacs` dep version |
| `jacs-redb/Cargo.toml` | `version` + `jacs` dep version |
| `jacs-surrealdb/Cargo.toml` | `version` + `jacs` dep version |
| `jacs-postgresql/Cargo.toml` | `version` + `jacs` dep version |
