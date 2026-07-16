# Releasing JACS

## Files to update when bumping versions

All main crates share a single version (e.g. `0.9.6`). Storage backend crates
(`jacs-duckdb`, `jacs-redb`, `jacs-surrealdb`, `jacs-postgresql`) have their
own version track but their `jacs` dependency version must match the main version.

### Package versions (the `version = "X.Y.Z"` line)

| File | Field |
|------|-------|
| `jacs-core/Cargo.toml` | `version` |
| `jacs-media/Cargo.toml` | `version` |
| `jacs/Cargo.toml` | `version` |
| `jacs-wasm/Cargo.toml` | `version` |
| `binding-core/Cargo.toml` | `version` |
| `jacs-cli/Cargo.toml` | `version` |
| `jacs-mcp/Cargo.toml` | `version` |
| `jacsnpm/Cargo.toml` | `version` |
| `jacspy/Cargo.toml` | `version` |
| `jacsgo/lib/Cargo.toml` | `version` |
| `jacsnpm/package.json` | `"version"` |
| `jacs-wasm/package.template.json` | `"version"` |
| `jacspy/pyproject.toml` | `version` |
| `jacs-mcp/contract/jacs-mcp-contract.json` | `"version"` |

### Inter-crate dependency versions

| File | Dependency |
|------|-----------|
| `jacs/Cargo.toml` | `jacs-core = { version = "..." }` |
| `jacs/Cargo.toml` | `jacs-media = { version = "..." }` |
| `jacs-wasm/Cargo.toml` | `jacs-core = { version = "..." }` |
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
make check-release-matrix # validate checked-in shipped-artifact evidence
```

`release/shipped-artifacts.json` records what an unpinned consumer actually
gets. It is deliberately separate from source manifest versions. Do not update
install-facing documentation to imply parity until the public registries have
been queried and `make verify-shipped-release` passes.

## Release process

### 1. Bump versions

Use the bump script to update all files automatically:

```bash
make bump-patch   # 0.9.6 -> 0.9.7
make bump-minor   # 0.9.6 -> 0.10.0
make bump-major   # 0.9.6 -> 1.0.0
```

This updates all Cargo.toml, package.json, pyproject.toml, contract JSON,
README footers, CHANGELOG, and storage backend crates. It also runs
`cargo generate-lockfile` and `make check-versions` automatically.

Then verify the compile:

```bash
RUSTFLAGS="-D warnings" cargo check -p jacs -p jacs-binding-core -p jacs-mcp -p jacs-cli
```

Run the same blocking supply-chain gates used by CI:

```bash
./scripts/check-action-pins.sh
cargo audit
cargo audit --file jacs-surrealdb/Cargo.lock \
  --ignore RUSTSEC-2023-0071
cargo deny --all-features check advisories licenses
cargo deny --manifest-path jacs-surrealdb/Cargo.toml --all-features check advisories licenses
cargo deny --manifest-path jacs/examples/observability/Cargo.toml --all-features check advisories licenses
(cd jacsnpm && npm audit --audit-level=high)
```

The dated rationale for every temporary ignore is in `SECURITY_AUDIT.md` and
`deny.toml`. A new advisory is a release blocker.

### 2. Commit and push

```bash
git add -A
git commit -m "Bump version to X.Y.Z"
git push
```

### 3. Release via tags

Release all registries (crates.io, PyPI, Node npm, WASM npm, and the semantic
Go module/native assets) plus CLI binaries:

```bash
make plan-release-everything  # remote-aware, read-only tag plan
make release-everything
```

`release-everything` completes the version, shipped-matrix, and sealed-
changelog preflight before starting one serial tag-writing command. This remains
true under `make -j` and inherited `MAKEFLAGS`. The fixed tag order is Rust,
PyPI, CLI, Node, WASM, Go, then the storage crates. CLI deliberately precedes
Node because a normal `@hai.ai/jacs` install bootstraps the matching CLI asset.
Every tag in the batch is planned before the first write.

Or release individually:

```bash
make release-jacs       # crates.io (jacs-core, jacs-media, jacs, binding-core, jacs-mcp, jacs-cli)
make release-jacspy     # PyPI
make release-cli        # GitHub Release binaries (before Node)
make release-jacsnpm    # npm
make release-jacs-wasm  # npm @jacs/wasm
make release-jacsgo     # jacsgo/vX.Y.Z source tag + native libraries
make release-jacs-storage  # storage backend crates
```

The release helper reads versions directly from manifests, validates strict
SemVer, and passes Git arguments without shell evaluation. It distinguishes a
tag that exists only locally, only remotely, in both places with the same
identity, or in both places with conflicting identities. Storage tags use the
same checks; a failed probe or push stops the batch rather than being masked by
the shell loop. If a batch mixes existing and new tags, every tag must resolve
to the current `HEAD`; this prevents a partially retried release from spanning
two source commits.

Tag workflows are asynchronous. A pushed tag is not evidence that publication
succeeded. In particular, the Node `0.10.2`/`0.11.x` builds completed before an
npm `E403`; treat that as a credential/authorization failure, not a native build
failure.

The Rust workflows prefer crates.io OIDC trusted publishing. Before enabling
it, create a protected GitHub environment `crates-io` and configure a trusted
publisher on every crate with owner/repository `HumanAssisted/JACS` and
environment `crates-io`:

| Crates | Workflow |
|---|---|
| `jacs-core`, `jacs-media`, `jacs`, `jacs-binding-core`, `jacs-mcp`, `jacs-cli` | `release-crate.yml` |
| `jacs-duckdb`, `jacs-redb`, `jacs-surrealdb`, `jacs-postgresql` | `release-storage-crate.yml` |

Until all ten trust entries exist, leave the repository variable
`CRATES_IO_TRUSTED_PUBLISHING_ENABLED` unset/false and retain the scoped
`CRATES_IO_TOKEN` migration fallback. Once every entry is configured, set the
variable to `true`; each publish step then obtains a fresh short-lived token
immediately before uploading that crate. After one successful OIDC release,
require trusted publishing on every crate, delete the GitHub secret, and revoke
the old crates.io API token. An OIDC exchange failure is fatal and never falls
back silently to the long-lived credential.

The npm workflows use OIDC trusted publishing rather than a stored write token.
Before tagging, configure these exact trusted publishers on npmjs.com with the
`npm publish` action allowed:

| Package | Owner/repository | Workflow | Environment |
|---|---|---|---|
| `@hai.ai/jacs` | `HumanAssisted/JACS` | `release-npm.yml` | `npm` |
| `@jacs/wasm` | `HumanAssisted/JACS` | `release-wasm.yml` | `npm` |

The workflow pins Node 24 and npm 11.18.0, requests `id-token: write`, and sends
no `NPM_TOKEN`. `npm whoami` cannot validate OIDC because npm exchanges the
credential only during publish. A missing or mismatched registry trust entry
therefore fails the publish job explicitly, after candidate build and smoke
tests have already established that it is not a native build failure. After a
successful migration, disallow traditional publish tokens in npm package
settings and revoke the old automation token.

### 4. Verify and record shipped state

Check each registry:
- https://crates.io/crates/jacs-media
- https://crates.io/crates/jacs
- https://crates.io/crates/jacs-cli
- https://crates.io/crates/jacs-binding-core
- https://crates.io/crates/jacs-mcp
- https://pypi.org/project/jacs/
- https://www.npmjs.com/package/@hai.ai/jacs
- https://www.npmjs.com/package/@jacs/wasm
- https://github.com/HumanAssisted/JACS/releases (CLI and jacsgo assets)

Each workflow performs an exact-version post-publish smoke where its runtime
allows it. The npm jobs also run `npm audit signatures`, PyPI cryptographically
verifies PEP 740 provenance for every wheel and source distribution, and the CLI
and Go jobs download and verify every GitHub release attestation. After all jobs
are green:

1. Query every registry and inspect the published package contents.
2. Update `release/shipped-artifacts.json` with the observed versions and
   platform assets.
3. Run `./scripts/check-release-matrix.py --online`.
4. Run `make verify-shipped-release`; it must pass before claiming parity.
5. Test empty Rust, Python, Node CJS/ESM, Go, and browser consumers without
   repository-relative dependencies.

### Retrying failed releases

Inspect the exact retry before changing a remote tag:

```bash
make plan-retry-jacs
make plan-retry-jacspy
make plan-retry-jacsnpm
make plan-retry-jacs-wasm
make plan-retry-cli
make plan-retry-jacsgo
make plan-retry-everything  # registry and provenance-aware aggregate plan
```

Each plan is non-destructive and prints the original tag-object ID and peeled
commit ID. Apply a reviewed plan with the matching retry target:

```bash
make retry-jacs
make retry-jacspy
make retry-jacsnpm
make retry-jacs-wasm
make retry-cli
make retry-jacsgo
make retry-everything
```

A retry never deletes the local tag and never recreates a tag at `HEAD`. If the
original exists only on the remote, the helper first fetches that exact ref. It
then deletes only the remote ref and re-pushes the unchanged local ref. If the
final push fails, the exact local original remains, so rerunning the same target
is safe. If neither local nor remote has the original, retry refuses; recover
the original tag object from authoritative evidence instead of manufacturing a
replacement. `make release-delete-tags` is a destructive maintenance command,
not a retry mechanism.

Remote Git probes and writes have per-command deadlines. Override them only for
a known slow connection with `JACS_RELEASE_GIT_TIMEOUT_SECONDS`. Registry/API
probes use `JACS_RELEASE_HTTP_TIMEOUT_SECONDS`; exact CLI/Go inventory and
provenance verification has the bounded outer deadline
`JACS_RELEASE_VERIFY_TIMEOUT_SECONDS`.

`retry-everything` checks all six Rust crates (`jacs-core`, `jacs-media`, `jacs`,
`jacs-binding-core`, `jacs-mcp`, and `jacs-cli`) at the exact version. Only an
authoritative HTTP 404 is considered unpublished. HTTP 403/429/5xx, timeouts,
authentication errors, and transport failures stop the retry. An existing CLI
or Go GitHub release counts as complete only after the exact asset inventory,
checksums, and attestations pass `verify_github_release_attestations.py`; an
incomplete or unverifiable release requires manual review and is not
automatically retagged.

For crates.io, a retry of the shared `crate/vX.Y.Z` workflow skips any of the six
crates already published and resumes in dependency order: `jacs-core`, `jacs-media`, `jacs`, `jacs-binding-core`, `jacs-mcp`, then `jacs-cli`.

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
