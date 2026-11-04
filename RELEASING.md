# Releasing JACS

The coordinated source version is **0.16.1**. MCP is the primary documented
integration; Rust, Node, Python, Go and browser packages all remain supported
release surfaces. Consult [release status](docs/release-status.md) and the
[0.16.0 verification record](release/0.16.0-verification.json) (the latest
published release) for observed publication and installation evidence,
separately from source versions.

## Version and build commands

`make versions` displays and checks all 17 Rust crates, native npm, WASM npm,
Python, Go, mobile metadata and both MCP contracts. `make check-versions` performs
the same alignment check without the listing.

| Change | Preview without edits | Apply |
|---|---|---|
| Patch | `make plan-bump-patch` | `make bump-patch` |
| Minor | `make plan-bump-minor` | `make bump-minor` |
| Major | `make plan-bump-major` | `make bump-major` |

The bump helper updates the coordinated sources and lockfile identities. It
preserves observations of already published versions and never publishes.
**Do not bump again for this release: the source is already 0.16.1.**

```sh
make build-jacsnpm       # Native @hai.ai/jacs tarball
make build-jacspy        # Python jacs wheel
make build-jacsgo        # Go native library
make test-bindings       # Build and test fresh installed consumers for all three
```

These commands use the isolated native workspace and write candidates under
`target/native-bindings/artifacts`. The five-member portable Cargo workspace
stays separate. The extended native MCP and CLI publish as `jacs-mcp-compat` and
`jacs-cli-compat`, preserving library imports with Cargo dependency aliases; the
compatibility executable is `jacs-compat`. The primary CLI remains `jacs` from
`cargo install jacs-cli`, and MCP starts with `jacs mcp`.

## Held crates

`HELD_CRATES` in [the release catalog](scripts/release_catalog.py) lists crates
that keep their source version aligned but are not packaged or published, with
the reason. For 0.16.1 it holds `jacs-surrealdb`: its lock pins unpublished
jsonwebtoken and object_store backports, so crates.io keeps 0.15.0. A held crate
is excluded from candidate preparation, its own lock, the publish steps,
retries and registry parity; the generated release table names it with its
registry version. No released crate may depend on a held crate. Only a crate
with its own lock (`STANDALONE_LOCKS` in `scripts/rust_release.py`) can be held.
A crate inside a shared workspace lock would fail that lock's publication gate.

Holding a crate does not remove its security gate. Every release workflow's
`security-gate` audits the held crate's lock and runs
`scripts/check-security-exceptions.py` at the tagged commit. That check fails
after any review date in `archive/native/SECURITY_AUDIT.md`. The SurrealDB
exceptions RUSTSEC-2023-0071, RUSTSEC-2023-0089 and RUSTSEC-2025-0141 are due
2026-11-26. Finish every 0.16.1 tag by then, including retries, which re-push
the original tag. Otherwise complete a fresh reachability review and renew the
dates in the release commit before tagging. Review dates are deadlines, not
automatic renewals.

To release a held crate again, once its dependencies have published fixes:

1. Remove its `HELD_CRATES` entry.
2. Remove its `[patch.crates-io]` backports and its standalone `[workspace]`
   table, then regenerate its lock. It stays standalone because
   `archive/native/Cargo.toml` excludes it. A released crate cannot declare
   either table, and `rust_release.py validate` rejects one that does.
3. Restore its two publish steps in `release-crate.yml`; the release contract
   tests require them.
4. For SurrealDB, restore the reviewed `--ignore RUSTSEC-2023-0071` on the
   candidate audit while that exception remains in force.
5. Unpin its install guidance: the crate README,
   `archive/native/DEVELOPMENT.md` and the `jacs` storage module docs pin it
   to 0.15 while it is held.

## One-time registry setup

CI publication uses the `crates-io`, `pypi` and `npm` GitHub environments. A local
`npm login` authorizes local commands; it does not configure CI authentication.
Configure publisher identities in the registry before creating release tags.

### npm

For existing `@hai.ai/jacs`, configure a GitHub trusted publisher with:

| Setting | Value |
|---|---|
| Organization | `HumanAssisted` |
| Repository | `JACS` |
| Workflow filename | `release-npm.yml` |
| Environment | `npm` |
| Allowed action | Direct `npm publish` |

Use the package's npm Settings page, or npm 11.15+ with an interactive login
and account 2FA:

```sh
npm trust github @hai.ai/jacs --repo HumanAssisted/JACS --file release-npm.yml --env npm --allow-publish
```

`@hai.ai/jacs-wasm` has existed since 0.15.0. That first release used a
one-time bootstrap token, because npm requires an existing package before a
trusted publisher can be registered. Its trusted publisher, with the same
organization, repository and environment and **`release-wasm.yml`**, was
configured on 2026-11-03; 0.16.0 was its first OIDC publication, and
`release/0.16.0-verification.json` records the switch. The bootstrap variable
and secret are removed from the `npm` environment. Bootstrap mode
(`JACS_NPM_WASM_BOOTSTRAP=true` with the `NPM_WASM_BOOTSTRAP_TOKEN` secret) now
always fails, because the workflow requires the package to return HTTP 404.
Without a trusted publisher, OIDC publication fails after every gate passes. To
inspect or recreate it, use the npm website or an interactive 2FA session, and
name the package explicitly; without a name, `npm trust list` reads the
`package.json` in the current directory:

```sh
npm trust list @hai.ai/jacs-wasm
npm trust github @hai.ai/jacs-wasm --repo HumanAssisted/JACS --file release-wasm.yml --env npm --allow-publish
```

The npm CLI refuses publisher-setting changes authenticated only by a granular
token that bypasses 2FA. Use the website or an interactive 2FA session for those
settings. See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
and [npm trust](https://docs.npmjs.com/cli/v11/commands/npm-trust/).

### Rust and Python

- **crates.io:** `release-crate.yml` publishes every crate in
  [the ordered release catalog](scripts/release_catalog.py) except those in
  `HELD_CRATES` (16 for 0.16.1), including WASM, mobile, bindings and the
  DuckDB, PostgreSQL and Redb storage backends. Configure each crate's trusted
  publisher for `HumanAssisted/JACS`, `release-crate.yml`, and the
  `crates-io` environment. Keep the protected `CRATES_IO_TOKEN` migration credential for
  first publication/new crate names until all publisher identities exist and
  are verified. Then set `CRATES_IO_TRUSTED_PUBLISHING_ENABLED=true` and revoke
  the old crates.io API token; remove its secret. Rust publication is enabled.
- **PyPI:** configure the existing `jacs` project's trusted publisher for owner
  `HumanAssisted`, repository `JACS`, workflow **`release-pypi.yml`**,
  environment **`pypi`**. No PyPI API token is used. CI publishes the tested
  wheels and source distribution with PEP 740 attestations.
- **Go and CLI:** GitHub Actions creates the tagged releases and their attested
  native assets. The Go module remains
  `github.com/HumanAssisted/JACS/jacsgo`; its `jacsgo/vVERSION` tag is also the
  Go submodule version tag. No separate Go registry token is needed.

## Release 0.16.1, one step at a time

1. Confirm the intended version:

   ```sh
   make versions
   ```

2. Regenerate notices if dependencies changed, then run the source checks:

   ```sh
   make third-party-notices
   make check
   ```

   These commands cover both portable and native dependency notices. Finish
   the affected Rust, browser, mobile and native installed-consumer checks.
   CI repeats the required functional, audit, license and secret-scan gates.

   Source-only dependency patches do not qualify a crates.io release: Cargo
   does not propagate workspace patches to downstream registry consumers.
   Candidate preparation rejects Git dependencies and third-party path
   overrides, even when source builds and audits pass. Replace them with
   reviewed published fixes and regenerate the locks before release.

3. Review and commit the complete candidate, including restored workflows and
   package sources, then push that reviewed commit. Release commands require
   a clean worktree, including untracked files:

   ```sh
   git status
   git push origin HEAD
   ```

4. Preview all release tags. This does not create or push tags:

   ```sh
   make plan-release-everything
   ```

5. Start Rust publication and wait for **Release crates.io** to pass:

   ```sh
   make release-jacs
   ```

   Every catalogued crate except the held ones is prepared before the first
   upload (16 for 0.16.1); registry dependencies publish in catalog order.
   Exact archive checksums, audits, SPDX SBOMs and durable attested evidence
   remain mandatory.

6. Release CLI binaries and wait for **Release CLI Binaries**:

   ```sh
   make release-cli
   ```

   Native npm's installation check consumes this matching CLI release.

7. Release native npm and wait for **Release native npm**:

   ```sh
   make release-jacsnpm
   ```

8. Release Python and wait for **Release PyPI**:

   ```sh
   make release-jacspy
   ```

9. Release Go and wait for **Release jacsgo Native Libraries**:

   ```sh
   make release-jacsgo
   ```

10. Release browser npm and wait for **Release @hai.ai/jacs-wasm**. It
    publishes through its trusted publisher (see [npm](#npm)):

    ```sh
    make release-jacs-wasm
    ```

11. Record the actual published versions and verified evidence in
    `release/shipped-artifacts.json`, regenerate its documentation, and verify
    coordinated parity:

    ```sh
    python3 scripts/check-release-matrix.py --write-docs
    python3 scripts/check-release-matrix.py --require-parity
    ```

    The Shipped artifact matrix workflow also cryptographically verifies
    recorded npm/PyPI provenance and complete CLI/Go release inventories.

`make release-everything` is available when you want to start all six workflows
at once. It pushes all six tags; it does not wait between workflows. The
step-by-step sequence above makes failures easier to resolve before continuing.

## Plans, retries and evidence

Every release target has a corresponding `plan-release-*`, `plan-retry-*` and
`retry-*` command (`jacs`, `cli`, `jacsnpm`, `jacspy`, `jacsgo`, `jacs-wasm`).
`make plan-retry-everything` probes exact registry versions and checks GitHub
release inventories before proposing retries. An unavailable registry or an
unverifiable existing asset fails closed. Retries preserve the original tag's
source identity; they never move a published version to new source.

An npm post-publish smoke can install within seconds of the registry indexing a
new version and receive HTTP 404 for its tarball. In 0.16.0 both npm tarballs
served about four minutes after indexing. Wait until the tarball serves, then
rerun only the failed jobs with `gh run rerun <run-id> --failed`; that repeats
the smoke and durable-evidence jobs, not publication.

proxy.golang.org can fetch a pushed `jacsgo/vVERSION` tag before its workflow
finishes, and sum.golang.org then records that module hash permanently. Re-point
an unreleased Go tag only to a commit with an identical `jacsgo/` tree and root
`LICENSE`; otherwise, release a new version.

| Surface | Tag |
|---|---|
| All released Rust crates | `crate/v0.16.1` |
| CLI binaries | `cli/v0.16.1` |
| Native npm | `npm/v0.16.1` |
| Python | `pypi/v0.16.1` |
| Go module/native libraries | `jacsgo/v0.16.1` |
| Browser npm | `wasm-v0.16.1` |

A source build is not a published release. Check workflow completion, exact
registry bytes and provenance before describing 0.16.1 as shipped. Mobile
XCFramework/AAR builds remain separate from app-store/Maven/Swift repository
publication and physical-device acceptance. Actual HAI deployment is separate
from source compatibility qualification.
