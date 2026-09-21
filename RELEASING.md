# Releasing JACS

The coordinated candidate is **0.15.0**. It has not been published. MCP is the
primary documented integration; Rust, Node, Python, Go and browser packages all
remain supported release surfaces. Existing registry versions are recorded in
[release status](docs/release-status.md), separately from source versions.

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
**Do not bump again for this release: the source is already 0.15.0.**

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

The new `@hai.ai/jacs-wasm` package does not yet exist. npm requires an existing
package before a trusted publisher can be registered. Its first release still
runs entirely through CI:

1. Create a short-lived npm granular token with write access to create packages
   in `@hai.ai` and the CI 2FA bypass permission. Store it as the GitHub `npm`
   environment secret **`NPM_WASM_BOOTSTRAP_TOKEN`**; do not put it in Git or chat.
2. Set the `npm` environment variable **`JACS_NPM_WASM_BOOTSTRAP=true`**.
3. Run the normal WASM release command below. The workflow requires the package
   itself to return authoritative HTTP 404, runs all candidate/browser gates,
   and publishes the exact tarball with provenance. Existing packages cannot
   use this bootstrap mode.
4. After the first successful publication, configure its trusted publisher with
   the same organization/repository/environment and **`release-wasm.yml`**:

   ```sh
   npm trust github @hai.ai/jacs-wasm --repo HumanAssisted/JACS --file release-wasm.yml --env npm --allow-publish
   ```

5. Remove the bootstrap variable and secret, and revoke that temporary token.
   Later releases use OIDC. If publication succeeded but a later job failed,
   finish this switch before retrying the workflow.

The npm CLI refuses publisher-setting changes authenticated only by a granular
token that bypasses 2FA. Use the website or an interactive 2FA session for those
settings. See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
and [npm trust](https://docs.npmjs.com/cli/v11/commands/npm-trust/).

### Rust and Python

- **crates.io:** `release-crate.yml` publishes every entry in
  [the ordered release catalog](scripts/release_catalog.py), including WASM,
  mobile, bindings and four storage backends. Configure each crate's trusted
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

## Release 0.15.0, one step at a time

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

   All 17 candidates are prepared before the first upload; registry dependencies
   publish in catalog order. Exact archive checksums, audits, SPDX SBOMs and
   durable attested evidence remain mandatory.

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

10. Release browser npm and wait for **Release @hai.ai/jacs-wasm**:

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

| Surface | Tag |
|---|---|
| All catalogued Rust crates | `crate/v0.15.0` |
| CLI binaries | `cli/v0.15.0` |
| Native npm | `npm/v0.15.0` |
| Python | `pypi/v0.15.0` |
| Go module/native libraries | `jacsgo/v0.15.0` |
| Browser npm | `wasm-v0.15.0` |

A source build is not a published release. Check workflow completion, exact
registry bytes and provenance before describing 0.15.0 as shipped. Mobile
XCFramework/AAR builds remain separate from app-store/Maven/Swift repository
publication and physical-device acceptance. Actual HAI deployment is separate
from source compatibility qualification.
