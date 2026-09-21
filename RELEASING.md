# Releasing the portable primitive

This change is source work, not a published release. The historical publication record is retained in `archive/native/release/shipped-artifacts.json`; the active matrix describes only the portable surfaces. Assign a fresh coordinated version before releasing these incompatible CLI/MCP/API changes. Never overwrite an existing registry version or treat an existing legacy artifact as this candidate.

The active Rust publication order is `jacs-core`, `jacs-mcp`, `jacs-cli`. `jacs-wasm` is packaged as `@jacs/wasm`; `jacs-mobile` remains `publish=false` and produces Android AAR/Maven and iOS XCFramework/SwiftPM bundles. Archived native/binding/backend crates are all `publish=false`; their historical workflows are inert under `archive/native/.github/workflows`.

Run `make check` and `make test`, then the browser and mobile workflow gates. A release must pass the full active source suite, dependency/license audits, full-history secret scan and package consumer checks. Rust releases build the complete three-crate candidate set before uploading, verify registry archive digests, produce SPDX SBOMs and attest durable evidence. CLI releases smoke the exact staged binary, preserve license/notices, verify checksums and attest every public release asset. WASM releases retain browser tests and npm provenance. Do not bypass these gates to reuse an already published version.

Use `scripts/release_retry.py` to plan release/retry actions without writes. Tag conventions remain `crate/vVERSION`, `cli/vVERSION`, and `wasm-vVERSION`; execution is explicit. The protected `crates-io` environment supports OIDC trusted publishing; the existing credential migration fallback applies only until its maintainers enable trusted publishers. No archive publication, tap sync, PyPI, native npm binding or Go release runs from the active workflows.

Mobile CI artifacts are review candidates. Distribution to an app store, Maven registry or Swift package repository, actual HAI API deployment and mobile app integration are separate authorized steps. Physical-device biometrics and enrollment/lifecycle behavior remain release acceptance requirements beyond emulator/simulator results.

## Make commands

`make versions` (or `make version`) displays and checks all five active Cargo
package versions, the `@jacs/wasm` npm template and the MCP contract against the
release matrix's source version. `make check-versions` performs the same checks
without the listing. Both commands fail on a mismatch. Archived packages retain
their historical versions and are not required to match this release; these
offline checks do not claim that the source versions have been published.

Choose one bump size. Preview it first; the preview validates all version edits
without changing files:

| Change | Preview | Apply |
|---|---|---|
| Patch (`0.14.0` → `0.14.1`) | `make plan-bump-patch` | `make bump-patch` |
| Minor (`0.14.0` → `0.15.0`) | `make plan-bump-minor` | `make bump-minor` |
| Major (`0.14.0` → `1.0.0`) | `make plan-bump-major` | `make bump-major` |

Skip the bump if the intended unpublished version is already prepared. Bumps
update the five portable packages together using `scripts/bump-version.sh`;
the release matrix's source version follows the bump, while recorded registry
versions and publication evidence stay unchanged. Bumps do not create tags or
publish packages. Review the diff and release notes,
regenerate notices with `make third-party-notices`, and complete the gates above.
Commit the candidate before running a release target, which requires a clean
worktree including untracked files.

| Surface | Preview | Start publication |
|---|---|---|
| `jacs-core`, `jacs-mcp`, `jacs-cli` | `make plan-release-jacs` | `make release-jacs` |
| CLI binaries | `make plan-release-cli` | `make release-cli` |
| npm `@jacs/wasm` | `make plan-release-jacs-wasm` | `make release-jacs-wasm` |
| All three active surfaces | `make plan-release-everything` | `make release-everything` |

Release targets run `make release-preflight`, then use the checked helper to
create/push the version tags and start GitHub Actions. Wait for the workflows,
registry checks and provenance verification before recording a release as
published. These commands do not configure registry credentials or bootstrap a
previously unpublished npm package. Archived native npm/Python/Go packages and
the `jacs-wasm` crates.io package remain outside this release set.

For a failed publication, inspect `make plan-retry-jacs`, `make plan-retry-cli`,
`make plan-retry-jacs-wasm`, or `make plan-retry-everything`. The corresponding
`make retry-*` target executes the retry using the original tag identity; it
does not move an existing version to new source. `retry-everything` checks
registry evidence and retries only incomplete surfaces. Retry commands still
validate source version alignment, but allow unrelated worktree changes because
the original tag determines the source being retried.

## Trusted-publishing migration

Configure the three crates.io trusted publishers for `.github/workflows/release-crate.yml` and the protected `crates-io` environment. Set `CRATES_IO_TRUSTED_PUBLISHING_ENABLED=true` only after verifying those publishers. The `CRATES_IO_TOKEN` secret is a temporary migration fallback; after a successful OIDC release, revoke the old crates.io API token and remove the secret. Keep the immutable workflow references and existing `npm@11.18.0` OIDC/provenance requirements in `.github/workflows/release-wasm.yml`. See the archived release guide for historical package publisher configuration; it does not authorize publishing archived code.
