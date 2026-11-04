# Release status

The release inventory was observed
2026-11-04 against source version 0.16.0.

This inventory describes those recorded release artifacts, not every subsequent
change in this repository. Source changes after the recorded release commits
require a separate release record.

Source version **0.16.0 is published and verified** across 16 of the 17 Rust
crates, CLI binaries, native npm, Python, Go and WASM npm. The
[verification record](../release/0.16.0-verification.json) records exact public
artifacts, checksums, provenance, installed-consumer checks and the three release
commits, which differ only in two CI workflow files. The SurrealDB backend's lock
contains source-only jsonwebtoken and object_store backports, which are not
published fixes available to downstream crates.io consumers. The
[release process](../RELEASING.md) rejects unpublished third-party dependencies
during candidate preparation, packaging and publication, so `jacs-surrealdb` was
held from 0.16.0 and remains at 0.15.0; use it only with `jacs` 0.15. See the
[source backports and release blockers](../archive/native/SECURITY_AUDIT.md#source-backports-and-release-blockers-after-the-2026-10-27-updates)
for the current dependency status.

`@hai.ai/jacs-wasm` 0.16.0 is the package's first publication through its npm
trusted publisher; the 0.15.0 bootstrap credential is removed from CI, and the
record tracks its revocation. MCP remains the primary documented integration;
native compatibility packages retain their separate workspace.

The per-crate observations in
[`release/shipped-artifacts.json`](../release/shipped-artifacts.json) distinguish
every published package from the coordinated source version. Source validation
alone does not establish publication. The SDK's 13 envelope and media tests
also pass against the published 0.16.0 crates.io packages, with no path or Git
override (`sdk_registry_compatibility` in the
[verification record](../release/0.16.0-verification.json)).

<!-- BEGIN GENERATED SHIPPED ARTIFACT MATRIX -->
| Surface | Shipped version/status | Prebuilt targets | CI/runtime evidence and limits |
|---|---|---|---|
| Rust (17 portable and native crates) | crates.io `0.16.0`; published verified; except `jacs-surrealdb` held at `0.15.0` | portable Rust and isolated native compatibility crates; storage backends | All 16 published registry archives, downloaded and hashed, match their crates.io checksums and the source-bound attested candidate manifest. The manifest and both SPDX inventories pass hosted GitHub attestation verification. A clean registry consumer passes in CI. Publication used the crates.io token fallback, not trusted publishing. |
| CLI (`jacs-cli`) | crates.io and GitHub Releases `0.16.0`; published verified | macOS arm64; macOS x86_64; Linux x86_64 glibc; Linux arm64 glibc; Windows x86_64 | All 12 public assets (five archives, their checksum files, the manifest and SPDX inventory) pass exact-inventory, checksum and hosted GitHub attestation verification. The published macOS arm64 binary passes PQ signing/verification, tamper rejection, custody, re-encryption, rotation and verify-only MCP tests. |
| Node.js (`@hai.ai/jacs`) | npm `0.16.0`; published verified | macOS arm64/x86_64; Linux arm64/x86_64 glibc; Linux x86_64 musl | The exact registry tarball matches its source-bound attested SHA-256 candidate checksum and was published through npm trusted publishing with SLSA provenance. Registry signature/provenance audit, CJS/ESM loading, CommonJS PQ signing with tamper and wrong-key rejection, public human-approval proof and CI postinstall/CLI shim checks pass; the durable SBOM is attested. No Linux arm64 musl binary ships. |
| Python (`jacs`) | PyPI `0.16.0`; published verified | macOS arm64/x86_64; Linux arm64/x86_64 glibc; Linux x86_64 musl; source distribution | Five abi3 wheels for CPython 3.11 and newer and the source distribution match the source-bound attested candidate checksums, and all six pass PEP 740 verification. Published-wheel checks pass on Python 3.11–3.14; fresh macOS PQ signing, tamper rejection and human-approval proof checks pass. |
| Go (`github.com/HumanAssisted/JACS/jacsgo`) | Go module proxy and GitHub Releases `0.16.0`; published verified | macOS arm64/amd64; Linux arm64/amd64 | The semantic Go module tag and four native libraries are public; a direct fetch of the tag matches sum.golang.org. All 12 exact release assets pass checksum and hosted attestation verification bound to the release commit. External consumers pass on all four targets; a fresh macOS arm64 consumer also passes after moving the build tree and clearing its environment. |
| Browser (`@hai.ai/jacs-wasm`) | npm `0.16.0`; published verified | browser WASM (Chromium verified) | The registry tarball matches its source-bound attested candidate checksum. It is the package's first publication through its npm trusted publisher, with SLSA provenance. npm signature/provenance audit passes, and the registry-installed package passes PQ signing, verification and identity-transfer tamper tests in Chromium. Its durable checksum and SPDX SBOM are attested. |
<!-- END GENERATED SHIPPED ARTIFACT MATRIX -->

The release catalog includes portable crates, native compatibility crates,
language binding crates and storage backends. All except crates in `HELD_CRATES`
(for 0.16.0, jacs-surrealdb, which stays at 0.15.0) are enabled for CI publishing.
The extended MCP/CLI crates use `jacs-mcp-compat` and `jacs-cli-compat` to preserve
the active portable identities. Mobile Rust publication is enabled; mobile
bundle delivery and app/device acceptance are separate.

`make versions` checks source alignment across the full catalog.
`scripts/check-release-matrix.py --online` verifies registry observations;
`--require-parity` requires every release surface and every non-held crate to
match source; held crates keep their recorded registry version.
After publication, update observed versions and statuses only with actual
registry and provenance evidence, then regenerate this table with `--write-docs`.
The scheduled readiness workflow checks recorded npm/PyPI provenance and exact
attested CLI/Go inventories.

See [the release guide](../RELEASING.md) for registry setup, individual Make
commands and immutable-tag retry behavior. Historical release evidence remains
in [the original inventory](../archive/native/release/shipped-artifacts.json).
