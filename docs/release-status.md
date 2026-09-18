# Portable release status

The active source scope was observed
2026-09-17 against source version 0.13.0. This is an unreleased source change,
not evidence that registries contain the trimmed implementation. A coordinated
release requires an unused version if existing registry versions contain
different immutable package bytes.

<!-- BEGIN GENERATED SHIPPED ARTIFACT MATRIX -->
| Surface | Shipped version/status | Prebuilt targets | CI/runtime evidence and limits |
|---|---|---|---|
| Rust (`jacs-core`, `jacs-mcp`, `jacs-cli`) | crates.io unpublished; source only unreleased trim | portable core; thin native CLI and MCP source | The active publication set contains only jacs-core, jacs-mcp and jacs-cli. Trimmed source has not been published; historical registry versions do not attest these new source bytes. Exact candidate checksums, SPDX and provenance gates remain required. |
| CLI (`jacs-cli`) | crates.io and GitHub Releases unpublished; source only unreleased trim | source build; no trimmed prebuilt artifact recorded | The thin CLI delegates key creation, signing, verification, rotation and re-encryption to the portable core. No historical native CLI download is claimed to contain the trimmed implementation. Release assets still require exact inventories, SHA-256 digests and attestations. |
| Browser (`@jacs/wasm`) | npm unpublished; source only not published | browser source build; release package unavailable | Browser source and cross-runtime crypto checks are available. No npm publication or installed-browser compatibility is implied by source validation; publication retains npm integrity, provenance and post-publish checks. |
<!-- END GENERATED SHIPPED ARTIFACT MATRIX -->

The active release surfaces are `crate`, `cli` and `wasm`. The coordinated crate
set is `jacs-core`, `jacs-mcp`, `jacs-cli`, published in that dependency order.
`jacs-mobile` remains a source binding crate with Android/iOS build gates; no
prebuilt mobile distribution is claimed here.

Historical Python, native Node, Go, storage and extended-native release evidence
is preserved in [the archived inventory](../archive/native/release/shipped-artifacts.json).
Those packages are not part of active release or retry plans.

`scripts/check-release-matrix.py` checks source alignment, active scope and this
generated table. `--online` performs bounded registry queries and reports drift;
it does not turn a same-number historical release into evidence for new source.
After reviewed publication, update the inventory with exact registry evidence
and use `--require-parity` to require coordinated versions.

Release safety gates still require a clean worktree, immutable tag identity,
authoritative exact-version registry responses, candidate checksum equality,
complete GitHub inventories and cryptographic attestations. Browser npm
verification installs with lifecycle scripts disabled and audits signatures.
