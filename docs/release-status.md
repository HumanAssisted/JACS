# Release status

The release inventory was observed
2026-09-20 against source version 0.15.0.

Source version **0.15.0 is unreleased**. The coordinated release includes all 17
Rust crates, CLI binaries, native npm, Python, Go and browser npm. MCP remains
the primary documented integration; native compatibility packages remain in
their separate Cargo workspace.

Observed registry versions are older source: main Rust/CLI, Python and Go
0.13.0; native npm 0.10.1; no `@hai.ai/jacs-wasm` publication. Some storage crates
have their own older versions. The per-crate observations in
[`release/shipped-artifacts.json`](../release/shipped-artifacts.json) distinguish
every package from the coordinated source candidate. Existing registry bytes
are not evidence that 0.15.0 has shipped.

<!-- BEGIN GENERATED SHIPPED ARTIFACT MATRIX -->
| Surface | Shipped version/status | Prebuilt targets | CI/runtime evidence and limits |
|---|---|---|---|
| Rust (17 portable and native crates) | crates.io `0.13.0`; historical version observed candidate unreleased | portable Rust and isolated native compatibility crates; storage backends | All 17 catalogued crates are coordinated at source 0.15.0 and enabled for CI publication. Per-crate registry observations describe older or absent releases; no 0.15.0 publication is claimed. Exact archives, checksums, audits, SPDX and provenance are required. |
| CLI (`jacs-cli`) | crates.io and GitHub Releases `0.13.0`; historical version observed candidate unreleased | source build; no trimmed prebuilt artifact recorded | The thin CLI delegates key creation, signing, verification, rotation and re-encryption to the portable core. No historical native CLI download is claimed to contain the trimmed implementation. Release assets still require exact inventories, SHA-256 digests and attestations. |
| Node.js (`@hai.ai/jacs`) | npm `0.10.1`; historical version observed candidate unreleased | native Node.js; release matrix qualifies macOS and Linux addons | Native npm builds and publication are restored from the isolated compatibility workspace. The 0.15.0 candidate retains the native API over portable core; no registry publication is claimed. Exact packed-artifact runtime checks, audits, SPDX and provenance remain required. |
| Python (`jacs`) | PyPI `0.13.0`; historical version observed candidate unreleased | macOS, Linux and Windows wheel matrix; source distribution | Python wheels and source distribution are restored from the native compatibility workspace at 0.15.0. CI qualifies exact installed candidates and source archives before publishing, then verifies PEP 740 provenance. |
| Go (`github.com/HumanAssisted/JACS/jacsgo`) | Go module proxy and GitHub Releases `0.13.0`; historical version observed candidate unreleased | macOS arm64/amd64; Linux arm64/amd64 | The public jacsgo module path and native library release are restored at source 0.15.0. Staged consumer checks, library checksums, SPDX and GitHub attestations precede recorded publication. |
| Browser (`@hai.ai/jacs-wasm`) | npm unpublished; source only not published | browser source build; release package unavailable | Browser source and cross-runtime crypto checks are available. No npm publication or installed-browser compatibility is implied by source validation; publication retains npm integrity, provenance and post-publish checks. |
<!-- END GENERATED SHIPPED ARTIFACT MATRIX -->

The release catalog includes portable crates, native compatibility crates,
language binding crates and storage backends. All are enabled for CI publishing.
The extended MCP/CLI crates use `jacs-mcp-compat` and `jacs-cli-compat` to preserve
the active portable identities. Mobile Rust publication is enabled; mobile
bundle delivery and app/device acceptance are separate.

`make versions` checks source alignment across the full catalog.
`scripts/check-release-matrix.py --online` verifies registry observations;
`--require-parity` requires every release surface and crate to match source.
After publication, update observed versions and statuses only with actual
registry and provenance evidence, then regenerate this table with `--write-docs`.
The scheduled readiness workflow checks recorded npm/PyPI provenance and exact
attested CLI/Go inventories.

See [the release guide](../RELEASING.md) for registry setup, individual Make
commands and immutable-tag retry behavior. Historical release evidence remains
in [the original inventory](../archive/native/release/shipped-artifacts.json).
