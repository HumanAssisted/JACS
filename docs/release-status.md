# Release status

The release inventory was observed
2026-09-21 against source version 0.15.0.

Publication of source version **0.15.0 is in progress**. CLI binaries, native
npm, Python and Go are published and verified. Rust publication and WASM
bootstrap remain incomplete. The [verification record](../release/0.15.0-verification.json)
records exact public artifacts, checksums, provenance and installed-consumer
checks. MCP remains the primary documented integration; native compatibility
packages remain in their separate Cargo workspace.

The per-crate observations in
[`release/shipped-artifacts.json`](../release/shipped-artifacts.json) distinguish
every published package from the coordinated source version. Source validation
alone does not establish publication. The SDK also passes 13 envelope and media
tests using the actual crates.io packages without local JACS overrides.

<!-- BEGIN GENERATED SHIPPED ARTIFACT MATRIX -->
| Surface | Shipped version/status | Prebuilt targets | CI/runtime evidence and limits |
|---|---|---|---|
| Rust (17 portable and native crates) | crates.io `0.15.0`; partially published | portable Rust and isolated native compatibility crates; storage backends | 11 of 17 crates are published at 0.15.0. Remaining uploads and durable Rust evidence are still in progress after a new-crate registry throttle. Published archives must match the reviewed candidate checksums. |
| CLI (`jacs-cli`) | crates.io and GitHub Releases `0.15.0`; published verified | macOS arm64; macOS x86_64; Linux x86_64 glibc; Linux arm64 glibc; Windows x86_64 | All five CLI archives, checksum files and SPDX inventory pass exact public-asset and hosted GitHub attestation verification. The published macOS arm64 binary passes PQ signing/verification, custody, rotation and verify-only MCP tests. |
| Node.js (`@hai.ai/jacs`) | npm `0.15.0`; published verified | macOS arm64/x86_64; Linux arm64/x86_64 glibc and musl | The exact registry tarball matches its source-bound attested SHA-256 candidate checksum. Registry signatures/provenance, CJS/ESM PQ signing, tamper rejection, public exports, signing-input helpers and installed CLI checks pass; the durable SBOM is attested. |
| Python (`jacs`) | PyPI `0.15.0`; published verified | macOS arm64/x86_64; Linux arm64/x86_64 glibc; Linux x86_64 musl; source distribution | Five wheels and the source distribution match the source-bound attested candidate checksums and all six pass PEP 740 verification. Published-wheel checks pass on Python 3.10–3.14 after index propagation; fresh macOS PQ signing, tamper rejection and human-approval proof checks pass. |
| Go (`github.com/HumanAssisted/JACS/jacsgo`) | Go module proxy and GitHub Releases `0.15.0`; published verified | macOS arm64/amd64; Linux arm64/amd64 | The semantic Go module tag and four native libraries are public. All 12 exact release assets pass checksum and hosted attestation verification. External consumers pass on all four targets; a fresh macOS arm64 consumer also passes after moving the build tree and clearing its environment. |
| Browser (`@hai.ai/jacs-wasm`) | npm unpublished; source only publication blocked | browser source build; release package unavailable | Candidate browser, checksum and security gates passed, but first publication failed with npm EOTP. The bootstrap credential needs create-package write access and CI 2FA bypass; trusted publishing and credential removal follow successful publication. No npm release is claimed. |
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
