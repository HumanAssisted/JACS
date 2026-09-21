# Repository restoration audit — 2026-09-21

This compares the tree before the September 17 cleanup
(`2608f3dda9ef6d0f8c03c13a43ff6978b942fee0`, parent of `51903ce9`)
with release candidate `1f9c3d5ff9b958308475770681b12466ad47d406`.
It distinguishes missing entry points from source that still exists elsewhere.
This is a source inventory, not a claim that every archived test or command works.

## Restored in this follow-up

### Prepared after the 0.15.0 publication

The post-publication follow-up restores root browser/doc build commands, native
test and maintenance entry points, a separate `mcp-compat` launcher, an
attestation-verified Homebrew formula generator, Homebrew install CI, and a
Pages build/deploy workflow. See the [developer commands](developer-commands.md)
and [native MCP profiles](native-mcp.md). Homebrew tap publication and Pages
deployment are prepared operations, not claims that those destinations changed.

Native MCP is documented by its actual 1/9/14-tool runtime profiles. The remaining
compiled tools still require their authorization implementation; this follow-up
does not treat the 42-name contract as a runtime grant. The comparison tables
below retain the historical release-candidate inventory.

### Restored before publication

The root [`sloc.sh`](../sloc.sh) is restored byte-for-byte from its original
version, which was moved unchanged to `archive/native/sloc.sh` by `51903ce9`.
Run `./sloc.sh` from the repository root with `tokei` installed. It prints the
Rust, Go, TypeScript, TSX and Python counts and writes `LINES_OF_CODE.md`, as
before. The report covers the whole checkout, including the native workspace;
it is not a count of only the five portable crates or of unique shared source.

The five public Python A2A fixture copies are also restored to
`archive/native/jacspy/tests/fixtures/a2a_contract/`. Each matches its original
pre-cleanup Python fixture and the retained canonical Rust fixture byte-for-byte.
This repairs the paths used by the existing Python contract tests.

## What happened to the files

At the release candidate, 1,775 pre-cleanup paths were absent from their original
locations. Of these, 1,629 still existed at the corresponding
`archive/native/<old-path>` location. These counts precede this restoration.

The other 146 paths need more careful interpretation:

- 19 have identical Git blob contents elsewhere, including shared public keys,
  A2A fixtures and empty placeholder files. A matching empty file does not mean
  the old directory layout is still available.
- 127 no longer have their old blob contents anywhere in the current tree:
  120 native test fixture files, six Node/Python example key files, and
  `jacs/jacs.config.json`. The fixture set includes private test keys, generated
  signed documents, public-key metadata and encrypted data. These should not all
  be treated as lost application source or restored indiscriminately.

The broad change was made by `51903ce9`, titled “Trim JACS to portable keys;
remove raw test keys and preserve public compatibility vectors,” merged in
PR #189. The later release restoration (`c10ac650` and `1f9c3d5f`) restored
coordinated package builds and publishing, but did not restore every old
developer command, automation workflow or public interface.

## Remaining differences with practical impact

| Area | Current state |
|---|---|
| Homebrew | `homebrew.yml`, `release-homebrew.yml`, both `Formula/*.rb` files and `scripts/homebrew_release.py` survive under `archive/native`, but are absent from their active root locations. Homebrew testing and formula publication are not included in the restored release command. |
| Documentation site | `.github/workflows/static.yml` survives only in the archive. It used to build the mdBook and deploy GitHub Pages. The documentation source remains at `archive/native/jacs/docs/jacsbook`; the root deployment workflow and `build-jacsbook` / `build-jacsbook-pdf` targets are missing. This does not establish whether an older deployed site is still available. |
| Browser developer commands | `make build-wasm` and `make test-wasm` are missing. Browser build/test/release CI exists. `make test-jacs-wasm` runs the Rust `native_sanity` test and is not a replacement for the old headless-browser command. |
| Native test commands | Old fast, PQ, storage, cross-language, feature, observability and secure-fetch targets are missing from the root Makefile. Their native source/tests mostly remain archived. Current `test-bindings` and language-specific targets verify installed candidates; `test-all` only tests the portable Cargo workspace. These are not the entire former native test matrix. |
| Python A2A fixture copies | Five public JSON copies were absent from `archive/native/jacspy/tests/fixtures/a2a_contract/` at the release candidate, while `test_a2a_contract.py` still opened that directory. They are restored in this follow-up from identical canonical Rust fixtures. |
| Developer utilities | Root Make shortcuts for schema sync, cross-language fixture generation, changelog sealing, verifier smoke checks, Git-hook installation and disk maintenance are missing. Several underlying scripts remain, including `scripts/seal-changelog.sh`; the old Make recipes remain in `archive/native/Makefile` and use the former layout. |
| Public MCP/CLI surface | The portable MCP contract lists 7 tools; the native compatibility contract lists 42. Agreement, A2A, trust-store, search, media, attestation and W3C tools are retained in compatibility source, but are not part of the current public `jacs mcp` contract. The default portable MCP profile is verify-only. The broader compatibility CLI is named `jacs-compat`. Publishing its source does not make those tools available through the portable CLI. |
| Root guides and examples | `A2A_QUICKSTART.md`, `USECASES.md`, `SCHEMA_CONSOLIDATION_TODO.md`, `docker-compose.test.yml` and the former root examples survive under `archive/native`. Their original root entry points are missing. |

## Exact public MCP contract difference

The native contract contains 42 tool names. Five are retained by name in the
portable contract: `jacs_create_agent`, `jacs_sign_document`,
`jacs_verify_document`, `jacs_rotate_keys` and `jacs_reencrypt_key`. This is a
name comparison, not a claim of identical input/output contracts.

The portable contract adds `jacs_import_encrypted_agent` and
`jacs_export_encrypted_agent`, for seven names in total. Its default
`verify-only` profile exposes just `jacs_verify_document`; `local-sign` exposes
all seven. Encrypted-agent export is not the same tool as public-agent JSON export.

These 37 old names are absent from the portable contract:

| Capability | Tool names |
|---|---|
| Agreements (10) | `jacs_create_agreement`, `jacs_sign_agreement`, `jacs_check_agreement`, `jacs_create_agreement_v2`, `jacs_apply_agreement_v2`, `jacs_sign_agreement_v2`, `jacs_verify_agreement_v2`, `jacs_detect_agreement_v2_branch_conflict`, `jacs_merge_agreement_v2_transcript_branches`, `jacs_resolve_agreement_v2_branch_conflict` |
| A2A and discovery (5) | `jacs_assess_a2a_agent`, `jacs_export_agent_card`, `jacs_generate_well_known`, `jacs_verify_a2a_artifact`, `jacs_wrap_a2a_artifact` |
| Trust store (5) | `jacs_get_trusted_agent`, `jacs_is_trusted`, `jacs_list_trusted_agents`, `jacs_trust_agent`, `jacs_untrust_agent` |
| Text and images (5) | `jacs_sign_text`, `jacs_verify_text`, `jacs_sign_image`, `jacs_verify_image`, `jacs_extract_media_signature` |
| Attestation (4) | `jacs_attest_create`, `jacs_attest_verify`, `jacs_attest_lift`, `jacs_attest_export_dsse` |
| W3C (6) | `jacs_w3c_export_agent_description`, `jacs_w3c_export_did`, `jacs_w3c_export_did_document`, `jacs_w3c_generate_well_known`, `jacs_w3c_sign_request`, `jacs_w3c_verify_request` |
| Search and public-agent export (2) | `jacs_search`, `jacs_export_agent` |

Sources: [`jacs-mcp/contract/jacs-mcp-contract.json`](../jacs-mcp/contract/jacs-mcp-contract.json)
and the [native compatibility contract](../archive/native/jacs-mcp/contract/jacs-mcp-contract.json).
The latter's runtime exposure still depends on compiled features, the selected
MCP profile and its authorization rules; the inventory is not a promise that
every tool is exposed in every profile.

## Native client libraries retain their broader APIs

The portable MCP tool list is not the API inventory for the native libraries.
The Node and Python clients, their MCP adapters and Rust bindings, the Go
document, agreement, media and W3C wrappers, and both binding-core wrappers
retain their pre-cleanup source unchanged. The native media implementation also
remains unchanged. Text and image signing, image signature extraction, trust,
A2A and agreements therefore still have native client entry points; attestation
is enabled in the Node, Python and Go release builds. Individual language
wrappers have their own exposure and feature rules, so this does not claim that
all 42 MCP tools are methods in every client.

Native Rust email signing and PNG logo steganography remain in
[`jacs/src/email`](../archive/native/jacs/src/email/). The native compatibility
MCP implementation remains in
[`jacs-mcp`](../archive/native/jacs-mcp/); applications that embed it do not
automatically switch to the seven-tool portable server. Browser WASM has a
separate portable API and does not provide all native filesystem or transport
features.

## Restored or consolidated already

- Node, Python and Go builds and installed-package checks are available through
  the root Makefile and `native-bindings.yml`.
- Rust, CLI, Python, native npm, Go and browser npm releases are enabled through
  their root workflows and `make release-everything`.
- All 17 Rust crates, including storage backends, are in the coordinated release
  catalog. The old separate storage release workflow/Make target is absent, but
  storage publication is included in the main Rust release.
- Version listing and patch/minor/major bumps coordinate the full release.
  The old per-package `check-version-*` commands were not restored; `versions`
  and `check-versions` cover the coordinated source versions.
- Separate Node/Python/Go CI filenames were consolidated into
  `native-bindings.yml`; portable/native MCP checks run in `rust.yml`.
  This is not evidence that every old test invocation has an equivalent gate.
- The local `publish-*` Make commands were not restored. The current release
  flow publishes through GitHub Actions, as requested.
- Public compatibility vectors are retained in `tests/fixtures/native_compat`
  and the separate native workspace. Private test keys are not restored here.

## Old root Make targets still absent

These are the 68 old target names absent at the release candidate. This list
includes commands with replacements or consolidated behavior described above;
it is not a list of 68 unavailable capabilities.

```text
audit-jacs
build-jacs
build-jacsbook
build-jacsbook-pdf
build-wasm
check-changelog-sealed
check-version-cli
check-version-jacs
check-version-jacsgo
check-version-jacsnpm
check-version-jacspy
check-version-wasm
disk-clean-deep
disk-clean-light
disk-sweep
disk-usage
install-disk-tools
install-githooks
plan-release-jacs-storage
publish-jacs
publish-jacs-binding-core
publish-jacs-cli
publish-jacs-core
publish-jacs-dry
publish-jacs-duckdb
publish-jacs-mcp
publish-jacs-media
publish-jacs-postgresql
publish-jacs-redb
publish-jacs-storage
publish-jacs-storage-dry
publish-jacs-surrealdb
publish-jacs-wasm
publish-jacsnpm
publish-jacsnpm-dry
publish-jacspy
publish-jacspy-dry
regen-cross-lang-fixtures
release-delete-tags
release-jacs-storage
seal-changelog
smoke-verifiers
sync-schemas
test-all-pq
test-bindings-fast
test-jacs
test-jacs-binding-core
test-jacs-binding-core-pq
test-jacs-cross-language
test-jacs-duckdb
test-jacs-fast
test-jacs-fast-bin-shard-a
test-jacs-fast-bin-shard-b
test-jacs-fast-lib
test-jacs-features
test-jacs-observability
test-jacs-postgresql
test-jacs-pq
test-jacs-redb
test-jacs-secure-fetch
test-jacs-storage
test-jacs-surrealdb
test-jacsnpm-parallel
test-jacspy-parallel
test-rust-pr
test-rust-slow
test-wasm
verify-shipped-release
```

For the removal itself, inspect `git show --find-renames 51903ce9`; for the
remaining active workflow differences, use:

```sh
git diff --name-status 2608f3dd 1f9c3d5f -- .github/workflows Makefile scripts Formula
```

Native Cargo isolation does not require moving repository-wide utilities such
as `sloc.sh` out of reach, disabling documentation deployment, or leaving test
fixture paths unresolved. Those are separate follow-up issues from maintaining
the five-crate portable dependency boundary.
