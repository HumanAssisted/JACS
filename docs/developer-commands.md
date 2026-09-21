# Developer commands after the native workspace move

Run commands from the repository root. Check disk headroom and the shared Rust
cache as described in the root README before substantial builds. Native Cargo
commands select `archive/native/Cargo.toml`; they do not add native dependencies
to the five portable crates. SurrealDB retains its own Cargo workspace.

| Work | Root command | Prerequisites and scope |
|---|---|---|
| Portable CLI | `make build` or `make build-jacs` | Rust; builds without installing over a user binary |
| Native compatibility CLI | `make build-jacs-compat` | Rust; executable is `jacs-compat` |
| Native MCP | `make mcp-compat` | Verify-only unless explicit host configuration selects local signing; see [profiles](native-mcp.md) |
| Browser package | `make build-wasm` | `wasm-pack`, `wasm32-unknown-unknown`; finalizes `@hai.ai/jacs-wasm` metadata |
| Browser tests | `make test-wasm` | `wasm-pack`, Chrome and matching ChromeDriver; separate from native sanity tests |
| Documentation | `make build-jacsbook` | mdBook (CI pins 0.4.52); current guide and labelled native reference in `target/jacsbook` |
| PDF | `make build-jacsbook-pdf` | mdBook and Playwright CLI with Chromium; writes `target/jacsbook.pdf` |
| Native Rust suites | `make test-jacs-fast`, `test-jacs-pq`, `test-jacs-cross-language`, `test-jacs-observability` | Restored suite selection and explicit native paths; network/collector and language prerequisites still apply |
| Native boundary contracts | `make test-jacs-binding-core`, `test-jacs-binding-core-pq`, `test-jacs-mcp-compat`, `test-jacs-cli-compat` | Separate from the existing portable MCP/CLI targets |
| Storage | `make test-jacs-storage` or `test-jacs-duckdb`, `test-jacs-redb`, `test-jacs-postgresql`, `test-jacs-surrealdb` | Backend dependencies and any required test services |
| Broad Rust checks | `make test-rust-pr`, `test-rust-slow`, `test-all-pq` | Explicit larger suites; `test-all` continues to mean the portable workspace |
| Parallel binding tests | `make test-bindings-fast`, `test-jacspy-parallel`, `test-jacsnpm-parallel` | Prepared native bindings and each language's test dependencies |
| Installed packages | `make test-bindings` | Builds and tests fresh installed Node/Python/Go consumers |
| Dependency audit | `make audit-jacs` | `cargo-audit`; portable, native and SurrealDB lockfiles |
| Public release verification | `make verify-shipped-release` | Network, `gh`, npm and `pypi-attestations`; requires recorded registry parity and provenance |
| Portable verifier smoke | `make smoke-verifiers` | Builds the portable CLI; real PQ, tamper, MCP and encrypted-custody checks |
| Schema comparison | `make sync-schemas` | Read-only byte comparison of native and portable schema trees |
| Fixture regeneration | `make regen-cross-lang-fixtures` | Mutates canonical fixtures; review the diff and keep private key material out of commits |
| Git hooks | `make install-githooks` | Selects the existing repository hooks |
| Changelog | `make seal-changelog`, `check-changelog-sealed` | Explicit note-edit/check utilities; sealing notes is not evidence of publication |
| Disk report | `make disk-usage` | Read-only filesystem/target report; APFS shared blocks may be counted more than once |

These commands restore access to retained suites; adding a shortcut does not
establish that every optional backend or historical fixture suite has passed.
The release workflows remain the evidence for the published candidates.

Automatic disk deletion, local credential-based `publish-*` commands and tag
deletion are not restored. The shared-cache guide covers deliberate cleanup;
the CI release commands preserve candidate verification and immutable retries.
Coordinated `make check-versions` replaces per-package version checks.

## Homebrew preparation and publication

Generate a formula only for an already published CLI, with its reviewed commit:

```sh
make homebrew-formula VERSION=0.15.0 \
  SOURCE_COMMIT=10c16ba07d56b872e9c6c6ddd83a45af7bd8f94a
```

The generator verifies all 12 CLI release assets, their checksums, hosted-runner
provenance and exact source digest before writing `Formula/jacs.rb`. The formula
installs the portable `jacs` binary on macOS/Linux arm64/x86_64. CI reproduces
the formula, installs it with Homebrew and runs the real portable CLI checks.

The **Sync Homebrew Tap** workflow is a separate manual publication to
`HumanAssisted/homebrew-jacs` on `master`. It requires `HOMEBREW_TAP_TOKEN` in
the repository or `homebrew` environment. It changes only `Formula/jacs.rb`;
the SDK formula has its own release lifecycle. Preparing this PR does not
publish the formula to the tap.

## Documentation deployment

The documentation workflow builds on relevant PRs. Pages deployment runs only
from `main`, using the `github-pages` environment and a separate job with Pages
and OIDC permissions. The downloaded mdBook binary has a pinned checksum.
The current MCP-first guide is the landing page; preserved native chapters
carry a compatibility notice. A prepared workflow is not a claim of a live
site deployment.
