# Development and releases

From a checkout, `make help` lists the main build and test entry points.
Use `make check` for dependency boundaries, source version alignment, licensing,
notices, release policy and script tests. `make test-all` exercises the portable
workspace; native compatibility suites remain explicit.

`make build-wasm` creates the browser package; `make test-wasm` runs headless
Chrome tests. `make build-jacsbook` builds this guide and the preserved native
reference. See the [developer command reference](https://github.com/HumanAssisted/JACS/blob/main/docs/developer-commands.md)
for prerequisites, native tests and maintenance commands.

All 17 Rust crates and all language packages use one source version.
`make release-everything` triggers six publishing workflows. Run
`make verify-shipped-release` after recording actual published artifacts.
Homebrew formula preparation verifies the CLI assets' checksums and source-bound
attestations; tap synchronization is a separate workflow.

See the [release guide](https://github.com/HumanAssisted/JACS/blob/main/RELEASING.md).
