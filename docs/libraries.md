# Supported libraries and packages

MCP is the recommended starting point for agent/tool integration. Direct
libraries are supported integrations too. The native workspace's location at
`archive/native` keeps its dependencies separate from the portable core; it
does not deprecate the native Rust, Node.js, Python or Go packages.

JACS 0.15.0 is published across all 17 Rust crates, native npm, browser npm,
PyPI and Go. See the [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
for platform coverage, verified artifacts and provenance.

| Integration | Package / installation | Reference |
|---|---|---|
| Portable CLI and MCP | `cargo install jacs-cli --version 0.15.0 --locked` | [CLI](https://github.com/HumanAssisted/JACS/blob/main/jacs-cli/README.md), [MCP](https://github.com/HumanAssisted/JACS/blob/main/jacs-mcp/README.md) |
| Portable Rust primitives | `jacs-core = "=0.15.0"` | [Core API](https://github.com/HumanAssisted/JACS/blob/main/jacs-core/README.md) |
| Rust integration library | `jacs = "=0.15.0"`, optional `a2a`, `agreements`, `attestation` features | [Rust library](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs/docs/jacsbook/src/rust/library.md) |
| Native Node.js | `npm install --save-exact @hai.ai/jacs@0.15.0` | [Node guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsnpm/README.md) |
| Python | `python -m pip install jacs==0.15.0` | [Python guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacspy/README.md) |
| Go with CGo | `github.com/HumanAssisted/JACS/jacsgo@v0.15.0`, plus its matching native library | [Go installation](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsgo/README.md) |
| Browser | `npm install --save-exact @hai.ai/jacs-wasm@0.15.0` | [Browser guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-wasm/README.md) |
| Android / iOS | `jacs-mobile` plus its platform host libraries | [Mobile guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-mobile/README.md) |
| Extended Rust CLI and MCP | `cargo install jacs-cli-compat --version 0.15.0 --locked`; executable `jacs-compat` | [Extended MCP profiles](https://github.com/HumanAssisted/JACS/blob/main/docs/native-mcp.md) |
| Storage | `jacs-duckdb`, `jacs-redb`, `jacs-postgresql`, `jacs-surrealdb`, all 0.15.0 | [Storage guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs/docs/jacsbook/src/advanced/storage.md) |

`jacs-media` and `jacs-binding-core` remain the shared native media/binding
layers. `jacs-mcp` and `jacs-mcp-compat` are distinct server libraries. The
published `jacsnpm`, `jacspy` and `jacsgo` Rust crates implement their language
boundaries; application users normally install their npm/PyPI/Go packages.

## Choose by capability

The portable core, browser and mobile libraries cover cryptography and
encrypted identity lifecycle. They do not include native filesystem, email,
database or network integrations. Native libraries retain JSON/files,
Agreement v2, A2A, trust, text/media, attestation and transport helpers, with
package-specific feature gates. Check the relevant language API before
assuming a native Rust method is exposed by every wrapper.

Node and Python ship native binaries for the platforms in the release
inventory. Go requires CGo, a C toolchain and the matching shared library at
build and runtime. Mobile bundle assembly and physical-device acceptance are
separate from publishing the `jacs-mobile` Rust crate.

## Build and validate from source

The root commands remain supported:

```sh
make build-jacsnpm
make build-jacspy
make build-jacsgo
make test-bindings
```

They select the separate native workspace and test installed consumers.
See the [developer commands](https://github.com/HumanAssisted/JACS/blob/main/docs/developer-commands.md)
for broader native test suites and the
[example index](https://github.com/HumanAssisted/JACS/blob/main/examples/README.md)
for integration examples. Historical reference chapters can contain earlier
package names or CLI commands; current extended CLI examples use `jacs-compat`.
