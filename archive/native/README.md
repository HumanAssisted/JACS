# JACS native libraries and integrations

This supported workspace provides native Rust, Python, Node.js and Go APIs,
storage backends, and the extended CLI/MCP integration. Its directory name does
not deprecate these packages. It stays outside the five-crate portable workspace;
shared cryptography and canonical JSON live in `jacs-core`.

MCP is the primary integration. Start with the
[current MCP guide](https://github.com/HumanAssisted/JACS/blob/main/docs/mcp-quickstart.md) for the portable `jacs` binary,
or [extended profiles](https://github.com/HumanAssisted/JACS/blob/main/docs/native-mcp.md) for the native surface.

## Install

| Surface | Package / guide |
| --- | --- |
| Native Rust | `cargo add jacs@=0.15.0`; [API and examples](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs/README.md) |
| Python | `python -m pip install jacs==0.15.0`; [Python guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacspy/README.md) |
| Node.js | `npm install --save-exact @hai.ai/jacs@0.15.0`; [Node guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsnpm/README.md) |
| Go | [Module and matching CGo library setup](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsgo/README.md) |
| Extended CLI and MCP | `cargo install jacs-cli-compat --locked`; [CLI](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-cli/README.md), [MCP](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-mcp/README.md) |
| Browser | Published `@hai.ai/jacs-wasm`; [browser guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-wasm/README.md) |

The native CLI executable is `jacs-compat`:

```bash
cargo install jacs-cli-compat --locked
jacs-compat quickstart --name my-agent --domain my-agent.example.com
jacs-compat mcp
```

MCP defaults to verification-only. Local signing is explicit:
`jacs-compat mcp --profile local-sign --config /absolute/path/to/jacs.config.json`.
Passwords belong in a prompt or host secret source, never in command arguments
or MCP tool parameters. See the profile guide before enabling file tools.

## Capabilities and trust

Native APIs cover persistent identities, signed JSON/files, inline text, images,
Rust email, agreements, attestations, DNS, A2A and framework adapters. New
identities default to `pq2025` (ML-DSA-87), without classical fallback. Existing
Ed25519 identities can rotate in place or explicitly upgrade; PQ-to-Ed25519
rotation is rejected.

The current [identity standards guide](https://github.com/HumanAssisted/JACS/blob/main/docs/identity-standards.md) covers
native ML-DSA-87 DID/JWK/Agent Card exports and explicit ES256 compatibility.
Those new standards changes are source work, not a new published release.
Discovery and mathematical signature validity do not establish identity,
consent, policy acceptance or permission to act; callers supply trusted keys
and application policy.

## Storage packages

- [DuckDB](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-duckdb/README.md): embedded SQL storage.
- [PostgreSQL](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-postgresql/README.md): database storage with full-text search.
- [Redb](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-redb/README.md): embedded key/value storage.
- [SurrealDB](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-surrealdb/README.md): embedded in-memory backend.

Current source pins SurrealDB 3.3.4 and carries unpublished dependency backports.
See [source backports and release blockers](https://github.com/HumanAssisted/JACS/blob/main/archive/native/SECURITY_AUDIT.md#source-backports-and-release-blockers-after-the-2026-10-27-updates).
Repository patches are not published fixes for downstream crates.io consumers.

## Build and release

From the repository root, use `make build-jacspy`, `make build-jacsnpm`, or
`make build-jacsgo`. Rust builds select `--manifest-path archive/native/Cargo.toml`.
This checkout requires Rust 1.97 or newer. See the [developer guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md)
and [shared cache setup](https://github.com/HumanAssisted/JACS/blob/main/docs/rust-cache.md) before substantial builds.

The [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md) records verified 0.15.0
artifacts across all 17 Rust crates and all language packages. Later source
changes need separate release evidence. The [root release guide](https://github.com/HumanAssisted/JACS/blob/main/RELEASING.md)
coordinates versions and publication order across both workspaces. SurrealDB
and the unpublished observability example retain separate lockfiles.

Report vulnerabilities to security@hai.ai. See [security](https://github.com/HumanAssisted/JACS/blob/main/SECURITY.md).

Apache-2.0. [License](https://github.com/HumanAssisted/JACS/blob/main/archive/native/LICENSE-APACHE) · [Third-party notices](https://github.com/HumanAssisted/JACS/blob/main/archive/native/THIRD-PARTY-NOTICES).
