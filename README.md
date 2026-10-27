# JACS: signed JSON for agents

JACS gives agents a persistent cryptographic identity to sign JSON and verify
messages, artifacts and identity updates. New identities use `pq2025`
(ML-DSA-87); classical algorithms require an explicit choice, with no automatic
fallback. Keep the same key across sessions; rotate it deliberately with a
signed identity transition.

**Start with MCP.** For direct service integration, jump to
[DID and post-quantum identity](docs/identity-standards.md),
[A2A](A2A_QUICKSTART.md), or [Rust, Node.js, Python and Go](docs/libraries.md).

## Quick setup

Install the CLI and start the local MCP server:

```sh
cargo install jacs-cli --locked
jacs mcp
```

For clients that use `mcpServers`, add:

```json
{
  "mcpServers": {
    "jacs": { "command": "jacs", "args": ["mcp"] }
  }
}
```

The default server exposes `jacs_verify_document` over stdio. Verification uses
an independently trusted public key; check the returned `valid` field.
A valid signature establishes integrity under that key, not permission to act.
See [client setup and local signing](docs/mcp-quickstart.md),
[MCP use cases](USECASES.md), and the [tool contract](jacs-mcp/README.md).

To create an encrypted identity and sign locally from a terminal:

```sh
mkdir -m 700 .jacs
jacs create --output .jacs/agent.json > public-identity.json
printf '%s' '{"message":"hello"}' | jacs sign --agent .jacs/agent.json --input - > signed.json
jacs verify --public-identity public-identity.json --input signed.json
```

The CLI prompts for a password. Local MCP signing is an explicit opt-in:
`jacs mcp --profile local-sign --agent .jacs/agent.json`.
Passwords belong in the terminal or the host's secret manager, never command
arguments or MCP tool parameters. See the [CLI guide](jacs-cli/README.md).

## DID, A2A and direct libraries

[DID and identity standards](docs/identity-standards.md) explains how the native
signing key appears in `did:wba`, JWK/JWKS and signed Agent Cards, including
ML-DSA-87 support and explicit ES256 compatibility. These integrations belong
to the native library workspace; the portable MCP server has no DID resolver
or A2A transport. The [A2A quickstart](A2A_QUICKSTART.md) covers discovery,
signed artifacts, explicit A2A 1.0 Node/Python APIs and current SDK examples.

| Integration | Install / guide |
| --- | --- |
| Native Rust | `jacs = "=0.15.0"`; [library guide](archive/native/jacs/docs/jacsbook/src/rust/library.md) |
| Node.js | `npm install --save-exact @hai.ai/jacs@0.15.0` |
| Python | `python -m pip install jacs==0.15.0` |
| Go | [CGo and native library setup](archive/native/jacsgo/README.md) |
| Browser | [WASM package and encrypted storage](jacs-wasm/README.md) |
| Extended CLI / MCP | `cargo install jacs-cli-compat --locked`; executable `jacs-compat`; [profiles](docs/native-mcp.md) |

Native packages remain supported in the separate
[`archive/native`](archive/native/README.md) workspace. Its directory name does
not retire those APIs. See [all packages and platform coverage](docs/libraries.md)
and [examples](examples/README.md).

**Published packages and this checkout differ.** Version 0.15.0 has a recorded
[release inventory](docs/release-status.md). New identity-standards behavior in
this checkout is source work, not evidence of a new registry release; use the
[source integration guide](docs/identity-standards.md) for those changes.

## Build from source

```sh
cargo build --locked -p jacs-cli
cargo run --locked -p jacs-cli -- mcp
cargo run --locked -p jacs-core --example portable_quickstart
cargo test --locked --workspace
```

The active workspace is `jacs-core`, `jacs-wasm`, `jacs-mobile`, `jacs-mcp` and
`jacs-cli`. Native Node/Python/Go builds use `make build-jacsnpm`,
`make build-jacspy` and `make build-jacsgo`; `make test-bindings` tests installed
consumers. See [developer commands](docs/developer-commands.md),
[shared Rust cache setup](docs/rust-cache.md), [development](DEVELOPMENT.md)
and [releases](RELEASING.md).

Private keys remain encrypted at rest and software-held while signing.
Hardware-backed custody does not imply hardware ML-DSA signing. Native private
file operations enforce Unix owner-only permissions and fail closed where the
required ACL adapter is unavailable. See [security](SECURITY.md) and the
[platform custody guide](jacs-mobile/README.md).
