# JACS

**Cryptographic identity, data provenance, and trust for AI agents.**

JACS gives every AI agent a verifiable identity, signs everything it produces, and lets any other agent or system verify who said what — without a central server.

`cargo install jacs-cli` | `brew install jacs`

> For the HAI.AI platform (agent email, benchmarks, leaderboard), see [haiai](https://github.com/HumanAssisted/haiai).

  [![Rust](https://github.com/HumanAssisted/JACS/actions/workflows/rust.yml/badge.svg)](https://github.com/HumanAssisted/JACS/actions/workflows/rust.yml)
  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/HumanAssisted/JACS/blob/main/LICENSE)
  [![Crates.io](https://img.shields.io/crates/v/jacs)](https://crates.io/crates/jacs)
  [![npm](https://img.shields.io/npm/v/@hai.ai/jacs)](https://www.npmjs.com/package/@hai.ai/jacs)
  [![PyPI](https://img.shields.io/pypi/v/jacs)](https://pypi.org/project/jacs/)
  [![Rust 1.93+](https://img.shields.io/badge/rust-1.93+-DEA584.svg?logo=rust)](https://www.rust-lang.org/)
  [![Homebrew](https://github.com/HumanAssisted/JACS/actions/workflows/homebrew.yml/badge.svg)](https://github.com/HumanAssisted/JACS/actions/workflows/homebrew.yml)

## What JACS does

| Capability | What it means |
|-----------|---------------|
| **Agent Identity** | Generate a cryptographic keypair that uniquely identifies your agent. Post-quantum ready (ML-DSA-87/FIPS-204) by default. |
| **Data Provenance** | Sign any JSON document or file. Every signature is tamper-evident — anyone can verify the content hasn't been modified and who produced it. |
| **Agent Trust** | Verify other agents' identities, manage a local trust store, and establish trust policies (`open`, `verified`, `strict`) for cross-agent interactions. |

## Quick start

```bash
cargo install jacs-cli

export JACS_PRIVATE_KEY_PASSWORD='your-password'
jacs quickstart --name my-agent --domain example.com
jacs document create -f mydata.json
jacs verify signed-document.json
```

Or via Homebrew:

```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

## MCP server

JACS includes a built-in MCP server for AI tool integration (Claude Desktop, Cursor, Claude Code, etc.):

```bash
jacs mcp
```

```json
{
  "mcpServers": {
    "jacs": {
      "command": "jacs",
      "args": ["mcp"]
    }
  }
}
```

The MCP server uses **stdio transport only** — no HTTP endpoints. This is a deliberate security choice: the server holds the agent's private key, so it runs as a subprocess of your MCP client. The key never leaves the local process and no ports are opened.

**Core profile** (default) — 7 tool families: state, document, trust, audit, memory, search, key.

**Full profile** (`jacs mcp --profile full`) — adds agreements, messaging, A2A, and attestation tools.

## Core operations

| Operation | What it does |
|-----------|-------------|
| **Create** | Generate an agent identity with a cryptographic keypair |
| **Sign** | Attach a tamper-evident signature to any JSON payload or file |
| **Verify** | Prove a signed document is authentic and unmodified |
| **Export** | Share your agent's public key or signed documents with others |

## Use cases

**Local provenance** — An agent creates, signs, verifies, and exports documents locally. No server required.

**Trusted local memory** — Store agent memories, plans, configs as signed documents with searchable metadata and visibility controls (`public`/`private`/`restricted`).

**Platform workflows** — Use the same JACS identity with [haiai](https://github.com/HumanAssisted/haiai) to register with HAI.AI, send signed email, and run benchmarks.

**Multi-agent trust** — Agreements with quorum signing, A2A interoperability, attestation chains, and DNS-verified identity discovery.

## When you DON'T need JACS

- **Single developer, single service.** Standard logging is fine.
- **Internal-only prototypes.** No trust boundaries, no value in signing.
- **Simple checksums.** If you only need to detect accidental corruption, use SHA-256.

JACS adds value when data crosses trust boundaries — between organizations, between services with different operators, or into regulated audit trails.

## Features

- **Post-quantum ready** — ML-DSA-87 (FIPS-204) default, with Ed25519 and RSA-PSS.
- **Cross-language** — Sign in Rust, verify in Python or Node.js. Tested on every commit.
- **Pluggable storage** — Filesystem, SQLite, PostgreSQL, DuckDB, SurrealDB, Redb.
- **Document visibility** — `public`, `private`, or `restricted` access control.
- **Trust policies** — `open`, `verified` (default), or `strict` modes.
- **Multi-agent agreements** — Quorum signing, timeouts, algorithm requirements (feature-gated).
- **A2A interoperability** — Every JACS agent is an A2A agent with zero config (feature-gated).

## Language bindings (experimental)

The MCP server and CLI are the recommended integration paths. Native bindings exist for direct library use:

| Language | Install | Status |
|----------|---------|--------|
| Python | `pip install jacs` | Experimental |
| Node.js | `npm install @hai.ai/jacs` | Experimental |
| Go | `go get github.com/HumanAssisted/JACS/jacsgo` | Experimental |

See [DEVELOPMENT.md](DEVELOPMENT.md) for library APIs, framework adapters, and build instructions.

## Security

- **Private keys are encrypted** with password-based key derivation.
- **MCP server is stdio-only** — no network exposure.
- **260+ automated tests** covering cryptographic operations, password validation, agent lifecycle, DNS verification, and attack scenarios.
- **Post-quantum default** — ML-DSA-87 (FIPS-204) composite signatures.

Report vulnerabilities to security@hai.ai. Do not open public issues for security concerns.

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Algorithm Guide](https://humanassisted.github.io/JACS/advanced/algorithm-guide.html)
- [Use Cases](USECASES.md)
- [Development Guide](DEVELOPMENT.md)
- [HAI.AI Platform](https://hai.ai)

---

v0.9.7 | [Apache-2.0 OR MIT](./LICENSE-APACHE) | [Third-Party Notices](./THIRD-PARTY-NOTICES)
