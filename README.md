# JACS

**Open source cryptographic provenance for AI agents and the artifacts they create.**

JACS gives an agent a verifiable identity, signs the work it produces, and lets other tools, agents, or people verify who signed what without a central server.

`cargo install jacs-cli` | `brew install jacs`

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
| **Agent identity** | Generate and manage a persistent cryptographic identity for an agent. Post-quantum ready (`pq2025` / ML-DSA-87) by default. |
| **Artifact provenance** | Sign JSON, files, Markdown/text, images, and Rust email payloads so consumers can detect tampering and identify the signer. |
| **Local trust** | Verify other agents with local keys, DNS anchors, and explicit trust policies (`open`, `verified`, `strict`). |
| **Developer integration** | Use the CLI, built-in MCP server, Rust crate, Python package, Node package, or Go bindings. |

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

This installs a single `jacs` binary with the CLI and MCP server built in.

## Sign and verify more than JSON

JACS started with signed JSON documents and agent state. The same trust model now covers common AI-era artifacts:

| Artifact | Interface | Notes |
|----------|-----------|-------|
| **JSON and files** | `jacs document create`, `jacs verify`, `sign_message`, `sign_file` | Self-contained signed envelopes for durable records, configs, memories, reports, and audit artifacts. |
| **Markdown and text** | `jacs sign-text`, `jacs verify-text`; Rust/Python/Node/Go bindings | Appends a readable JACS signature block to the file. Multi-signer review works without sidecar JSON. |
| **Images** | `jacs sign-image`, `jacs verify-image`; Rust/Python/Node/Go bindings | Embeds provenance in PNG, JPEG, or WebP metadata. Consumers verify signer identity and pixel-content integrity. |
| **Email** | Rust `jacs::email` | Signs raw RFC 5322 `.eml` bytes by adding a `jacs-signature.json` MIME attachment, then verifies field-level content hashes. |

These signatures prove that a given agent signed specific canonical bytes at its claimed time. They do not prove first creation, copyright ownership, or real-world authorship by themselves.

## MCP server

JACS includes a stdio-only MCP server for Claude Desktop, Cursor, Claude Code, Codex, and other MCP clients:

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

The MCP server opens no HTTP port. It runs as a subprocess of the MCP client so the agent private key stays local to that process.

**Core profile** (default) includes state, document, trust, audit, memory, search, and key tools.

**Full profile** (`jacs mcp --profile full`) adds agreements, messaging, A2A, and attestation tools.

## Use cases

**Local provenance** — Create, sign, verify, and export agent documents locally. No server required.

**Reviewable text** — Let multiple agents or reviewers counter-sign a README, design doc, policy, or release note in place.

**Media provenance** — Attach verifiable signer identity to photos, charts, screenshots, or AI-generated images without a sidecar file.

**Email provenance** — Add a JACS signature attachment to raw email and verify important headers, body parts, and attachments.

**Agent boundaries** — Sign tool outputs, API responses, MCP calls, A2A artifacts, or multi-agent agreements when data crosses a trust boundary.

**Platform verification** — For verified documents, agent behavior, benchmarks, and hosted workflows around JACS identities, see [HumanAssisted/haiai](https://github.com/HumanAssisted/haiai).

## When you do not need JACS

- Everything stays inside one service you control and logs are enough.
- You only need accidental-corruption detection; a checksum is simpler.
- There is no meaningful trust boundary or audit requirement.

JACS is most useful when signed data leaves the process, service, team, or organization that produced it.

## Language support

The CLI and MCP server are the recommended starting points. Native APIs are available when you need direct library integration:

| Language | Install | Notes |
|----------|---------|-------|
| Rust | `cargo add jacs` | Deepest API surface, including `jacs::email`, `jacs::text`, and `jacs::media`. |
| Python | `pip install jacs` | Simple API, framework adapters, text/image signing. |
| Node.js | `npm install @hai.ai/jacs` | Async-first API, framework adapters, text/image signing. |
| Go | `go get github.com/HumanAssisted/JACS/jacsgo` | Signing and verification bindings for services. |

## Security

- Private keys are encrypted with password-based key derivation.
- The MCP server is stdio-only and opens no network listener.
- Signatures include algorithm identification and downgrade protection.
- Automated tests cover cryptographic operations, password validation, agent lifecycle, DNS verification, media/text signing, and attack scenarios.
- `pq2025` (ML-DSA-87 / FIPS-204) is the default signing algorithm for new agents.

Report vulnerabilities to security@hai.ai. Do not open public issues for security concerns.

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Inline Text Signatures](https://humanassisted.github.io/JACS/guides/inline-text-signing.html)
- [Image and Media Signatures](https://humanassisted.github.io/JACS/guides/media-signing.html)
- [Email Signing and Verification](https://humanassisted.github.io/JACS/guides/email-signing.html)
- [Development Guide](DEVELOPMENT.md)
- [HAI.AI Platform](https://github.com/HumanAssisted/haiai)
- [HAI SDK](https://github.com/HumanAssisted/haisdk)

---

v0.10.2 | [Apache-2.0](./LICENSE-APACHE) | [Third-Party Notices](./THIRD-PARTY-NOTICES)
