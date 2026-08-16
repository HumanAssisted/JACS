# JACS

**Portable cryptographic signatures for AI agents, services, and the artifacts they exchange.**

JACS signs canonical JSON and common artifact formats, then lets Rust, Python, Node.js, Go, CLI, MCP clients, and other systems verify who signed what without a central server. Its schemas define verifiable JSON document formats so data can move between libraries, languages, and use cases without losing integrity.

`cargo install jacs-cli` | `brew install jacs`

  [![Rust](https://github.com/HumanAssisted/JACS/actions/workflows/rust.yml/badge.svg)](https://github.com/HumanAssisted/JACS/actions/workflows/rust.yml)
  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/HumanAssisted/JACS/blob/main/LICENSE)
  [![Crates.io](https://img.shields.io/crates/v/jacs)](https://crates.io/crates/jacs)
  [![npm](https://img.shields.io/npm/v/@hai.ai/jacs)](https://www.npmjs.com/package/@hai.ai/jacs)
  [![PyPI](https://img.shields.io/pypi/v/jacs)](https://pypi.org/project/jacs/)
  [![Rust 1.97+](https://img.shields.io/badge/rust-1.97+-DEA584.svg?logo=rust)](https://www.rust-lang.org/)
  [![Homebrew](https://github.com/HumanAssisted/JACS/actions/workflows/homebrew.yml/badge.svg)](https://github.com/HumanAssisted/JACS/actions/workflows/homebrew.yml)

## What JACS does

| Capability | What it means |
|-----------|---------------|
| **Agent identity** | Generate and manage a persistent cryptographic identity for an agent. `pq2025` / ML-DSA-87 is the post-quantum default; explicit Ed25519 selection is also supported. |
| **Portable signatures** | Sign in one surface and verify in another across Rust, Python, Node.js, Go, CLI, and MCP integrations. |
| **Schema-backed JSON** | Create verifiable JSON documents with declared schemas, content hashes, signer identity, signing algorithm, and signature metadata. |
| **Artifact provenance** | Sign files, Markdown/text, images, and Rust email payloads so consumers can detect tampering and identify the signer. |
| **Agreement v2** | Create standalone signed agreement documents with terms, parties, transcript evidence, notary support, branch handling, and portable verification. |
| **Local trust** | Verify other agents with local keys, DNS anchors, and explicit trust policies (`open`, `verified`, `strict`). |
| **Ecosystem compatibility** | Optional ES256 key bound to the selected native root. Export JWKS, key bindings, AP2 mandates, A2A agent cards, and Agreement v2 credentials via CLI and bindings. |
| **Developer integration** | Use the CLI, built-in MCP server, Rust crate, Python package, Node package, or Go bindings. |

## Quick start

```bash
cargo install jacs-cli

export JACS_PRIVATE_KEY_PASSWORD='your-password'
jacs quickstart --name my-agent --domain example.com
jacs document create -f mydata.json --output signed-document.json
jacs verify jacs_data/signed-document.json
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
      "args": ["mcp"],
      "env": {
        "JACS_CONFIG": "/absolute/path/to/jacs.config.json",
        "JACS_PASSWORD_FILE": "/absolute/path/to/jacs-password",
        "JACS_MCP_BASE_DIR": "/absolute/path/to/project"
      }
    }
  }
}
```

The MCP server opens no HTTP port. It runs as a subprocess of the MCP client so the agent private key stays local to that process.

`JACS_CONFIG` is required. Prefer an owner-readable password file (for example, mode `0600`) or the OS keychain instead of placing the private-key password directly in desktop-client JSON.

**Core profile** (default) includes document, inline text/media, trust, search, key/agent, A2A discovery, and W3C tools.

**Full profile** adds Agreement v2, A2A artifact, and attestation tools:

```bash
jacs mcp --profile full
# Equivalent when --profile is absent:
JACS_MCP_PROFILE=full jacs mcp
```

An explicit `--profile` overrides `JACS_MCP_PROFILE`; unknown profile values fail startup instead of silently selecting core.

File-tool paths must be relative to `JACS_MCP_BASE_DIR` (or the launch working directory when unset). Absolute paths, traversal, and symlinks are rejected. Existing output files are not overwritten unless the operator explicitly sets `JACS_MCP_OVERWRITE_OK=1`.

## Use cases

**Local provenance** — Create, sign, verify, and export agent documents locally. No server required.

**Reviewable text** — Let multiple agents or reviewers counter-sign a README, design doc, policy, or release note in place.

**Media provenance** — Attach verifiable signer identity to photos, charts, screenshots, or AI-generated images without a sidecar file.

**Email provenance** — Add a JACS signature attachment to raw email and verify important headers, body parts, and attachments.

**Agent boundaries** — Sign tool outputs, API responses, MCP calls, A2A artifacts, or standalone Agreement v2 documents when data crosses a trust boundary.

**Platform verification** — For verified documents, hosted agent identities, and `@hai.ai` mail built on JACS, see [HumanAssisted/haiai](https://github.com/HumanAssisted/haiai) — the SDK for the agreement factory at [hai.ai](https://hai.ai), where people and their advocate agents interview, draft, and confirm agreements. HAI.AI's research evaluation is published on [MediationBench](https://whatisprogress.com).

## When you do not need JACS

- Everything stays inside one service you control and logs are enough.
- You only need accidental-corruption detection; a checksum is simpler.
- There is no meaningful trust boundary or audit requirement.

JACS is most useful when signed data leaves the process, service, team, or organization that produced it.

## Language support

The CLI and MCP server are the recommended starting points. Native APIs are available when you need direct library integration:

> **Shipped versions observed 2026-07-11:** source is `0.11.4`, while crates.io
> and PyPI publish `0.11.3`, npm publishes `@hai.ai/jacs@0.10.1`, and
> `@jacs/wasm` is not published. The Go module has only a pseudo-version and no
> matching native-library release. Do not assume source-head API parity from an
> unpinned install. The machine-readable evidence is
> [`release/shipped-artifacts.json`](release/shipped-artifacts.json).

| Language | Install | Notes |
|----------|---------|-------|
| Rust | `cargo add jacs` | Registry `0.11.3`; deepest API surface, including `jacs::email`, `jacs::text`, and `jacs::media`. |
| Python | `pip install jacs` | Registry `0.11.3`; simple API, framework adapters, text/image signing. |
| Node.js | `npm install @hai.ai/jacs` | Registry `0.10.1`; it does **not** contain every API documented on this `0.11.4` branch. |
| Go | See [`jacsgo/README.md`](jacsgo/README.md) | `go get` alone cannot link. Build the full repository today; after a semantic release exists, install its checksum-verified native library. |
| Browser | Source build only | `@jacs/wasm` is not yet available from npm. |

## HTTP trust-boundary protocol

Source `0.11.4` includes a request-bound HTTP credential and a fully signed
response/event envelope on the instance-based simple API:

| Language | Request credential | Signed response | Strict event verification |
|----------|--------------------|-----------------|---------------------------|
| Rust | `SimpleAgent::build_request_auth_header` | `SimpleAgent::sign_response` | `protocol::verify_signed_event_with_trusted_keys` |
| Python | `SimpleAgent.build_request_auth_header` | `SimpleAgent.sign_response` | `SimpleAgent.unwrap_signed_event` |
| Node.js | `JacsSimpleAgent.buildRequestAuthHeader` | `JacsSimpleAgent.signResponse` | `JacsSimpleAgent.unwrapSignedEvent` |
| Go | `JacsSimpleAgent.BuildRequestAuthHeader` | `JacsSimpleAgent.SignResponse` | `JacsSimpleAgent.UnwrapSignedEvent` |

The request credential is `JACS v2.<claims>.<signature>`. Build it from the
actual HTTP method, absolute URL (including the query string), exact transmitted
body bytes, and a non-empty service-specific audience. Changing any of those
values invalidates the credential. Servers must verify with a configured
signer-to-public-key binding, enforce freshness, and atomically consume the
nonce; multi-replica services need a shared replay store. Application-owned
stores must retain the nonce for at least
`protocol::request_auth_replay_ttl(&verified_claims, max_age)`, not merely
`max_age`, so accepted positive clock skew cannot outlive the replay entry.

`sign_response` / `signResponse` emits a `2.0.0` response envelope whose
`jacs-response-v2` signature covers the payload and all envelope metadata.
Strict event unwrapping rejects plain events, legacy payload-only envelopes,
unknown signers, and any payload or metadata mutation. It returns verified data
and provenance; there is no successful `verified: false` result.

These checks prove possession of the private key corresponding to the public
key selected by the verifier. A signer ID, name, domain, or timestamp is not a
real-world identity claim unless the application has established that mapping
through its configured trust policy.

The legacy no-argument request header signs only identity, time, and nonce. It
remains available for source compatibility and emits a WARN. Migrate both peers
to v2; strict deployments can reject legacy construction with
`JACS_REJECT_UNBOUND_AUTH_HEADER=true`.

## Security

- Private keys are encrypted with password-based key derivation.
- The MCP server is stdio-only and opens no network listener.
- Signatures include algorithm identification and downgrade protection.
- Automated tests cover cryptographic operations, password validation, agent lifecycle, DNS verification, media/text signing, and attack scenarios.
- `pq2025` (ML-DSA-87 / FIPS-204) is the default native signing algorithm. Explicit `ed25519` creation produces `ring-Ed25519` keys and signatures. Rotation preserves the current algorithm unless an Ed25519 identity explicitly upgrades to `pq2025`; PQ-to-Ed25519 downgrade is rejected.

Report vulnerabilities to security@hai.ai. Do not open public issues for security concerns.

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Inline Text Signatures](https://humanassisted.github.io/JACS/guides/inline-text-signing.html)
- [Image and Media Signatures](https://humanassisted.github.io/JACS/guides/media-signing.html)
- [Email Signing and Verification](https://humanassisted.github.io/JACS/guides/email-signing.html)
- [Development Guide](DEVELOPMENT.md)
- [HAI.AI Platform](https://github.com/HumanAssisted/hai)
- [haiai SDK](https://github.com/HumanAssisted/haiai)

---

v0.11.4 | [Apache-2.0](./LICENSE-APACHE) | [Third-Party Notices](./THIRD-PARTY-NOTICES)
