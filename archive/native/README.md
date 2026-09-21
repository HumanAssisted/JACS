> **Native compatibility workspace.** This code supports existing HAI SDK and
> native integrations while remaining outside the five-crate portable workspace.
> Rust, Node, Python and Go builds and publication are enabled through the root
> Makefile and CI. All release packages are coordinated at 0.15.0; existing
> licenses and notices remain in force.
>
> Follow the [current root release guide](../../RELEASING.md). Extended MCP/CLI
> crates use `jacs-mcp-compat` and `jacs-cli-compat`; the compatibility executable
> is `jacs-compat`. Historical commands below describe the pre-move layout.
> SurrealDB and the observability example retain separate lockfiles. The example
> remains unpublished; storage crates are in the coordinated release catalog.

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
      "args": ["mcp"]
    }
  }
}
```

The MCP server opens no HTTP port. Without an explicit config, its default
verification-only process loads no identity; a supplied config is public-only
and never loads/decrypts a private signing key. Callers provide the exact public
key and algorithm with the document bytes they inspect.

The default `verify-only` process advertises only explicit-key document
integrity verification; it does not expose signing, key/trust mutation, disk
search, ambient trust reads, or public exports. The only accepted profile names are
`verify-only`, `local-sign`, `trust-admin`, and compatibility-only
`legacy-core`. An explicit `--profile` overrides `JACS_MCP_PROFILE`, and
unknown values fail startup. For local JSON/Agreement signing, explicitly
select your existing signed config:

```bash
jacs mcp --profile local-sign --config ./jacs.config.json
```

This uses the existing encrypted key/password source and a closed offline tool
set; documents persist under `<config directory>/documents`. It signs as the
local agent, not as evidence of per-action human approval. To enable the five
scoped file tools, also select an existing content directory at startup:

```bash
JACS_MCP_BASE_DIR=/path/to/content jacs mcp --profile local-sign --config ./jacs.config.json
```

This adds `jacs_sign_text`, `jacs_verify_text`, `jacs_sign_image`,
`jacs_verify_image`, and `jacs_extract_media_signature`. The content root does
not expand `verify-only`; trust/admin capabilities remain unavailable. See the [MCP local scope
and remaining limitations](jacs-mcp/README.md#explicit-local-signing).

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

> **Committed release ledger dated 2026-09-10:**
> [`release/shipped-artifacts.json`](release/shipped-artifacts.json) records
> Rust, CLI and Python `0.13.0`, Go `v0.13.0` with native libraries, Node
> `@hai.ai/jacs@0.10.1`, and no published `@jacs/wasm` package. These are dated
> ledger entries, not a fresh registry check. See the ledger for platform and
> verification limits; an unpinned install does not imply source-head API parity.

| Language | Install | Notes |
|----------|---------|-------|
| Rust | `cargo add jacs` | Ledger: `0.13.0`; includes `jacs::email`, `jacs::text`, and `jacs::media`. |
| Python | `pip install jacs` | Ledger: `0.13.0`; simple API, framework adapters, text/image signing. |
| Node.js | `npm install @hai.ai/jacs` | Ledger: `0.10.1`; it does **not** contain every API documented on this `0.13.0` branch. |
| Go | See [`jacsgo/README.md`](jacsgo/README.md) | Ledger: `v0.13.0` and native libraries. `go get` alone cannot link; use the matching checksum-verified library and check the recorded platform limits. |
| Browser | Source build only | Ledger: no published `@jacs/wasm` package. |

## HTTP trust-boundary protocol

Source `0.13.0` includes a request-bound HTTP credential and a fully signed
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

v0.13.0 | [Apache-2.0](./LICENSE-APACHE) | [Third-Party Notices](./THIRD-PARTY-NOTICES)
