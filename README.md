# JACS

**Prove who said what, cryptographically.**

Cryptographic signatures for AI agent outputs. No server. No account. Three lines of code.

`pip install jacs` | `npm install @hai.ai/jacs` | `cargo install jacs-cli`

> For a higher-level agent framework built on JACS, see [haiai](https://github.com/HumanAssisted/haiai).

  [![Rust](https://github.com/HumanAssisted/JACS/actions/workflows/rust.yml/badge.svg)](https://github.com/HumanAssisted/JACS/actions/workflows/rust.yml)
  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/HumanAssisted/JACS/blob/main/LICENSE)
  [![Crates.io](https://img.shields.io/crates/v/jacs)](https://crates.io/crates/jacs)
  [![npm](https://img.shields.io/npm/v/@hai.ai/jacs)](https://www.npmjs.com/package/@hai.ai/jacs)
  [![PyPI](https://img.shields.io/pypi/v/jacs)](https://pypi.org/project/jacs/)
  [![Rust 1.93+](https://img.shields.io/badge/rust-1.93+-DEA584.svg?logo=rust)](https://www.rust-lang.org/)

  [![Homebrew](https://github.com/HumanAssisted/JACS/actions/workflows/homebrew.yml/badge.svg)](https://github.com/HumanAssisted/JACS/actions/workflows/homebrew.yml)


## The Simple Contract

JACS has four core operations. Everything else builds on these:

| Operation | What it does |
|-----------|-------------|
| **Create** | Generate an agent identity with a cryptographic key pair |
| **Sign** | Attach a tamper-evident signature to any JSON payload or file |
| **Verify** | Prove a signed document is authentic and unmodified |
| **Export** | Share your agent's public key or signed documents with others |

## Quick Start

### Password Setup

```bash
export JACS_PRIVATE_KEY_PASSWORD='use-a-strong-password'
```

### Python

```python
import jacs.simple as jacs

info = jacs.quickstart(name="payments-agent", domain="payments.example.com")
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

### Node.js

```javascript
const jacs = require('@hai.ai/jacs/simple');

const info = await jacs.quickstart({
  name: 'payments-agent',
  domain: 'payments.example.com',
});
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

### Go

```go
import jacs "github.com/HumanAssisted/JACS/jacsgo"

jacs.Load(nil)
signed, _ := jacs.SignMessage(map[string]interface{}{"action": "approve", "amount": 100})
result, _ := jacs.Verify(signed.Raw)
fmt.Printf("Valid: %t, Signer: %s\n", result.Valid, result.SignerID)
```

### Rust / CLI

```bash
cargo install jacs-cli
jacs quickstart --name payments-agent --domain payments.example.com
jacs document create -f mydata.json
jacs verify signed-document.json
```

### Homebrew (macOS)

```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

## Verify a Signed Document

No agent needed. One command or one function call.

```bash
jacs verify signed-document.json                              # exit code 0 = valid
jacs verify --remote https://example.com/doc.json --json      # fetch + verify
```

```python
result = jacs.verify_standalone(signed_json, key_directory="./keys")
```

```typescript
const r = verifyStandalone(signedJson, { keyDirectory: './keys' });
```

## Use Cases

JACS is optimized for five scenarios:

**U1. Local Provenance** -- An agent creates, signs, verifies, and exports its identity and documents locally. No server required. This is the baseline JACS promise.

**U2. Trusted Local Memory** -- An agent stores memories, plans, tool audit trails, and configs as signed local documents with searchable metadata and visibility controls (`public`/`private`/`restricted`).

**U3. Public Signed Publishing** -- An agent publishes agent cards, public keys, attestations, and shared artifacts that anyone can verify.

**U4. Platform Workflows** -- A [haiai](https://github.com/HumanAssisted/haiai) client uses the same JACS identity to register with HAI, send signed email, and exchange signed artifacts with platform services.

**U5. Advanced Provenance** -- Multi-agent agreements, A2A provenance chains, attestation, and richer storage backends. These are feature-gated and optional -- they do not define the default onboarding story.

See [USECASES.md](USECASES.md) for detailed scenario walkthroughs.

## When You DON'T Need JACS

- **Single developer, single service.** Standard logging is fine.
- **Internal-only prototypes.** No trust boundaries, no value in signing.
- **Simple checksums.** If you only need to detect accidental corruption, use SHA-256.

JACS adds value when data crosses trust boundaries -- between organizations, between services with different operators, or into regulated audit trails.

## Storage

The default storage backend is **filesystem**: signed documents live as JSON on disk under `jacs_data/`. For indexed local search, set `jacs_default_storage` to `"rusqlite"` and JACS stores document rows in `jacs_data/jacs_documents.sqlite3`.

`DocumentService` storage in JACS core currently guarantees:

- Every read verifies the stored JACS document before returning it.
- Every create and update verifies the signed document before persisting it.
- If an update payload modifies an already-signed JACS document without re-signing it, the write fails.

Additional backends are available as separate crates:

| Backend | Crate | Install |
|---------|-------|---------|
| Filesystem | built-in | (always available) |
| Local indexed SQLite (`rusqlite`) | built-in (`sqlite` feature, default) | `cargo add jacs --features sqlite` |
| SQLite (async, sqlx) | built-in (`sqlx-sqlite` feature) | `cargo add jacs --features sqlx-sqlite` |
| PostgreSQL | `jacs-postgresql` | `cargo add jacs-postgresql` |
| DuckDB | `jacs-duckdb` | `cargo add jacs-duckdb` |
| SurrealDB | `jacs-surrealdb` | `cargo add jacs-surrealdb` |
| Redb | `jacs-redb` | `cargo add jacs-redb` |

JACS core resolves the unified `DocumentService` for `fs` and `rusqlite`. Extracted backend crates expose the same traits in their own packages. See [Storage Backends](https://humanassisted.github.io/JACS/advanced/storage.html) for current configuration details.

## Document Visibility

Every document has a visibility level that controls access:

| Level | Meaning |
|-------|---------|
| `public` | Fully public -- can be shared, listed, and returned to any caller |
| `private` | Private to the owning agent (default) |
| `restricted` | Restricted to explicitly named agent IDs or roles |

Visibility is part of signed document state. Changing it creates a new signed version.

## Feature Flags

JACS uses Cargo features to keep the default build minimal:

| Feature | Default | What it enables |
|---------|---------|----------------|
| `sqlite` | Yes | Sync SQLite storage backend (rusqlite) |
| `sqlx-sqlite` | No | Async SQLite storage backend (sqlx + tokio) |
| `a2a` | No | Agent-to-Agent protocol support |
| `agreements` | No | Multi-agent agreement signing with quorum and timeouts |
| `attestation` | No | Evidence-based attestation and DSSE export |
| `otlp-logs` | No | OpenTelemetry log export |
| `otlp-metrics` | No | OpenTelemetry metrics export |
| `otlp-tracing` | No | OpenTelemetry distributed tracing |

## MCP Server

JACS includes a Model Context Protocol (MCP) server for AI tool integration:

```bash
jacs mcp                    # start with core tools (default)
jacs mcp --profile full     # start with all tools
```

**Core profile** (default) -- 7 tool families: state, document, trust, audit, memory, search, key.

**Full profile** -- Core + 4 advanced families: agreements, messaging, a2a, attestation.

Set the profile via `--profile <name>` or `JACS_MCP_PROFILE` environment variable.

## Integrations

Framework adapters for signing AI outputs with zero infrastructure:

| Integration | Import | Status |
|-------------|--------|--------|
| Python + LangChain | `from jacs.adapters.langchain import jacs_signing_middleware` | Experimental |
| Python + CrewAI | `from jacs.adapters.crewai import jacs_guardrail` | Experimental |
| Python + FastAPI | `from jacs.adapters.fastapi import JacsMiddleware` | Experimental |
| Python + Anthropic SDK | `from jacs.adapters.anthropic import signed_tool` | Experimental |
| Node.js + Vercel AI SDK | `require('@hai.ai/jacs/vercel-ai')` | Experimental |
| Node.js + Express | `require('@hai.ai/jacs/express')` | Experimental |
| Node.js + LangChain.js | `require('@hai.ai/jacs/langchain')` | Experimental |
| MCP (Rust, canonical) | `jacs mcp` | Stable |
| A2A Protocol | `client.get_a2a()` | Experimental |
| Go bindings | `jacsgo` | Experimental |

## Features

- **Post-quantum ready** -- ML-DSA-87 (FIPS-204) is the default algorithm alongside Ed25519 and RSA-PSS.
- **Cross-language** -- Sign in Rust, verify in Python or Node.js. Tested on every commit.
- **Multi-agent agreements** -- Quorum signing, timeouts, algorithm requirements (feature-gated).
- **A2A interoperability** -- Every JACS agent is an A2A agent with zero additional config (feature-gated).
- **Trust policies** -- `open`, `verified` (default), or `strict` modes.
- **Document visibility** -- `public`, `private`, or `restricted` access control on every document.
- **Pluggable storage** -- Filesystem, SQLite, PostgreSQL, DuckDB, SurrealDB, Redb via trait-based backends.
- **MCP integration** -- Full MCP server with core and full tool profiles.

### Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Full Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Algorithm Guide](https://humanassisted.github.io/JACS/advanced/algorithm-guide.html)
- [API Reference](https://humanassisted.github.io/JACS/nodejs/api.html)
- [Use Cases](USECASES.md)

---

v0.9.4 | [Apache-2.0 OR MIT](./LICENSE-APACHE) | [Third-Party Notices](./THIRD-PARTY-NOTICES)
