# Development

Detailed API reference, language-specific usage, framework adapters, and build instructions.

## Rust library

```toml
[dependencies]
jacs = "0.9.7"
```

```rust
use jacs::simple::{load, sign_message, verify};

load(None)?;
let signed = sign_message(&serde_json::json!({"action": "approve"}))?;
let result = verify(&signed.raw)?;
assert!(result.valid);
```

### Feature flags

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

### Storage backends

Default storage is **filesystem** (`jacs_data/`). For indexed local search, set `jacs_default_storage` to `"rusqlite"`.

Storage guarantees:
- Every read verifies the stored document before returning it.
- Every write verifies the signed document before persisting it.
- Updating a signed document without re-signing fails.

| Backend | Crate | Install |
|---------|-------|---------|
| Filesystem | built-in | (always available) |
| SQLite (rusqlite) | built-in (`sqlite` feature) | `cargo add jacs --features sqlite` |
| SQLite (sqlx) | built-in (`sqlx-sqlite` feature) | `cargo add jacs --features sqlx-sqlite` |
| PostgreSQL | `jacs-postgresql` | `cargo add jacs-postgresql` |
| DuckDB | `jacs-duckdb` | `cargo add jacs-duckdb` |
| SurrealDB | `jacs-surrealdb` | `cargo add jacs-surrealdb` |
| Redb | `jacs-redb` | `cargo add jacs-redb` |

### Document visibility

| Level | Meaning |
|-------|---------|
| `public` | Fully public — can be shared, listed, and returned to any caller |
| `private` | Private to the owning agent (default) |
| `restricted` | Restricted to explicitly named agent IDs or roles |

Visibility is part of signed document state. Changing it creates a new signed version.

## Python

```bash
pip install jacs
```

Prebuilt native bindings via maturin. No Rust compilation during install.

### Simple API

```python
import jacs.simple as jacs

info = jacs.quickstart(name="my-agent", domain="my-agent.example.com")
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

### Loading an existing agent

```python
agent = jacs.load("./jacs.config.json")
signed = jacs.sign_message({"action": "approve", "amount": 100})
signed_file = jacs.sign_file("document.pdf", embed=True)
```

### Headless loading (no env vars)

```python
from jacs import JacsAgent

secret = get_secret_from_manager()
agent = JacsAgent()
agent.set_private_key_password(secret)
info = json.loads(agent.load_with_info("/srv/my-project/jacs.config.json"))
```

### Full API reference

| Operation | Description |
|-----------|-------------|
| `quickstart(name, domain)` | Create a persistent agent with keys on disk |
| `create()` | Create a new agent programmatically |
| `load()` | Load an existing agent from config |
| `verify_self()` | Verify the loaded agent's integrity |
| `update_agent()` | Update the agent document |
| `update_document()` | Update an existing document |
| `sign_message()` | Sign text or JSON data |
| `sign_file()` | Sign a file with optional embedding |
| `verify()` | Verify any signed document |
| `verify_standalone()` | Verify without loading an agent |
| `verify_by_id()` | Verify a document by its storage ID |
| `get_dns_record()` | Get DNS TXT record for the agent |
| `get_well_known_json()` | Get well-known JSON for discovery |
| `export_agent()` | Export agent JSON for sharing |
| `get_public_key()` | Get the agent's public key |
| `reencrypt_key()` | Re-encrypt the private key |
| `trust_agent()` | Add an agent to the local trust store |
| `list_trusted_agents()` | List all trusted agent IDs |
| `untrust_agent()` | Remove an agent from the trust store |
| `is_trusted()` | Check if an agent is trusted |
| `audit()` | Run a security audit |

### Instance-based API (JacsClient)

For multiple agents in one process:

```python
from jacs.client import JacsClient

client = JacsClient("./jacs.config.json")
signed = client.sign_message({"action": "approve"})

# Or zero-config
client = JacsClient.quickstart(name="my-agent", domain="example.com")

# Ephemeral (in-memory, for tests)
client = JacsClient.ephemeral()
```

### Agreements

```python
from datetime import datetime, timedelta, timezone

agreement = client.create_agreement(
    document={"proposal": "Deploy model v2"},
    agent_ids=[alice.agent_id, bob.agent_id, mediator.agent_id],
    question="Do you approve?",
    quorum=2,
    timeout=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
)

signed = alice.sign_agreement(agreement)
status = alice.check_agreement(signed)
```

### Framework adapters

```bash
pip install jacs[langchain]    # LangChain / LangGraph
pip install jacs[fastapi]      # FastAPI / Starlette
pip install jacs[crewai]       # CrewAI
pip install jacs[anthropic]    # Anthropic / Claude SDK
pip install jacs[all]          # Everything
```

**LangChain:**
```python
from jacs.adapters.langchain import jacs_signing_middleware
agent = create_agent(model="openai:gpt-4o", tools=tools, middleware=[jacs_signing_middleware()])
```

**FastAPI:**
```python
from jacs.adapters.fastapi import JacsMiddleware
app.add_middleware(JacsMiddleware)
```

**CrewAI:**
```python
from jacs.adapters.crewai import jacs_guardrail
task = Task(description="Analyze data", agent=my_agent, guardrail=jacs_guardrail())
```

**Anthropic:**
```python
from jacs.adapters.anthropic import signed_tool

@signed_tool()
def get_weather(location: str) -> str:
    return f"Weather in {location}: sunny"
```

### A2A protocol

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="example.com")
card = client.export_agent_card("http://localhost:8080")
signed = client.sign_artifact({"action": "classify", "input": "hello"}, "task")
```

### Testing

```python
from jacs.testing import jacs_agent

def test_sign_and_verify(jacs_agent):
    signed = jacs_agent.sign_message({"test": True})
    result = jacs_agent.verify(signed.raw_json)
    assert result.valid
```

### Build from source

```bash
make setup   # Install dependencies (uv)
make dev     # Build Rust extension
make test    # Run all tests
```

## Node.js

```bash
npm install @hai.ai/jacs
```

Prebuilt native bindings. No Rust compilation during install.

### Simple API

```javascript
const jacs = require('@hai.ai/jacs/simple');

await jacs.quickstart({ name: 'my-agent', domain: 'agent.example.com' });
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

All operations are async by default. Sync variants with `Sync` suffix.

### Full API reference

| Function | Sync Variant | Description |
|----------|-------------|-------------|
| `quickstart(options)` | `quickstartSync()` | Create a persistent agent |
| `create(options)` | `createSync()` | Create a new agent |
| `load(configPath)` | `loadSync()` | Load from config |
| `signMessage(data)` | `signMessageSync()` | Sign JSON data |
| `signFile(path, embed)` | `signFileSync()` | Sign a file |
| `verify(doc)` | `verifySync()` | Verify a document |
| `verifyById(id)` | `verifyByIdSync()` | Verify by storage ID |
| `createAgreement(...)` | `createAgreementSync()` | Create multi-party agreement |
| `signAgreement(doc)` | `signAgreementSync()` | Co-sign an agreement |
| `checkAgreement(doc)` | `checkAgreementSync()` | Check agreement status |
| `createAttestation(params)` | `createAttestationSync()` | Create attestation |
| `verifyAttestation(doc)` | `verifyAttestationSync()` | Verify attestation |
| `audit(options)` | `auditSync()` | Security audit |

Pure sync functions (no suffix needed): `verifyStandalone`, `getPublicKey`, `isLoaded`, `getDnsRecord`, `getWellKnownJson`, `trustAgent`, `listTrustedAgents`, `isTrusted`.

### Instance-based API (JacsClient)

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart({ name: 'my-agent', domain: 'example.com' });
const signed = await client.signMessage({ action: 'approve' });

// Ephemeral (in-memory, for tests)
const test = await JacsClient.ephemeral('ring-Ed25519');
```

### Framework adapters

**Vercel AI SDK:**
```typescript
import { withProvenance } from '@hai.ai/jacs/vercel-ai';
const model = withProvenance(openai('gpt-4o'), { client });
```

**Express:**
```typescript
import { jacsMiddleware } from '@hai.ai/jacs/express';
app.use(jacsMiddleware({ client, verify: true }));
```

**LangChain.js:**
```typescript
import { createJacsTools } from '@hai.ai/jacs/langchain';
const jacsTools = createJacsTools({ client });
```

**MCP:**
```typescript
import { registerJacsTools } from '@hai.ai/jacs/mcp';
registerJacsTools(server, client);
```

All framework dependencies are optional peer deps.

### A2A protocol

```typescript
const client = await JacsClient.quickstart({ name: 'my-agent', domain: 'example.com' });
const card = client.exportAgentCard();
const signed = await client.signArtifact({ action: 'classify', input: 'hello' }, 'task');
```

### Testing

```typescript
import { createTestClient } from '@hai.ai/jacs/testing';

const client = await createTestClient('ring-Ed25519');
const signed = await client.signMessage({ hello: 'test' });
const result = await client.verify(signed.raw);
assert(result.valid);
```

## Go

```bash
go get github.com/HumanAssisted/JACS/jacsgo
```

Uses CGo to call the JACS Rust library via FFI. Requires a Rust toolchain to build from source.

### Quick start

```go
import jacs "github.com/HumanAssisted/JACS/jacsgo"

jacs.Load(nil)
signed, _ := jacs.SignMessage(map[string]interface{}{"action": "approve", "amount": 100})
result, _ := jacs.Verify(signed.Raw)
fmt.Printf("Valid: %t, Signer: %s\n", result.Valid, result.SignerID)
```

### API reference

| Function | Description |
|----------|-------------|
| `Load(configPath)` | Load agent from config |
| `Create(name, opts)` | Create new agent with keys |
| `SignMessage(data)` | Sign any JSON data |
| `SignFile(path, embed)` | Sign a file |
| `Verify(doc)` | Verify signed document |
| `VerifyStandalone(doc, opts)` | Verify without an agent |
| `ExportAgent()` | Export agent JSON |
| `GetPublicKeyPEM()` | Get public key |
| `Audit(opts)` | Security audit |

For concurrent use, create instances with `NewJacsAgent()`.

### Build

```bash
cd jacsgo && make build
```

## Integrations

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

## Feature Parity

Cross-language feature parity is enforced by canonical JSON fixtures in `binding-core/tests/fixtures/` and contract files in `jacs-cli/contract/` and `jacs-mcp/contract/`. Snapshot tests in Rust, Python, Node, and Go validate that each binding covers the same methods, error kinds, CLI commands, MCP tools, and framework adapters.

If you add or remove a public method, error kind, CLI command, MCP tool, or adapter, update the relevant fixture. Tests across all languages will fail until you do. See **[AGENTS.md](./AGENTS.md#feature-parity-enforcement)** for the full fixture inventory and update guide.

Key fixtures:
- `binding-core/tests/fixtures/method_parity.json` — SimpleAgentWrapper methods (all languages)
- `binding-core/tests/fixtures/parity_inputs.json` — ErrorKind variants (all languages)
- `binding-core/tests/fixtures/cli_mcp_alignment.json` — CLI-to-MCP mapping
- `jacs-cli/contract/cli_commands.json` — CLI commands (validated against Clap tree)
- `jacs-mcp/contract/jacs-mcp-contract.json` — MCP tool schemas

## Security

### Hardening

- Password entropy validation for key encryption (minimum 28 bits)
- Thread-safe environment variable handling
- TLS certificate validation (strict by default)
- Private key zeroization on drop
- Algorithm identification embedded in signatures with downgrade prevention
- DNSSEC-validated identity verification
- 260+ automated tests

### Best practices

- Prefer the OS keychain on desktops when available.
- On Linux/headless services, use `JACS_PASSWORD_FILE` from a secret mount and set `JACS_KEYCHAIN_BACKEND=disabled`.
- `JACS_PRIVATE_KEY_PASSWORD` is supported but less desirable for long-running services.
- Use strong passwords (12+ characters with mixed case, numbers, symbols).
- Keep JACS and its dependencies updated.

### Reporting vulnerabilities

Email: security@hai.ai. Do not open public issues for security vulnerabilities. We aim to respond within 48 hours.

### Dependency audit

```bash
cargo install cargo-audit && cargo audit
```

## Trust policies

| Policy | Behavior |
|--------|----------|
| `open` | Accept all signatures without key resolution |
| `verified` | Require key resolution before accepting (default) |
| `strict` | Require the signer to be in your local trust store |

## Password requirements

Passwords must be at least 8 characters and include uppercase, lowercase, a digit, and a special character.

For headless environments, prefer `JACS_PASSWORD_FILE` from a secret mount:

```bash
export JACS_PASSWORD_FILE=/run/secrets/jacs-password
export JACS_KEYCHAIN_BACKEND=disabled
```
