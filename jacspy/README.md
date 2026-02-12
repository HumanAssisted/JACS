# JACS Python Library

**Sign it. Prove it.**

Cryptographic signatures for AI agent outputs -- so anyone can verify who said what and whether it was changed. No server. Three lines of code. Optionally register with [HAI.ai](https://hai.ai) for cross-organization key discovery.

[Which integration should I use?](https://humanassisted.github.io/JACS/getting-started/decision-tree.html) | [Full documentation](https://humanassisted.github.io/JACS/)

```bash
# Using uv (recommended)
uv pip install jacs

# Or with pip
pip install jacs

# With HAI.ai integration
uv pip install jacs[hai]
```

Packaging/build metadata is defined in `pyproject.toml` (maturin). `setup.py` is intentionally not used.

To check dependencies for known vulnerabilities when using optional extras, run `pip audit` (or `safety check`).

## Quick Start

Zero-config -- one call to start signing:

```python
import jacs.simple as jacs

jacs.quickstart()
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

`quickstart()` creates a persistent agent with keys on disk. If `./jacs.config.json` already exists, it loads it; otherwise it creates a new agent. Agent, keys, and config are saved to `./jacs_data`, `./jacs_keys`, and `./jacs.config.json`. If `JACS_PRIVATE_KEY_PASSWORD` is not set, a secure password is auto-generated and saved to `./jacs_keys/.jacs_password`. Pass `algorithm="ring-Ed25519"` or `algorithm="RSA-PSS"` to override the default (`pq2025`).

**Signed your first document?** Next: [Verify it standalone](#standalone-verification-no-agent-required) | [Add framework adapters](#framework-adapters) | [Multi-agent agreements](#agreements-with-timeout-and-quorum) | [Full docs](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

### Advanced: Loading an existing agent

If you already have an agent (e.g., created by a previous `quickstart()` call), load it explicitly:

```python
import jacs.simple as jacs

agent = jacs.load("./jacs.config.json")

# Sign a message (accepts dict, list, str, or any JSON-serializable data)
signed = jacs.sign_message({"action": "approve", "amount": 100})
print(f"Signed by: {signed.agent_id}")

# Verify it
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}")

# Sign a file
signed_file = jacs.sign_file("document.pdf", embed=True)

# Update agent metadata
agent_doc = json.loads(jacs.export_agent())
agent_doc["jacsAgentType"] = "updated-service"
updated = jacs.update_agent(agent_doc)

# Update a document
doc = json.loads(signed.raw)
doc["content"]["status"] = "approved"
updated_doc = jacs.update_document(signed.document_id, doc)
```

## Core Operations

The simplified API provides these core operations:

| Operation | Description |
|-----------|-------------|
| `quickstart()` | Create a persistent agent with keys on disk -- zero config, no manual setup |
| `create()` | Create a new agent programmatically (non-interactive) |
| `load()` | Load an existing agent from config |
| `verify_self()` | Verify the loaded agent's integrity |
| `update_agent()` | Update the agent document with new data |
| `update_document()` | Update an existing document with new data |
| `sign_message()` | Sign a text message or JSON data |
| `sign_file()` | Sign a file with optional embedding |
| `verify()` | Verify any signed document (JSON string) |
| `verify_standalone()` | Verify without loading an agent (one-off) |
| `verify_by_id()` | Verify a document by its storage ID (`uuid:version`) |
| `get_dns_record()` | Get DNS TXT record line for the agent |
| `get_well_known_json()` | Get well-known JSON for `/.well-known/jacs-pubkey.json` |
| `reencrypt_key()` | Re-encrypt the private key with a new password |
| `trust_agent()` | Add an agent to the local trust store |
| `list_trusted_agents()` | List all trusted agent IDs |
| `untrust_agent()` | Remove an agent from the trust store |
| `is_trusted()` | Check if an agent is trusted |
| `get_trusted_agent()` | Get a trusted agent's JSON document |
| `audit()` | Run a read-only security audit (returns risks, health_checks, summary) |
| `generate_verify_link()` | Generate a shareable hai.ai verification URL for a signed document |

### Programmatic Agent Creation

```python
import jacs.simple as jacs

# Create an agent without interactive prompts
agent = jacs.create(
    name="my-agent",
    password="Str0ng-P@ssw0rd!",  # or set JACS_PRIVATE_KEY_PASSWORD env var
    algorithm="pq2025",            # default; also: "ring-Ed25519", "RSA-PSS"
    data_directory="./jacs_data",
    key_directory="./jacs_keys",
)
print(f"Created agent: {agent.agent_id}")
```

### Standalone Verification (No Agent Required)

Verify a signed document without loading an agent. Useful for one-off verification, CI/CD pipelines, or services that only need to verify, not sign.

```python
import jacs.simple as jacs

result = jacs.verify_standalone(
    signed_json,
    key_resolution="local",
    key_directory="./trusted-keys/"
)
if result.valid:
    print(f"Signed by: {result.signer_id}")
```

Generate a shareable verification link:

```python
url = jacs.generate_verify_link(signed_doc.raw_json)
# https://hai.ai/jacs/verify?s=<base64url-encoded-document>
```

Documents signed by Rust or Node.js agents verify identically in Python -- cross-language interop is tested on every commit with Ed25519 and pq2025 (ML-DSA-87). See the full [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html) for CLI, DNS, and cross-language examples.

### Verify by Document ID

```python
# If you have a document ID instead of the full JSON
result = jacs.verify_by_id("550e8400-e29b-41d4-a716-446655440000:1")
print(f"Valid: {result.valid}")
```

### Re-encrypt Private Key

```python
jacs.reencrypt_key("old-password-123!", "new-Str0ng-P@ss!")
```

### Password Requirements

Passwords must be at least 8 characters and include uppercase, lowercase, a digit, and a special character.

### Algorithm Deprecation Notice

The `pq-dilithium` algorithm is deprecated. Use `pq2025` (ML-DSA-87, FIPS-204) instead. `pq-dilithium` still works but emits deprecation warnings.

## Type Definitions

```python
from jacs import AgentInfo, SignedDocument, VerificationResult

# All return types are dataclasses with clear fields
agent: AgentInfo = jacs.load()
signed: SignedDocument = jacs.sign_message({"data": "hello"})
result: VerificationResult = jacs.verify(signed.raw)
```

## JacsClient (Instance-Based API)

When you need multiple agents in one process, or want to avoid global state, use `JacsClient`. Each instance wraps its own `JacsAgent` with independent keys and config.

```python
from jacs.client import JacsClient

# Load from config
client = JacsClient("./jacs.config.json")
signed = client.sign_message({"action": "approve"})
result = client.verify(signed.raw_json)
print(f"Valid: {result.valid}, Agent: {client.agent_id}")

# Or zero-config quickstart (creates keys on disk)
client = JacsClient.quickstart()

# Context manager for automatic cleanup
with JacsClient.quickstart() as client:
    signed = client.sign_message("hello")
```

### Multi-Agent Example

```python
from jacs.client import JacsClient

alice = JacsClient.ephemeral()
bob = JacsClient.ephemeral()

signed = alice.sign_message({"from": "alice"})
result = bob.verify(signed.raw_json)
print(f"Alice: {alice.agent_id}")
print(f"Bob verifies Alice's message: {result.valid}")
```

### Agreements with Timeout and Quorum

`create_agreement` accepts flat keyword arguments for advanced options:

```python
from datetime import datetime, timedelta, timezone

agreement = client.create_agreement(
    document={"proposal": "Deploy model v2"},
    agent_ids=[alice.agent_id, bob.agent_id, mediator.agent_id],
    question="Do you approve?",
    quorum=2,                    # 2-of-3 signatures required
    timeout=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    required_algorithms=None,    # optional: restrict signing algorithms
    minimum_strength=None,       # optional: "classical" or "post-quantum"
)

signed = alice.sign_agreement(agreement)
status = alice.check_agreement(signed)
print(f"Complete: {status.complete}, Pending: {status.pending}")
```

See [`examples/multi_agent_agreement.py`](../examples/multi_agent_agreement.py) for a full 3-agent agreement demo with crypto proof chain.

### JacsClient API Reference

| Method | Description |
|--------|-------------|
| `JacsClient(config_path)` | Load from config |
| `JacsClient.quickstart()` | Zero-config persistent agent |
| `JacsClient.ephemeral()` | In-memory agent (no disk, for tests) |
| `sign_message(data)` | Sign JSON-serializable data |
| `verify(document)` | Verify a signed document |
| `verify_self()` | Verify agent integrity |
| `verify_by_id(doc_id)` | Verify by storage ID |
| `sign_file(path, embed)` | Sign a file |
| `create_agreement(...)` | Create multi-party agreement |
| `sign_agreement(doc)` | Co-sign an agreement |
| `check_agreement(doc)` | Check agreement status |
| `trust_agent(json)` | Add agent to trust store |
| `list_trusted_agents()` | List trusted agent IDs |
| `update_agent(data)` | Update and re-sign agent |
| `update_document(id, data)` | Update and re-sign document |
| `export_agent()` | Export agent JSON for sharing |
| `audit()` | Run security audit |
| `reset()` | Clear internal state |

## Framework Adapters

Auto-sign AI framework outputs with zero infrastructure. Install the extra for your framework:

```bash
pip install jacs[langchain]   # LangChain / LangGraph
pip install jacs[fastapi]     # FastAPI / Starlette
pip install jacs[crewai]      # CrewAI
pip install jacs[anthropic]   # Anthropic / Claude SDK
pip install jacs[all]         # Everything
```

**LangChain** -- sign every tool result via middleware:
```python
from jacs.adapters.langchain import jacs_signing_middleware
agent = create_agent(model="openai:gpt-4o", tools=tools, middleware=[jacs_signing_middleware()])
```

**FastAPI** -- sign all JSON responses:
```python
from jacs.adapters.fastapi import JacsMiddleware
app.add_middleware(JacsMiddleware)
```

**CrewAI** -- sign task outputs via guardrail:
```python
from jacs.adapters.crewai import jacs_guardrail
task = Task(description="Analyze data", agent=my_agent, guardrail=jacs_guardrail())
```

**Anthropic / Claude SDK** -- sign tool return values:
```python
from jacs.adapters.anthropic import signed_tool

@signed_tool()
def get_weather(location: str) -> str:
    return f"Weather in {location}: sunny"
```

See the [Framework Adapters guide](https://humanassisted.github.io/JACS/python/adapters.html) for full documentation, custom adapters, and strict/permissive mode details.

## Testing

The `jacs.testing` module provides a pytest fixture that creates an ephemeral client with no disk I/O or env vars required:

```python
from jacs.testing import jacs_agent

def test_sign_and_verify(jacs_agent):
    signed = jacs_agent.sign_message({"test": True})
    result = jacs_agent.verify(signed.raw_json)
    assert result.valid

def test_agent_has_unique_id(jacs_agent):
    assert jacs_agent.agent_id
```

The fixture automatically resets after each test.

## MCP Integration

For AI tool servers using the Model Context Protocol:

```python
from fastmcp import FastMCP
import jacs.simple as jacs

mcp = FastMCP("My Server")
jacs.load("./jacs.config.json")

@mcp.tool()
def signed_hello(name: str) -> dict:
    signed = jacs.sign_message({"greeting": f"Hello, {name}!"})
    return {"response": signed.raw}
```

## JacsAgent Class (Advanced)

For more control, use the `JacsAgent` class directly:

```python
from jacs import JacsAgent

agent = JacsAgent()
agent.load("./jacs.config.json")

# Sign raw strings
signature = agent.sign_string("data to sign")

# Verify documents
is_valid = agent.verify_document(document_json)

# Create documents with schemas
doc = agent.create_document(json_string, schema=None)
```

## A2A Protocol Support

Every JACS agent is an A2A agent -- zero additional configuration. JACS implements the [Agent-to-Agent (A2A)](https://github.com/google/A2A) protocol with cryptographic trust built in.

### Quick Start

```python
from jacs.client import JacsClient

client = JacsClient.quickstart()
card = client.export_agent_card("http://localhost:8080")
signed = client.sign_artifact({"action": "classify", "input": "hello"}, "task")
```

### Using JACSA2AIntegration Directly

For full A2A lifecycle control (well-known documents, chain of custody, extension descriptors):

```python
from jacs.client import JacsClient
from jacs.a2a import JACSA2AIntegration

client = JacsClient.quickstart()
a2a = client.get_a2a(url="http://localhost:8080")

# Export an A2A Agent Card
card = a2a.export_agent_card(agent_data)

# Sign an artifact with provenance
signed = a2a.sign_artifact({"taskId": "t-1", "operation": "classify"}, "task")

# Verify a received artifact
result = a2a.verify_wrapped_artifact(signed)
assert result["valid"]

# Build chain of custody across agents
step2 = a2a.sign_artifact(
    {"step": 2, "data": "processed"}, "message",
    parent_signatures=[signed],
)
```

### One-Liner Quickstart

```python
from jacs.a2a import JACSA2AIntegration

a2a = JACSA2AIntegration.quickstart(url="http://localhost:8080")
a2a.serve(port=8080)  # Publishes /.well-known/agent-card.json
```

### Trust Policies

JACS trust policies control how your agent handles foreign signatures:

| Policy | Behavior |
|--------|----------|
| `open` | Accept all signatures without key resolution |
| `verified` | Require key resolution before accepting (**default**) |
| `strict` | Require the signer to be in your local trust store |

See the [A2A Guide](https://humanassisted.github.io/JACS/integrations/a2a.html) for well-known documents, cross-organization discovery, and chain-of-custody examples.

## HAI.ai Integration

[HAI.ai](https://hai.ai) benchmarks AI mediator agents on conflict resolution skills. Register your agent, run benchmarks at three price tiers, and compete on the public leaderboard.

### Quick Start: Zero to Benchmarked

```bash
pip install jacs[hai]
export HAI_API_KEY=your-api-key  # Get one at https://hai.ai/dev
```

```python
from jacs.hai import register_new_agent, hello_world, free_chaotic_run

# Step 1: Create + register (one call)
result = register_new_agent(name="My Mediator")
print(f"Agent ID: {result.agent_id}")

# Step 2: Hello world (verify connectivity, free)
ack = hello_world("https://hai.ai")
print(f"HAI says: {ack.message}")

# Step 3: Free chaotic run (see your agent mediate, no score)
run = free_chaotic_run("https://hai.ai")
for msg in run.transcript:
    print(f"[{msg.role}] {msg.content}")
```

### Three-Tier Benchmark System

| Tier | Cost | What You Get |
|------|------|-------------|
| **Free Chaotic** | $0 (once per keypair) | Transcript + annotations, no score |
| **Baseline** | $5 | Single score (0-100), private to you |
| **Certified** | ~$500 | Full report, leaderboard placement, public profile |

```python
from jacs.hai import baseline_run, sign_benchmark_result

# $5 baseline -- opens Stripe Checkout, returns score + transcript
result = baseline_run("https://hai.ai")
print(f"Score: {result.score}/100")

# Sign the result for independent verification
signed = sign_benchmark_result(run_id=result.run_id, score=result.score, tier="baseline")
```

### Available Methods

| Method | Description |
|--------|-------------|
| `register_new_agent()` | Create agent + register in one call |
| `hello_world()` | Verify connectivity with HAI-signed ACK |
| `free_chaotic_run()` | Free benchmark with transcript (no score) |
| `baseline_run()` | $5 benchmark with private score |
| `sign_benchmark_result()` | Sign a result for independent verification |
| `testconnection()` | Test HAI.ai connectivity |
| `register()` | Register an existing agent |
| `verify_agent()` | Verify another agent's trust level |
| `status()` | Check registration status |
| `connect()` | Connect to SSE or WebSocket event stream |
| `submit_benchmark_response()` | Submit a job response during benchmarks |
| `disconnect()` | Close event stream connection |

### Agent Connection: SSE vs WebSocket

HAI.ai supports two transport protocols for real-time agent connections. Both use the same `connect()` API with automatic reconnection.

**SSE (Server-Sent Events)** -- Default, recommended for most use cases:

```python
# SSE connection (default)
for event in hai.connect("https://hai.ai", api_key="your-key"):
    if event.event_type == "benchmark_job":
        # Process benchmark job, submit response via REST
        result = process_job(event.data)
        hai.submit_benchmark_response(hai_url, api_key, event.data["job_id"], result)
    elif event.event_type == "heartbeat":
        pass  # Connection alive
```

**WebSocket** -- For bidirectional communication and lower latency:

```python
# WebSocket connection
for event in hai.connect("https://hai.ai", api_key="your-key", transport="ws"):
    if event.event_type == "benchmark_job":
        # Can submit response on the same connection (lower latency)
        result = process_job(event.data)
```

**When to use which:**

| | SSE | WebSocket |
|---|---|---|
| **Best for** | Most agents, simple setup | High-frequency agents, latency-sensitive |
| **Direction** | Server-to-client (responses via REST) | Bidirectional |
| **Proxy/CDN** | Works through all proxies | May need proxy configuration |
| **Resume** | `Last-Event-ID` header | Sequence number tracking |
| **Auth** | `Authorization` header | JACS-signed handshake as first message |
| **Install** | `pip install jacs[hai]` | `pip install jacs[ws]` (adds `websockets`) |

Both transports use exponential backoff reconnection (1s initial, 60s max) and reset on successful connection.

### Agent Verification Levels

JACS agents can be verified at three trust levels:

| Level | Badge | What it proves |
|-------|-------|----------------|
| 1 | Basic | Agent holds a valid private key (self-signed) |
| 2 | Domain | Agent owner controls a DNS domain |
| 3 | Attested | HAI.ai has verified and co-signed the agent |

```python
from jacs.hai import verify_agent

# Verify another agent meets your trust requirements
result = verify_agent(sender_agent_doc, min_level=2)

if result.valid:
    print(f"Verified: {result.agent_id} (Level {result.level}: {result.level_name})")
else:
    print(f"Verification failed: {result.errors}")
```

### Examples

- `examples/hai_quickstart.py` - Full three-tier flow (register, hello, free, baseline)
- `examples/register_with_hai.py` - Registration with DNS verification
- `examples/sse_client.py` - SSE event stream connection
- `examples/run_benchmark.py` - Benchmark execution details

## Installation

```bash
# Basic installation
pip install jacs

# With framework adapters
pip install jacs[langchain]    # LangChain / LangGraph
pip install jacs[fastapi]      # FastAPI / Starlette
pip install jacs[crewai]       # CrewAI
pip install jacs[anthropic]    # Anthropic / Claude SDK
pip install jacs[all]          # All adapters + MCP + HAI + A2A

# With A2A support
pip install jacs[a2a]          # Discovery only (httpx)
pip install jacs[a2a-server]   # A2A server with serve() (FastAPI + uvicorn)

# With MCP support
pip install jacs[mcp]

# With HAI.ai integration
pip install jacs[hai]
```

## Examples

See the [examples/](./examples/) directory:
- `quickstart.py` - Basic signing and verification
- `hai_quickstart.py` - Full HAI.ai three-tier benchmark flow
- `sign_file.py` - File signing with embeddings
- `mcp_server.py` - Authenticated MCP server
- `p2p_exchange.py` - Peer-to-peer trust establishment
- [`multi_agent_agreement.py`](../examples/multi_agent_agreement.py) - Three-agent agreement with quorum, timeout, and crypto proof chain

## Development

Using uv (recommended):

```bash
# Quick start with Makefile
make setup   # Install all dependencies
make dev     # Build for development
make test    # Run all tests

# Or manually:
uv venv && source .venv/bin/activate
uv pip install maturin pytest httpx httpx-sse
uv run maturin develop
uv run python -m pytest tests/ -v
```

### Available Make Commands

| Command | Description |
|---------|-------------|
| `make setup` | Install dev dependencies with uv |
| `make dev` | Build Rust extension for development |
| `make test` | Run all tests (Python + HAI) |
| `make test-hai` | Run HAI integration tests only |
| `make check-imports` | Verify all imports work |

## Documentation

- [JACS Book](https://humanassisted.github.io/JACS/) - Full documentation (published book)
- [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html) - CLI, standalone, DNS verification
- [API Reference](https://humanassisted.github.io/JACS/api/python) - Python API docs
- [Migration Guide](https://humanassisted.github.io/JACS/migration) - Upgrading from v0.4.x
- [Source](https://github.com/HumanAssisted/JACS) - GitHub repository
