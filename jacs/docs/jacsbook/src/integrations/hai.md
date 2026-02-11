# HAI.ai Platform Integration

The `jacs.hai` module (`jacspy/python/jacs/hai.py`) provides a Python client for integrating JACS agents with the HAI.ai platform. This is the infrastructure that connects locally-created JACS agents to the global trust network.

## What HAI.ai Provides

| Capability | Description |
|------------|-------------|
| Agent Registration | Register your JACS agent to get a HAI.ai counter-signature |
| Trust Attestation | Three-level trust model (basic, domain, attested) |
| Agent Verification | Verify any agent's trust level before accepting their data |
| Benchmarking | Run standardized benchmark suites against your agent |
| SSE Event Stream | Real-time events (jobs, messages, heartbeats) via Server-Sent Events |

## Installation

```bash
# Using uv (recommended)
uv pip install jacs[hai]

# Or with pip
pip install jacs[hai]
```

The `[hai]` extra installs `httpx` and `httpx-sse` for HTTP and SSE support.

## Quick Start: Create and Register in One Step

The fastest way to get started. Creates a new JACS agent with cryptographic keys and registers it with HAI.ai:

```python
from jacs.hai import register_new_agent

result = register_new_agent(
    name="My Trading Bot",
    api_key="your-api-key",       # or set HAI_API_KEY env var
    key_algorithm="ed25519",      # or "pq2025" for post-quantum
    output_dir=".",               # saves jacs.config.json here
)

print(f"Agent ID: {result.agent_id}")
print(f"HAI signature: {result.hai_signature}")
print(f"Registration ID: {result.registration_id}")
```

This function does three things internally:
1. Calls `jacs.simple.create()` to generate keys and agent document
2. Calls `jacs.simple.load()` to load the new agent
3. Calls `HaiClient.register()` to register with HAI.ai

## Three-Level Trust Model

JACS agents have a trust level determined by independent verification checks:

| Level | Name | What It Proves |
|-------|------|----------------|
| 1 | **basic** | JACS self-signature is cryptographically valid |
| 2 | **domain** | DNS TXT record verification passed |
| 3 | **attested** | HAI.ai has registered and counter-signed the agent |

### Verify Another Agent

Before accepting messages, agreements, or transactions from another agent, verify their trust level:

```python
from jacs.hai import verify_agent

# Verify that sender meets your trust requirements
result = verify_agent(
    sender_agent_doc,    # JSON string or dict of the agent's JACS document
    min_level=2,         # require at least domain verification
    require_domain="example.com",  # optional: require specific domain
)

if result.valid:
    print(f"Verified: {result.level_name} (level {result.level})")
    print(f"Agent ID: {result.agent_id}")
    print(f"JACS valid: {result.jacs_valid}")
    print(f"DNS valid: {result.dns_valid}")
    print(f"HAI attested: {result.hai_attested}")
else:
    print(f"Rejected: {result.errors}")
```

`verify_agent()` checks all three levels and returns the highest achieved:

1. **Level 1**: Calls `jacs.simple.verify()` to check the JACS signature locally
2. **Level 2**: Calls `jacs.simple.verify_dns()` if a domain is available
3. **Level 3**: Queries `HaiClient.get_agent_attestation()` to check HAI.ai registration

## HaiClient Class

For advanced usage with an existing JACS agent:

```python
import jacs.simple as jacs
from jacs.hai import HaiClient

jacs.load("./jacs.config.json")
hai = HaiClient(timeout=30.0, max_retries=3)
```

### Test Connection

```python
if hai.testconnection("https://hai.ai"):
    print("HAI.ai is reachable")
```

Tries multiple health endpoints (`/api/v1/health`, `/health`, `/api/health`, `/`) with a short timeout.

### Register an Existing Agent

```python
# Preview what would be sent (dry run)
preview = hai.register("https://hai.ai", api_key="...", preview=True)
print(f"Endpoint: {preview.endpoint}")
print(f"Payload: {preview.payload_json}")

# Actually register
result = hai.register("https://hai.ai", api_key="...")
print(f"Registered: {result.agent_id}")
print(f"HAI signature: {result.hai_signature}")
```

### Check Registration Status

```python
status = hai.status("https://hai.ai", api_key="...")
if status.registered:
    print(f"Registered since {status.registered_at}")
    print(f"HAI signatures: {status.hai_signatures}")
```

### Run Benchmarks

```python
result = hai.benchmark(
    "https://hai.ai",
    api_key="...",
    suite="mediator",       # benchmark suite name
    timeout=120.0,          # benchmark timeout (default: 120s)
)

print(f"Score: {result.score}/100")
print(f"Passed: {result.passed}/{result.total}")
print(f"Duration: {result.duration_ms}ms")
```

Supports both synchronous and async (polling) benchmark execution. If the server returns a `job_id`, the client polls with exponential backoff until completion.

### SSE Event Stream

Connect to HAI.ai's real-time event stream for receiving jobs, messages, and heartbeats:

```python
# Generator-based usage
for event in hai.connect("https://hai.ai", api_key="..."):
    print(f"Event: {event.event_type}, Data: {event.data}")
    if event.event_type == "job":
        process_job(event.data)

# Or with callback
def handle_event(event):
    print(f"Received: {event.event_type}")

for event in hai.connect("https://hai.ai", "...", on_event=handle_event):
    pass
```

The connection auto-reconnects with exponential backoff (1s to 60s) on network errors. Disconnect gracefully:

```python
import threading

thread = threading.Thread(target=lambda: list(hai.connect(...)))
thread.start()

# Later
hai.disconnect()
thread.join()
```

## Module-Level Convenience Functions

For quick scripts, use the module-level functions that manage a global `HaiClient` instance:

```python
from jacs.hai import testconnection, register, status, benchmark, connect, disconnect

testconnection("https://hai.ai")
result = register("https://hai.ai", api_key="...")
status_result = status("https://hai.ai")
```

## Error Handling

All errors inherit from `HaiError`:

| Exception | When |
|-----------|------|
| `HaiError` | Base class for all HAI errors |
| `RegistrationError` | Registration fails, agent already registered, invalid document |
| `HaiConnectionError` | Server unreachable, timeout, SSL/TLS errors |
| `AuthenticationError` | Invalid or expired API key |
| `BenchmarkError` | Benchmark suite not found, job fails, timeout |
| `SSEError` | Stream disconnects, invalid event format |

```python
from jacs.hai import HaiClient, RegistrationError, AuthenticationError

try:
    result = hai.register("https://hai.ai", api_key="...")
except AuthenticationError:
    print("Invalid API key")
except RegistrationError as e:
    print(f"Registration failed: {e.message} (HTTP {e.status_code})")
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HAI_API_KEY` | Default API key (used when `api_key` parameter is not passed) |
| `HAI_KEYS_BASE_URL` | Base URL for HAI key distribution service |
| `JACS_KEY_RESOLUTION` | Key resolution order: `local`, `dns`, `hai` (comma-separated) |

## See Also

- [A2A Interoperability](a2a.md) -- agent discovery and artifact signing
- [MCP Integration](mcp.md) -- signed MCP transport
- [Security Model](../advanced/security.md) -- JACS cryptographic architecture
