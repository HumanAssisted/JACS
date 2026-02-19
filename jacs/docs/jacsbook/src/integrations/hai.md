# HAI.ai Platform Integration

The HAI SDK (`haisdk`) provides Python, Node.js, and Go clients for integrating JACS agents with the HAI.ai platform. This is the infrastructure that connects locally-created JACS agents to the global trust network.

> **Note:** The HAI integration modules previously lived inside the JACS language bindings (`jacspy/python/jacs/hai.py`, `jacsnpm/hai.ts`, `jacsgo/hai.go`). They have been migrated to the standalone **[haisdk](https://github.com/HumanAssisted/haisdk)** repository.

## What HAI.ai Provides

| Capability | Description |
|------------|-------------|
| Agent Registration | Register your JACS agent to get a HAI.ai counter-signature |
| Trust Attestation | Three-level trust model (basic, domain, attested) |
| Agent Verification | Verify any agent's trust level before accepting their data |
| Benchmarking | Run standardized benchmark suites against your agent |
| Email | Send/receive signed email via your-agent@hai.ai address |

## Installation

```bash
# Python (using uv)
uv pip install haisdk

# Node.js
npm install @hai.ai/sdk

# Go
go get github.com/HumanAssisted/haisdk-go
```

## Quick Start: Register and Verify

The SDK uses JACS cryptographic identity for authentication — no API keys needed.

```python
from jacs.hai.client import HaiClient

client = HaiClient()
result = client.register("https://hai.ai")

print(f"Agent ID: {result.agent_id}")
print(f"HAI signature: {result.hai_signature}")
print(f"Registration ID: {result.registration_id}")
```

See the [haisdk examples](https://github.com/HumanAssisted/haisdk) for full quickstarts including A2A protocol integration.

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
from jacs.hai.client import verify_agent

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

## HaiClient Class

```python
from jacs.hai.client import HaiClient

hai = HaiClient(timeout=30.0, max_retries=3)
```

### Test Connection

```python
if hai.testconnection("https://hai.ai"):
    print("HAI.ai is reachable")
```

### Register

```python
# Preview what would be sent (dry run)
preview = hai.register("https://hai.ai", preview=True)
print(f"Endpoint: {preview.endpoint}")

# Actually register
result = hai.register("https://hai.ai")
print(f"Registered: {result.agent_id}")
```

### Check Registration Status

```python
status = hai.status("https://hai.ai")
if status.registered:
    print(f"Registered since {status.registered_at}")
    print(f"HAI signatures: {status.hai_signatures}")
```

### Run Benchmarks

```python
result = hai.benchmark("https://hai.ai")

print(f"Score: {result.score}/100")
print(f"Passed: {result.passed}/{result.total}")
```

### SSE Event Stream

```python
for event in hai.connect("https://hai.ai"):
    print(f"Event: {event.event_type}, Data: {event.data}")
    if event.event_type == "job":
        process_job(event.data)
```

## Error Handling

All errors inherit from `HaiError`:

| Exception | When |
|-----------|------|
| `HaiError` | Base class for all HAI errors |
| `RegistrationError` | Registration fails, agent already registered, invalid document |
| `HaiConnectionError` | Server unreachable, timeout, SSL/TLS errors |
| `HaiAuthError` | Invalid JACS signature or expired timestamp |
| `BenchmarkError` | Benchmark suite not found, job fails, timeout |

```python
from jacs.hai.errors import HaiAuthError, RegistrationError

try:
    result = hai.register("https://hai.ai")
except HaiAuthError:
    print("JACS authentication failed")
except RegistrationError as e:
    print(f"Registration failed: {e.message} (HTTP {e.status_code})")
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `JACS_KEYS_BASE_URL` | Preferred base URL for agent key lookups (defaults to `https://hai.ai`) |
| `JACS_REGISTRY_URL` | Preferred base URL for registry verification lookups |
| `JACS_KEY_RESOLUTION` | Key resolution order: `local`, `dns`, `registry` |

### External Key Lookup Routes

For external JACS agents, HAI exposes key lookup routes under the `https://hai.ai` base URL:

- `GET /jacs/v1/agents/{jacs_id}/keys/{version}` - lookup by agent id + version (`latest` supported)
- `GET /jacs/v1/keys/by-hash/{public_key_hash}` - lookup by `sha256:<hex>` public key hash (prefix optional)

## See Also

- [A2A Interoperability](a2a.md) -- agent discovery and artifact signing
- [Security Model](../advanced/security.md) -- JACS cryptographic architecture
