# Framework Adapter Attestation Guide

JACS provides Python framework adapters for LangChain, FastAPI, and
Anthropic. Each adapter can be configured to produce attestations (not just
signatures) for tool calls, API requests, and agent actions.

## Common Patterns

All framework adapters share these attestation patterns:

### Default Claims

When `attest=True` is enabled on any adapter, it automatically includes
these default claims:

```python
[
    {"name": "framework", "value": "langchain", "confidence": 1.0},
    {"name": "tool_name", "value": "my_tool", "confidence": 1.0},
    {"name": "timestamp", "value": "2026-03-04T...", "confidence": 1.0},
]
```

### Custom Claims

Add your own claims to any adapter call:

```python
extra_claims = [
    {"name": "reviewed_by", "value": "human", "confidence": 0.95},
    {"name": "approved", "value": True, "assuranceLevel": "verified"},
]
```

### Evidence Attachment

Attach evidence references from external systems:

```python
evidence = [
    {
        "kind": "custom",
        "digests": {"sha256": "abc123..."},
        "uri": "https://scanner.example.com/report/456",
        "collectedAt": "2026-03-04T00:00:00Z",
        "verifier": {"name": "security-scanner", "version": "2.0"},
    }
]
```

## LangChain

### Enabling Attestation on Tool Calls

Use `jacs_wrap_tool_call` with `attest=True`:

```python
from jacs.adapters.langchain import jacs_wrap_tool_call
from jacs.client import JacsClient

client = JacsClient.quickstart()

# Wrap a tool call with attestation
@jacs_wrap_tool_call(client, attest=True)
def my_tool(query: str) -> str:
    return f"Result for: {query}"

# The tool call now produces a signed attestation
result = my_tool("test query")
# result.attestation contains the signed attestation document
```

### Using the signed_tool Decorator

```python
from jacs.adapters.langchain import signed_tool

@signed_tool(client, attest=True, claims=[
    {"name": "data_source", "value": "internal_db", "confidence": 1.0}
])
def lookup_customer(customer_id: str) -> dict:
    return {"name": "Alice", "status": "active"}
```

### With LangChain Chains

```python
from jacs.adapters.langchain import with_jacs_signing

# Wrap an entire chain with attestation
signed_chain = with_jacs_signing(
    chain=my_chain,
    client=client,
    attest=True,
)
```

## FastAPI

### Attestation Middleware

The `JacsMiddleware` can be configured to produce attestations for all
responses:

```python
from fastapi import FastAPI
from jacs.adapters.fastapi import JacsMiddleware
from jacs.client import JacsClient

app = FastAPI()
client = JacsClient.quickstart()

app.add_middleware(
    JacsMiddleware,
    client=client,
    attest=True,  # Produce attestations, not just signatures
    default_claims=[
        {"name": "service", "value": "my-api", "confidence": 1.0},
    ],
)
```

### Per-Route Attestation

Use `jacs_route` for route-level attestation control:

```python
from jacs.adapters.fastapi import jacs_route

@app.post("/approve")
@jacs_route(client, attest=True, claims=[
    {"name": "action", "value": "approve", "confidence": 1.0},
    {"name": "requires_review", "value": True},
])
async def approve_request(request_id: str):
    return {"approved": True, "request_id": request_id}
```

The response headers will include `X-JACS-Attestation-Id` with the
attestation document ID.

## Anthropic

### Tool Hook Attestation

The Anthropic adapter hooks into Claude tool calls to produce attestations:

```python
from jacs.adapters.anthropic import signed_tool, JacsToolHook
from jacs.client import JacsClient

client = JacsClient.quickstart()

@signed_tool(client, attest=True)
def search_database(query: str) -> str:
    return "Found 3 results"

# Or use the hook class for more control
hook = JacsToolHook(
    client=client,
    attest=True,
    default_claims=[
        {"name": "model", "value": "claude-4.6"},
        {"name": "tool_use_id", "value": "auto"},  # Auto-filled from tool call
    ],
)
```

### With the Anthropic SDK

```python
import anthropic
from jacs.adapters.anthropic import JacsToolHook

client = anthropic.Anthropic()
jacs_client = JacsClient.quickstart()
hook = JacsToolHook(jacs_client, attest=True)

# Register tools with JACS attestation
tools = hook.wrap_tools([
    {
        "name": "get_weather",
        "description": "Get weather for a location",
        "input_schema": {"type": "object", "properties": {"location": {"type": "string"}}},
    }
])
```

## Verifying Framework Attestations

All framework attestations use the same JACS verification API:

```python
# Verify any attestation (from any framework adapter)
result = client.verify_attestation(attestation_json, full=True)
print(f"Valid: {result['valid']}")
print(f"Framework: {result['claims'][0]['value']}")
print(f"Evidence: {result.get('evidence', [])}")
```

## Strict vs. Permissive Mode

All adapters respect the `strict` flag on `JacsClient`:

- **Permissive (default):** Signing/attestation failures log warnings but
  do not block the operation
- **Strict:** Signing/attestation failures raise exceptions and block
  the operation

```python
# Strict mode: attestation failure = operation failure
client = JacsClient.quickstart(strict=True)

# Permissive mode: attestation failure = warning + continue
client = JacsClient.quickstart(strict=False)
```
