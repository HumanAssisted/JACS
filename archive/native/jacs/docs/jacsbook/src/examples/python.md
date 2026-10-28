# Python Examples

These recipes use `JacsClient`. See [installation](../python/installation.md)
for the native package and platform requirements.

## Sign a tool result and reject tampering

```python
import json
from jacs.client import JacsClient

client = JacsClient.ephemeral()
signed = client.sign_message({"tool": "calculator", "answer": 42})
assert client.verify(signed.raw).valid

tampered = json.loads(signed.raw)
tampered["content"] = {"answer": 43}
assert not client.verify(tampered).valid
```

This identity exists only in memory. Before acting on a verified result, also
check the expected signer and your application's authorization policy.

## Persist an identity and signed document

```python
from pathlib import Path
from jacs.client import JacsClient

client = JacsClient.quickstart(name="publisher", domain="publisher.example.com")
signed = client.sign_message({"event": "report-ready", "report_id": "report-123"})
Path("report.json").write_text(signed.raw, encoding="utf-8")
received = Path("report.json").read_text(encoding="utf-8")
result = client.verify(received)
if not result.valid:
    raise ValueError(result.errors)
print(result.signer_id)
```

Quickstart creates encrypted `pq2025` keys or loads existing configuration.
Preserve its password through a host secret source or keychain; see
[password bootstrap](../getting-started/quick-start.md#native-password-bootstrap).

## Sign an existing file

```python
from jacs.client import JacsClient

client = JacsClient(config_path="./jacs.config.json")
signed = client.sign_file("report.pdf", embed=True)
assert client.verify(signed.raw).valid
```

Share the complete signed JSON. With `embed=False`, the envelope records the
file reference/hash; the receiver also needs the referenced bytes and an
external-file verification policy.

## Return signed content from an MCP tool

Install `jacs[mcp]`, then run this as an ordinary stdio MCP server:

```python
from fastmcp import FastMCP
from jacs.client import JacsClient

client = JacsClient.quickstart(name="tools", domain="tools.example.com")
mcp = FastMCP("Signed tools")

@mcp.tool()
def calculate() -> dict:
    """Return a signed calculation result."""
    signed = client.sign_message({"answer": 6 * 7})
    return {"signed_document": signed.raw}

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

This signs result content; it does not authenticate the transport or caller.
The receiver verifies `signed_document` under its own trust policy.
For the primary JACS tool server use `jacs mcp`; for custom native tools and
the separate signed local HTTP transport, see [Python MCP](../python/mcp.md).

## More recipes

- [Framework adapters](../python/adapters.md): LangChain, LangGraph, FastAPI and Anthropic.
- [A2A serving](../guides/a2a-serve.md): discovery documents and trust requirements.
- [DID integration](../integrations/did.md): identity binding without a blockchain.
- [Simplified API](../python/simple-api.md): request authentication, signed events and agreement inspection.
- [Native API reference](../python/api.md): exact low-level arguments.
