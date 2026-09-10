# MCP Integration (Python)

Python exposes two different MCP stories:

1. **Secure a local FastMCP transport** with `jacs.mcp`
2. **Expose JACS operations as MCP tools** with `jacs.adapters.mcp`

Use the first when you already have an MCP server or client. Use the second when you want the model to call JACS signing, agreement, A2A, or trust helpers as normal MCP tools.

## What Is Supported

- Local FastMCP server wrapping with `JACSMCPServer`
- Local FastMCP client wrapping with `JACSMCPClient`
- One-line server creation with `create_jacs_mcp_server()`
- FastMCP tool registration with `register_jacs_tools()`, `register_a2a_tools()`, and `register_trust_tools()`

## Important Constraints

- `JACSMCPClient`, `JACSMCPServer`, and `jacs_call()` enforce **loopback-only** URLs
- Unsigned fallback is **disabled by default**
- Clients must pin the expected server agent ID; servers must allowlist client agent IDs
- `stdio` is rejected because it bypasses the HTTP signing middleware
- JSON POST and response bodies default to a 2 MiB hard limit (`JACS_MCP_MAX_MESSAGE_BYTES`)
- `strict=True` is about config loading and failure behavior, not an opt-in to security

A valid signature proves possession of a key, not that the signer is the intended
peer. The peer-ID policy below is what binds that proof to your deployment. An
optional `expected_peer_public_key_hash` also pins one exact server key.
On the server, the agent-ID allowlist is combined with JACS trust/key
resolution; operators must maintain rotation and revocation policy for those
allowed identities.

## 1. Secure A FastMCP Server

The shortest path is the factory:

```python
from jacs.mcp import create_jacs_mcp_server

mcp = create_jacs_mcp_server(
    "My Server",
    "./jacs.config.json",
    allowed_peer_agent_ids=["CLIENT_AGENT_ID"],
)

@mcp.tool()
def hello(name: str) -> str:
    return f"Hello, {name}!"

mcp.run(transport="sse")
```

If you already have a `FastMCP` instance:

```python
from fastmcp import FastMCP
from jacs.mcp import JACSMCPServer

mcp = JACSMCPServer(
    FastMCP("Secure Server"),
    "./jacs.config.json",
    allowed_peer_agent_ids=["CLIENT_AGENT_ID"],
)

app = mcp.http_app(transport="sse")
```

## 2. Secure A FastMCP Client

```python
from jacs.mcp import JACSMCPClient

client = JACSMCPClient(
    "http://localhost:8000/sse",
    "./jacs.config.json",
    expected_peer_agent_id="SERVER_AGENT_ID",
    # Optional stronger rotation policy:
    # expected_peer_public_key_hash="SERVER_PUBLIC_KEY_HASH",
)

async with client:
    result = await client.call_tool("hello", {"name": "World"})
```

To accept any valid signer without authenticating which peer signed, use the
separate dangerous compatibility switch:

```python
client = JACSMCPClient(
    "http://localhost:8000/sse",
    "./jacs.config.json",
    allow_any_verified_peer=True,
)
```

This is proof-of-possession only and is not peer authentication. To allow fully
unsigned fallback explicitly:

```python
client = JACSMCPClient(
    "http://localhost:8000/sse",
    "./jacs.config.json",
    expected_peer_agent_id="SERVER_AGENT_ID",
    allow_unsigned_fallback=True,
)
```

## 3. Register JACS As MCP Tools

This is the better fit when the model should be able to ask for signatures, agreements, A2A cards, or trust-store operations directly.

```python
from fastmcp import FastMCP
from jacs.client import JacsClient
from jacs.adapters.mcp import (
    register_jacs_tools,
    register_a2a_tools,
    register_trust_tools,
)

client = JacsClient.quickstart(name="mcp-agent", domain="mcp.local")
mcp = FastMCP("JACS Tools")

register_jacs_tools(mcp, client=client)
register_a2a_tools(mcp, client=client)
register_trust_tools(mcp, client=client)
```

The core tool set includes document signing, verification, agreements, audit, and agent-info helpers. The A2A and trust helpers are opt-in registrations.

## Useful Helper APIs

From `jacs.mcp`:

- `jacs_tool` to sign a specific tool's response
- `jacs_middleware()` for explicit Starlette middleware
- `jacs_call()` for one-off authenticated local MCP calls

`jacs_tool`, `jacs_middleware()`, and `JacsSSETransport` refuse unsigned output
when no agent is loaded or signing fails. The dangerous
`allow_unsigned_fallback=True` option restores legacy passthrough explicitly.
Authenticated transport messages use a schema-valid JSON-RPC carrier whose
`params.envelope` is a complete portable-v2 JACS document. Requests receive a
fresh unpredictable wire ID per session, and responses with unknown IDs fail
closed, preventing a signed response from being transplanted into another
client session.

## Example Paths In This Repo

- `jacspy/examples/mcp/server.py`
- `jacspy/examples/mcp/client.py`
- `jacspy/examples/mcp_server.py`
- `jacspy/tests/test_adapters_mcp.py`

## When To Use Adapters Instead

Choose [Python Framework Adapters](adapters.md) instead of MCP when:

- the model and tools already live in the same Python process
- you only need signed LangChain, LangGraph, or FastAPI boundaries
- you do not need MCP clients to connect from outside the app
