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
- `strict=True` is about config loading and failure behavior, not an opt-in to security

## 1. Secure A FastMCP Server

The shortest path is the factory:

```python
from jacs.mcp import create_jacs_mcp_server

mcp = create_jacs_mcp_server("My Server", "./jacs.config.json")

@mcp.tool()
def hello(name: str) -> str:
    return f"Hello, {name}!"
```

If you already have a `FastMCP` instance:

```python
from fastmcp import FastMCP
from jacs.mcp import JACSMCPServer

mcp = JACSMCPServer(FastMCP("Secure Server"), "./jacs.config.json")
```

## 2. Secure A FastMCP Client

```python
from jacs.mcp import JACSMCPClient

client = JACSMCPClient("http://localhost:8000/sse", "./jacs.config.json")

async with client:
    result = await client.call_tool("hello", {"name": "World"})
```

To allow unsigned fallback explicitly:

```python
client = JACSMCPClient(
    "http://localhost:8000/sse",
    "./jacs.config.json",
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

## Example Paths In This Repo

- `jacspy/examples/mcp/server.py`
- `jacspy/examples/mcp/client.py`
- `jacspy/examples/mcp_server.py`
- `jacspy/tests/test_adapters_mcp.py`

## When To Use Adapters Instead

Choose [Python Framework Adapters](adapters.md) instead of MCP when:

- the model and tools already live in the same Python process
- you only need signed LangChain, LangGraph, CrewAI, or FastAPI boundaries
- you do not need MCP clients to connect from outside the app
