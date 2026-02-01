# JACS Python Library

Python bindings for JACS (JSON AI Communication Standard) - cryptographic signing and verification for AI agents.

```bash
pip install jacs
```

## Quick Start (Simplified API)

The simplified API gets you signing in under 2 minutes:

```python
import jacs.simple as jacs

# Load your agent
agent = jacs.load("./jacs.config.json")

# Sign a message
signed = jacs.sign_message("Hello, World!")
print(f"Signed by: {signed.signer_id}")

# Verify it
result = jacs.verify(signed.raw_json)
print(f"Valid: {result.valid}")

# Sign a file
signed_file = jacs.sign_file("document.pdf", embed=True)
```

## Core Operations

The simplified API provides 6 core operations:

| Operation | Description |
|-----------|-------------|
| `create()` | Create a new agent with cryptographic keys |
| `load()` | Load an existing agent from config |
| `verify_self()` | Verify the loaded agent's integrity |
| `sign_message()` | Sign a text message or JSON data |
| `sign_file()` | Sign a file with optional embedding |
| `verify()` | Verify any signed document |

## Type Definitions

```python
from jacs import AgentInfo, SignedDocument, VerificationResult

# All return types are dataclasses with clear fields
agent: AgentInfo = jacs.load()
signed: SignedDocument = jacs.sign_message("hello")
result: VerificationResult = jacs.verify(signed.raw_json)
```

## MCP Integration

For AI tool servers using the Model Context Protocol:

```python
from fastmcp import FastMCP
import jacs.simple as jacs

mcp = FastMCP("My Server")
jacs.load("./jacs.config.json")

@mcp.tool()
def signed_hello(name: str) -> dict:
    signed = jacs.sign_message(f"Hello, {name}!")
    return {"response": signed.raw_json}
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

JACS supports Google's Agent-to-Agent (A2A) protocol:

```python
from jacs.a2a import JACSA2AIntegration

a2a = JACSA2AIntegration("jacs.config.json")
agent_card = a2a.export_agent_card(agent_data)
wrapped = a2a.wrap_artifact_with_provenance(artifact, "task")
```

## Installation

```bash
# Basic installation
pip install jacs

# With MCP support
pip install jacs[mcp]
```

## Examples

See the [examples/](./examples/) directory:
- `quickstart.py` - Basic signing and verification
- `sign_file.py` - File signing with embeddings
- `mcp_server.py` - Authenticated MCP server
- `p2p_exchange.py` - Peer-to-peer trust establishment

## Development

```bash
# Setup
uv venv && source .venv/bin/activate
uv pip install maturin

# Build
maturin develop

# Test
pytest tests/
```

## Documentation

- [JACS Book](https://humanassisted.github.io/JACS) - Full documentation
- [API Reference](https://humanassisted.github.io/JACS/api/python) - Python API docs
- [Migration Guide](https://humanassisted.github.io/JACS/migration) - Upgrading from v0.4.x
