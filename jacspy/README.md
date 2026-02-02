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

The simplified API provides 8 core operations:

| Operation | Description |
|-----------|-------------|
| `create()` | Create a new agent with cryptographic keys |
| `load()` | Load an existing agent from config |
| `verify_self()` | Verify the loaded agent's integrity |
| `update_agent()` | Update the agent document with new data |
| `update_document()` | Update an existing document with new data |
| `sign_message()` | Sign a text message or JSON data |
| `sign_file()` | Sign a file with optional embedding |
| `verify()` | Verify any signed document |

## Type Definitions

```python
from jacs import AgentInfo, SignedDocument, VerificationResult

# All return types are dataclasses with clear fields
agent: AgentInfo = jacs.load()
signed: SignedDocument = jacs.sign_message({"data": "hello"})
result: VerificationResult = jacs.verify(signed.raw)
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

JACS supports Google's Agent-to-Agent (A2A) protocol:

```python
from jacs.a2a import JACSA2AIntegration

a2a = JACSA2AIntegration("jacs.config.json")
agent_card = a2a.export_agent_card(agent_data)
wrapped = a2a.wrap_artifact_with_provenance(artifact, "task")
```

## HAI.ai Integration

HAI.ai is a platform for agent-to-agent agreements and conflict resolution, providing cryptographic attestation of agent capabilities.

### Quick Registration

```python
from jacs.hai import HaiClient
import jacs.simple as jacs

# Load your JACS agent
jacs.load("./jacs.config.json")

# Connect to HAI.ai
hai = HaiClient()

# Test connection
if hai.testconnection("https://hai.ai"):
    # Register your agent
    result = hai.register("https://hai.ai", api_key="your-api-key")
    print(f"Registered: {result.agent_id}")
```

### Prerequisites

- JACS agent created (see [Quick Start](#quick-start-simplified-api))
- API key from HAI.ai (visit https://hai.ai/developers)

### Available Methods

| Method | Description |
|--------|-------------|
| `testconnection()` | Test HAI.ai connectivity |
| `register()` | Register agent with HAI.ai |
| `benchmark()` | Run benchmark suite |
| `connect()` | Connect to SSE event stream |

### Examples

- `examples/hai_quickstart.py` - 5-minute quickstart
- `examples/register_with_hai.py` - Complete registration example

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
