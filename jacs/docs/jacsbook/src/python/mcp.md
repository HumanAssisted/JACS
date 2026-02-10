# MCP Integration

JACS provides seamless integration with the Model Context Protocol (MCP), enabling cryptographically signed and verified communication between AI agents and MCP servers. This integration ensures that all tool calls, resource requests, and prompt interactions are authenticated and tamper-proof.

## 5-Minute Quickstart

Sign it. Prove it. -- every MCP tool call, automatically.

### Signed MCP Server

```python
# 1. Install
# pip install jacs fastmcp

# 2. Create a signed MCP server in one call
from jacs.mcp import create_jacs_mcp_server

mcp = create_jacs_mcp_server("My Server", "./jacs.config.json")

# 3. Define tools as usual -- responses are auto-signed
@mcp.tool()
def hello(name: str) -> str:
    return f"Hello, {name}!"

mcp.run()
```

### Signed MCP Client

```python
# 1. Connect to a JACS-enabled server
from jacs.mcp import JACSMCPClient

client = JACSMCPClient("http://localhost:8000/sse", "./jacs.config.json")

# 2. Calls are signed outgoing, verified incoming
async with client:
    result = await client.call_tool("hello", {"name": "World"})
```

Both `JACSMCPServer` and `JACSMCPClient` support `strict=True` to reject unsigned messages, or permissive mode (default) to log and pass through.

---

## Overview

JACS MCP integration provides:
- **Cryptographic Authentication**: All MCP messages are signed and verified
- **FastMCP Support**: Native integration with FastMCP servers
- **HTTP & SSE Transports**: Support for Server-Sent Events transport
- **Transparent Security**: Existing MCP code works with minimal changes

## Detailed Setup

### Basic MCP Server with JACS

```python
import jacs
import os
from pathlib import Path
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP
import uvicorn

# Setup JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.config.json"

# Initialize JACS agent
agent = jacs.JacsAgent()
agent.load(str(jacs_config_path))

# Create FastMCP server with JACS authentication
mcp = JACSMCPServer(FastMCP("Authenticated Echo Server"))

@mcp.tool()
def echo_tool(text: str) -> str:
    """Echo the input text with server prefix"""
    return f"SERVER SAYS: {text}"

@mcp.resource("echo://static")
def echo_resource() -> str:
    return "Echo!"

@mcp.prompt("echo")
def echo_prompt(text: str) -> str:
    return f"Echo prompt: {text}"

# Get the ASGI app with JACS middleware
sse_app_with_middleware = mcp.sse_app()

if __name__ == "__main__":
    print("Starting JACS-enabled MCP server...")
    uvicorn.run(sse_app_with_middleware, host="localhost", port=8000)
```

### Basic MCP Client with JACS

```python
import asyncio
import os
from pathlib import Path
import jacs
from jacs.mcp import JACSMCPClient

# Setup JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.client.config.json"

# Initialize JACS agent
agent = jacs.JacsAgent()
agent.load(str(jacs_config_path))

async def main():
    server_url = "http://localhost:8000/sse"

    try:
        client = JACSMCPClient(server_url)

        async with client:
            # Call authenticated tool
            result = await client.call_tool("echo_tool", {
                "text": "Hello from authenticated client!"
            })
            print(f"Tool result: {result}")

            # Read authenticated resource
            resource = await client.read_resource("echo://static")
            print(f"Resource: {resource}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

## How It Works

### JACSMCPServer

The `JACSMCPServer` wrapper adds JACS middleware to a FastMCP server:

1. **Incoming Requests**: Intercepts JSON-RPC requests and verifies them using `jacs.verify_request()`
2. **Outgoing Responses**: Signs JSON-RPC responses using `jacs.sign_response()`

```python
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP

# Create FastMCP server
base_server = FastMCP("My Server")

# Wrap with JACS authentication
authenticated_server = JACSMCPServer(base_server)

# All decorators work normally
@authenticated_server.tool()
def my_tool(data: str) -> str:
    return f"Processed: {data}"

# Get ASGI app with JACS middleware
app = authenticated_server.sse_app()
```

### JACSMCPClient

The `JACSMCPClient` wrapper adds interceptors to a FastMCP client:

1. **Outgoing Messages**: Signs messages using `jacs.sign_request()`
2. **Incoming Messages**: Verifies messages using `jacs.verify_response()`

```python
from jacs.mcp import JACSMCPClient

client = JACSMCPClient("http://localhost:8000/sse")

async with client:
    result = await client.call_tool("my_tool", {"data": "test"})
```

## Configuration

### JACS Configuration File

Create a `jacs.config.json` file for your server and client:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_agent_id_and_version": "your-agent-id:version",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_agent_private_key_filename": "private.pem",
  "jacs_agent_public_key_filename": "public.pem",
  "jacs_data_directory": "./jacs_data",
  "jacs_default_storage": "fs",
  "jacs_key_directory": "./jacs_keys"
}
```

### Initializing the Agent

Before using MCP integration, initialize your JACS agent:

```python
import jacs

# Create and load agent
agent = jacs.JacsAgent()
agent.load("./jacs.config.json")

# Agent is now ready for MCP operations
```

## Integration Patterns

### FastMCP with JACS Middleware

```python
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP
import jacs

# Initialize JACS
agent = jacs.JacsAgent()
agent.load("./jacs.config.json")

# Create and wrap server
server = FastMCP("My Server")
authenticated_server = JACSMCPServer(server)

@authenticated_server.tool()
def secure_tool(input_data: str) -> str:
    """A tool that processes signed input"""
    return f"Securely processed: {input_data}"

# Run server
if __name__ == "__main__":
    import uvicorn
    app = authenticated_server.sse_app()
    uvicorn.run(app, host="localhost", port=8000)
```

### Manual Request/Response Signing

For custom integrations, you can use the module-level functions directly:

```python
import jacs

# Initialize agent first
agent = jacs.JacsAgent()
agent.load("./jacs.config.json")

# Sign a request
signed_request = jacs.sign_request({
    "method": "tools/call",
    "params": {"name": "my_tool", "arguments": {"data": "test"}}
})

# Verify a response
verified_response = jacs.verify_response(signed_response_string)
payload = verified_response.get("payload")
```

## Error Handling

### Common Errors

```python
import jacs
from jacs.mcp import JACSMCPClient

async def robust_mcp_client():
    try:
        agent = jacs.JacsAgent()
        agent.load("./jacs.config.json")

        client = JACSMCPClient("http://localhost:8000/sse")
        async with client:
            result = await client.call_tool("my_tool", {"data": "test"})
            return result

    except FileNotFoundError as e:
        print(f"Configuration file not found: {e}")

    except ConnectionError as e:
        print(f"MCP connection failed: {e}")

    except Exception as e:
        print(f"Unexpected error: {e}")
```

### Debugging

Enable logging to debug authentication issues:

```python
import logging

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG)

# Your MCP code here...
```

## Production Deployment

### Security Best Practices

1. **Key Management**: Store private keys securely
2. **Environment Variables**: Use environment variables for sensitive paths
3. **Network Security**: Use TLS for network transport
4. **Key Rotation**: Implement key rotation policies

```python
import os
import jacs

# Production initialization
config_path = os.getenv("JACS_CONFIG_PATH", "/etc/jacs/config.json")

agent = jacs.JacsAgent()
agent.load(config_path)
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application
COPY . .

# Create secure key directory
RUN mkdir -p /secure/keys && chmod 700 /secure/keys

# Set environment variables
ENV JACS_CONFIG_PATH=/app/jacs.config.json

# Run MCP server
CMD ["python", "mcp_server.py"]
```

## Testing

### Unit Testing MCP Tools

```python
import pytest
import jacs
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import FastMCPTransport

@pytest.fixture
def jacs_agent():
    agent = jacs.JacsAgent()
    agent.load("./test.config.json")
    return agent

@pytest.fixture
def jacs_mcp_server(jacs_agent):
    server = FastMCP("Test Server")
    return JACSMCPServer(server)

async def test_authenticated_tool(jacs_mcp_server):
    @jacs_mcp_server.tool()
    def echo(text: str) -> str:
        return f"Echo: {text}"

    # Test the tool directly
    result = echo("test")
    assert "test" in result
```

## API Reference

### JACSMCPServer(mcp_server)

Wraps a FastMCP server with JACS authentication middleware.

**Parameters:**
- `mcp_server`: A FastMCP server instance

**Returns:** The wrapped server with JACS middleware

**Example:**
```python
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP

server = FastMCP("My Server")
authenticated = JACSMCPServer(server)
app = authenticated.sse_app()
```

### JACSMCPClient(url, **kwargs)

Creates a FastMCP client with JACS authentication interceptors.

**Parameters:**
- `url`: The MCP server SSE endpoint URL
- `**kwargs`: Additional arguments passed to the FastMCP Client

**Returns:** A FastMCP Client with JACS interceptors

**Example:**
```python
from jacs.mcp import JACSMCPClient

client = JACSMCPClient("http://localhost:8000/sse")
async with client:
    result = await client.call_tool("my_tool", {"arg": "value"})
```

### Module Functions

These functions are used internally by the MCP integration:

- `jacs.sign_request(data)` - Sign a request payload
- `jacs.verify_request(data)` - Verify an incoming request
- `jacs.sign_response(data)` - Sign a response payload
- `jacs.verify_response(data)` - Verify an incoming response

## Next Steps

- **[FastMCP Integration](mcp.md)** - Advanced FastMCP patterns
- **[API Reference](api.md)** - Complete API documentation
- **[Examples](../examples/python.md)** - More complex examples
