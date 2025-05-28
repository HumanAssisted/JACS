# MCP Integration

JACS provides seamless integration with the Model Context Protocol (MCP), enabling cryptographically signed and verified communication between AI agents and MCP servers. This integration ensures that all tool calls, resource requests, and prompt interactions are authenticated and tamper-proof.

## Overview

JACS MCP integration provides:
- **Cryptographic Authentication**: All MCP messages are signed and verified
- **FastMCP Support**: Native integration with FastMCP servers
- **HTTP & SSE Transports**: Support for both HTTP and Server-Sent Events
- **Transparent Security**: Existing MCP code works with minimal changes

## Quick Start

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

# Set password for private key
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "your_secure_password"

# Initialize JACS
jacs.load(str(jacs_config_path))

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

# Set password for private key
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "your_secure_password"

# Initialize JACS
jacs.load(str(jacs_config_path))

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

## Configuration

### JACS Configuration File

Create a `jacs.config.json` file for your server and client:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_agent_id_and_version": "your-agent-id:version",
  "jacs_agent_key_algorithm": "RSA-PSS",
  "jacs_agent_private_key_filename": "private.pem.enc",
  "jacs_agent_public_key_filename": "public.pem",
  "jacs_data_directory": "./jacs",
  "jacs_default_storage": "fs",
  "jacs_key_directory": "./jacs_keys",
  "jacs_private_key_password": "your_password",
  "jacs_use_security": "true"
}
```

### Key Generation

Generate cryptographic keys for your agents:

```python
import jacs

# Load configuration
jacs.load("jacs.config.json")

# Generate keys (only needed once per agent)
agent = jacs.Agent()
agent.generate_keys()

# Create agent document
agent_doc = agent.create_agent({
    "name": "MCP Server Agent",
    "description": "Agent for MCP server authentication",
    "type": "mcp_server"
})

print(f"Agent ID: {agent_doc['jacsId']}")
```

## Integration Patterns

### 1. FastMCP with JACS Middleware

The `JACSMCPServer` wrapper automatically adds cryptographic middleware:

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
```

### 2. HTTP MCP with Manual Signing

For HTTP-based MCP servers, you can manually sign responses:

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import jacs

app = FastAPI()

@app.post("/api/tool")
async def call_tool(request: Request):
    # Verify incoming request
    body = await request.body()
    verified_data = jacs.verify_request(body.decode())
    
    # Process the tool call
    result = {"message": "Tool executed", "data": verified_data}
    
    # Sign and return response
    signed_response = jacs.sign_response(result)
    return JSONResponse(content=signed_response)
```

### 3. Standard MCP with Stdio

For stdio-based MCP servers:

```python
from mcp.server.fastmcp import FastMCP
import jacs

# Initialize JACS
jacs.load("jacs.config.json")

mcp = FastMCP("Stdio Server")

@mcp.tool()
def secure_tool(input_data: str) -> str:
    """A tool that processes signed input"""
    # Input is automatically verified by JACS middleware
    return f"Securely processed: {input_data}"

if __name__ == "__main__":
    # Run with stdio transport
    mcp.run()
```

## Advanced Usage

### Custom Authentication Logic

```python
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP
import jacs

class CustomJACSServer:
    def __init__(self, base_server: FastMCP):
        self.base_server = base_server
        self.setup_middleware()
    
    def setup_middleware(self):
        # Custom verification logic
        @self.base_server.middleware("http")
        async def custom_auth(request, call_next):
            # Custom JACS verification
            if self.should_verify(request):
                body = await request.body()
                verified = jacs.verify_request(body.decode())
                # Update request with verified data
            
            response = await call_next(request)
            
            # Custom signing logic
            if self.should_sign(response):
                # Sign response
                pass
            
            return response
    
    def should_verify(self, request) -> bool:
        # Custom logic for when to verify
        return True
    
    def should_sign(self, response) -> bool:
        # Custom logic for when to sign
        return True
```

### Multi-Agent Authentication

```python
import jacs
from jacs.mcp import JACSMCPServer, JACSMCPClient

# Server side - configure for multiple agents
server_config = {
    "trusted_agents": ["agent1-id", "agent2-id"],
    "require_signatures": True
}

mcp_server = JACSMCPServer(FastMCP("Multi-Agent Server"))

@mcp_server.tool()
def multi_agent_tool(data: str, agent_context: dict) -> str:
    """Tool that can be called by multiple authenticated agents"""
    agent_id = agent_context.get("agent_id")
    return f"Agent {agent_id} processed: {data}"

# Client side - each agent uses its own keys
client1 = JACSMCPClient("http://server:8000/sse")
client2 = JACSMCPClient("http://server:8000/sse")
```

## Error Handling

### Common JACS MCP Errors

```python
import jacs
from jacs.mcp import JACSMCPClient

async def robust_mcp_client():
    try:
        client = JACSMCPClient("http://localhost:8000/sse")
        async with client:
            result = await client.call_tool("my_tool", {"data": "test"})
            return result
            
    except jacs.CryptographicError as e:
        print(f"Signature verification failed: {e}")
        # Handle invalid signatures
        
    except jacs.ConfigurationError as e:
        print(f"JACS configuration error: {e}")
        # Handle missing keys or config
        
    except ConnectionError as e:
        print(f"MCP connection failed: {e}")
        # Handle network issues
        
    except Exception as e:
        print(f"Unexpected error: {e}")
```

### Debugging Authentication Issues

```python
import logging
import jacs

# Enable detailed JACS logging
logging.basicConfig(level=logging.DEBUG)
jacs_logger = logging.getLogger("jacs")
jacs_logger.setLevel(logging.DEBUG)

# Enable MCP debugging
mcp_logger = logging.getLogger("mcp")
mcp_logger.setLevel(logging.DEBUG)

# Your MCP code here...
```

## Production Deployment

### Security Best Practices

1. **Key Management**: Store private keys securely
2. **Environment Variables**: Use environment variables for passwords
3. **Network Security**: Use TLS for network transport
4. **Key Rotation**: Implement key rotation policies

```python
import os
import jacs

# Production configuration
config = {
    "jacs_key_directory": os.getenv("JACS_KEY_DIR", "/secure/keys"),
    "jacs_private_key_password": os.getenv("JACS_KEY_PASSWORD"),
    "jacs_use_security": "true",
    "jacs_agent_key_algorithm": "RSA-PSS"
}

# Load with production settings
jacs.load_config(config)
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
ENV JACS_KEY_DIR=/secure/keys
ENV JACS_USE_SECURITY=true

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
def jacs_mcp_server():
    # Setup test configuration
    jacs.load("test.config.json")
    
    server = FastMCP("Test Server")
    return JACSMCPServer(server)

@pytest.fixture
def test_client(jacs_mcp_server):
    transport = FastMCPTransport(jacs_mcp_server)
    return Client(transport)

async def test_authenticated_tool(test_client):
    async with test_client:
        result = await test_client.call_tool("echo_tool", {"text": "test"})
        assert "test" in str(result)
```

## Performance Considerations

### Optimization Tips

1. **Key Caching**: JACS automatically caches keys
2. **Batch Operations**: Group multiple tool calls when possible  
3. **Connection Pooling**: Reuse client connections
4. **Async Operations**: Use async/await properly

```python
# Efficient client usage
async def efficient_mcp_usage():
    client = JACSMCPClient("http://server:8000/sse")
    
    # Single connection for multiple operations
    async with client:
        # Batch multiple tool calls
        tasks = [
            client.call_tool("tool1", {"data": f"item{i}"})
            for i in range(10)
        ]
        results = await asyncio.gather(*tasks)
    
    return results
```

## Next Steps

- **[FastMCP Integration](fastmcp.md)** - Advanced FastMCP patterns
- **[API Reference](api.md)** - Complete API documentation  
- **[Examples](../examples/python.md)** - More complex examples
- **[Security Guide](../security.md)** - Security best practices