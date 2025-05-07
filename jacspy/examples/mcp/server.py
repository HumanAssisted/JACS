import jacs
import os
from pathlib import Path
import logging
from mcp.server.fastmcp import FastMCP  # Make sure to import FastMCP
from middleware import JACSMCPServer 
import uvicorn

logger = logging.getLogger(__name__)
# Load JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.server.config.json"

# Set password if needed
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"  # You should use a secure method in production

# Initialize JACS
jacs.load(str(jacs_config_path))


# Create original FastMCP server first
original_mcp = FastMCP("Authenticated Echo Server")

# Then wrap it with JACSMCPServer
mcp = JACSMCPServer(original_mcp)


@mcp.tool()
def echo_tool(text: str) -> str:
    """Echo the input text"""
    return f"SERVER SAYS: {text}"


@mcp.resource("echo://static")
def echo_resource() -> str:
    return "Echo!"


@mcp.resource("echo://{text}")
def echo_template(text: str) -> str:
    """Echo the input text"""
    return f"Echo: {text}"


@mcp.prompt("echo")
def echo_prompt(text: str) -> str:
    return text


# --- Get the prepared ASGI app ---
sse_app_with_middleware = mcp.sse_app()

# --- Run with uvicorn ---
if __name__ == "__main__":
    host = "localhost"
    port = 8000
    print("Starting JACSFastMCP SSE server (auto-validate/sign)...")
    uvicorn.run(sse_app_with_middleware, host=host, port=port)
