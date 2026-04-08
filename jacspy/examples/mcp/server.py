import jacs
import os
from pathlib import Path
import logging
from fastmcp import FastMCP
from jacs.mcp import JACSMCPServer 
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
mcp = JACSMCPServer(FastMCP("Authenticated Echo Server"))


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


# --- Run with uvicorn ---
if __name__ == "__main__":
    host = "localhost"
    port = 8000
    print("Starting JACS FastMCP server...")
    app = mcp.http_app()
    uvicorn.run(app, host=host, port=port)
