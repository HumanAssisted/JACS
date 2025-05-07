import jacs
import os
from pathlib import Path
import logging
from mcp.server.fastmcp import FastMCP
from middleware import JACSAuthMiddleware, JACSMCPProxy
import uvicorn

logger = logging.getLogger(__name__)
# Load JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.server.config.json"

# Set password if needed
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"  # You should use a secure method in production

# Initialize JACS
jacs.load(str(jacs_config_path))


# Create server
mcp = FastMCP("Authenticated Echo Server")
auth_mcp = JACSMCPProxy(mcp, JACSAuthMiddleware())


@auth_mcp.tool()
def echo_tool(text: str) -> str:
    """Echo the input text"""
    return text


@auth_mcp.resource("echo://static")
def echo_resource() -> str:
    return "Echo!"


@auth_mcp.resource("echo://{text}")
def echo_template(text: str) -> str:
    """Echo the input text"""
    return f"Echo: {text}"


@auth_mcp.prompt("echo")
def echo_prompt(text: str) -> str:
    return text


# --- Get the prepared ASGI app ---
sse_app_with_middleware = auth_mcp.sse_app()

# --- Run with uvicorn ---
if __name__ == "__main__":
    host = "localhost"
    port = 8000
    print("Starting JACSFastMCP SSE server (auto-validate/sign)...")
    uvicorn.run(sse_app_with_middleware, host=host, port=port)
