import os
from pathlib import Path
import logging
from fastmcp import FastMCP
from jacs.mcp import JACSMCPServer
import uvicorn

logger = logging.getLogger(__name__)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} is required; generate fresh JACS identities before running "
            "this example (see examples/mcp/README.md)"
        )
    return value


jacs_config_path = Path(_required_env("JACS_CONFIG_PATH")).expanduser()
if not jacs_config_path.is_file():
    raise RuntimeError(f"JACS_CONFIG_PATH does not exist: {jacs_config_path}")
allowed_client_agent_id = _required_env("JACS_MCP_ALLOWED_CLIENT_AGENT_ID")


# Create original FastMCP server first
mcp = JACSMCPServer(
    FastMCP("Authenticated Echo Server"),
    str(jacs_config_path),
    allowed_peer_agent_ids=[allowed_client_agent_id],
)


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
    app = mcp.http_app(transport="sse")
    uvicorn.run(app, host=host, port=port)
