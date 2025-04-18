# server_stdio.py - Standalone FastMCP Stdio Server Example
import uuid
from fastmcp import Context # Keep Context
# Import the JACS wrapper, decorator, and default auth functions
from jacs_mcp.fast_mcp_auth import (
    JACSFastMCP,
    validate_tool_request, # Import the decorator
    default_sign_response # Needed for manual response signing
    # default_validate_request is used by the decorator by default
)

# --- Auth Server Setup using JACSFastMCP ---
# Instantiate the wrapper. Auth functions are needed for manual use here.
mcp = JACSFastMCP(
    name="AuthExampleStdio_JACS_Decorated"
)

# --- MCP Tool (Using Decorator for Request Validation) ---
@mcp.tool()
@validate_tool_request() # Apply the request validation decorator
# Signature does NOT need **kwargs anymore
# MUST STILL return dict for manual response signing in Stdio
async def echo(msg: str, ctx: Context) -> dict:
    """A simple echo tool with automatic request validation via decorator."""
    # Request metadata was validated by the decorator before this point
    print(f"STDIO SERVER: echo tool executing with msg='{msg}'")

    # Tool logic
    result_string = f"Echoing via Stdio: '{msg}'"

    # Manually sign response for Stdio (Middleware doesn't apply here)
    server_meta = default_sign_response(result_string) # Call signing function
    print(f"STDIO SERVER: Manually signing response: {server_meta}")

    # Return dictionary with result and metadata
    return {
        "result": result_string,
        "metadata": server_meta
    }

# --- Run the standalone FastMCP server using default (Stdio) transport ---
if __name__ == "__main__":
    print("Starting JACSFastMCP Stdio server (with decorator)...")
    # Use the wrapper's run method, which delegates to internal FastMCP for stdio
    mcp.run() # Defaults to stdio if not specified

 