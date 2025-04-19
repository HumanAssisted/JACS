# server_stdio.py - Standalone FastMCP Stdio Server Example
import uuid
from fastmcp import Context
# Import the JACS wrapper and only the manual signing function
from jacs_mcp.fast_mcp_auth import (
    JACSFastMCP,
    default_sign_response # Needed for manual response signing
    # Decorator handles request validation using default_validate_request
)

# --- Auth Server Setup using JACSFastMCP ---
mcp = JACSFastMCP(
    name="AuthExampleStdio_JACS_AutoValidate"
    # Can pass custom validate_request_fn here if needed
)

# --- MCP Tool (Clean Signature, Auto Request Validation) ---
@mcp.tool(strict=True) # Pass strict=True (or False) - example usage
# Signature is clean, no **kwargs needed for auth
# MUST STILL return dict for manual response signing in Stdio
async def echo(msg: str, ctx: Context) -> dict:
    """A simple echo tool with automatic request validation via @mcp.tool."""
    # Request metadata was validated by the wrapper inside @mcp.tool
    print(f"STDIO SERVER: echo tool executing with msg='{msg}' (strict=True specified)")

    result_string = f"Echoing via Stdio: '{msg}'"

    # Manually sign response for Stdio
    server_meta = default_sign_response(result_string)
    print(f"STDIO SERVER: Manually signing response: {server_meta}")

    return {
        "result": result_string,
        "metadata": server_meta
    }

# --- Run ---
if __name__ == "__main__":
    print("Starting JACSFastMCP Stdio server (auto-validate)...")
    mcp.run()

 