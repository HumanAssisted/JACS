# server_sse.py
import uvicorn
from fastmcp import Context
# Import only the JACS wrapper
from jacs_mcp.fast_mcp_auth import JACSFastMCP
# Defaults for validation (decorator) and signing (middleware) are used

# --- Auth Server Setup using JACSFastMCP ---
mcp = JACSFastMCP(
    name="AuthExampleSSE_JACS_AutoValidate"
    # Can pass custom validate_request_fn here if needed
)

# --- Tool Definition (Clean Signature, Auto Request Validation) ---
@mcp.tool(name="echo", description="Echoes a message via SSE", strict=True) # Add strict=True back
# Signature is clean
async def echo(msg: str, ctx: Context) -> str:
    """A simple echo tool with automatic request/response auth handling."""
    # Request validated by wrapper in @mcp.tool
    print(f"SSE SERVER: echo tool executing with msg='{msg}' (strict=True specified)")
    result_string = f"Echo via SSE: {msg}"
    # Response signing handled by middleware in mcp.sse_app()
    return result_string

# --- Get the prepared ASGI app ---
sse_app_with_middleware = mcp.sse_app()

# --- Run with uvicorn ---
if __name__ == "__main__":
    host = "localhost"
    port = 8000
    print(f"Starting JACSFastMCP SSE server (auto-validate/sign)...")
    uvicorn.run(sse_app_with_middleware, host=host, port=port)