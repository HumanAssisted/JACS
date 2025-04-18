# server_sse.py
import uvicorn
from fastmcp import Context
# Import the wrapper, CORRECT decorator name, and defaults needed
from jacs_mcp.fast_mcp_auth import JACSFastMCP, validate_tool_request
# default_validate_request is used by the decorator by default
# default_sign_response is used by the middleware by default

mcp = JACSFastMCP(
    name="AuthExampleSSE_JACS"
    # No auth functions needed here if using defaults in decorator/middleware
)

# Apply the MCP tool decorator FIRST, then our validation decorator
@mcp.tool()
@validate_tool_request() # Apply the validation decorator
async def echo(msg: str, ctx: Context) -> str: # REMOVED **kwargs
    """A simple echo tool with automatic request validation."""
    # NO manual validation call needed here
    # NO **kwargs needed in signature
    print(f"SSE SERVER: echo tool executing with msg='{msg}'")
    result_string = f"Echo via SSE: {msg}"
    # Response signing is handled by middleware applied in mcp.sse_app()
    return result_string

# --- Get the prepared ASGI app from the wrapper ---
sse_app_with_middleware = mcp.sse_app() # Gets app with response signing middleware

# --- Run with uvicorn ---
if __name__ == "__main__":
    host = "localhost"
    port = 8000
    print(f"Starting JACSFastMCP SSE server with Auth Decorator/Middleware on http://{host}:{port}")
    uvicorn.run(sse_app_with_middleware, host=host, port=port)