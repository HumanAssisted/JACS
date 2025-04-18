# server.py
from fastapi import FastAPI, HTTPException
from fastmcp import FastMCP, Context
import uvicorn

# Import the server-side middleware
from jacs_mcp.fast_mcp_auth import MetadataInjectingMiddleware, get_server_metadata

# --- FastAPI App Setup ---
app = FastAPI(title="MCP Auth Example")

# --- MCP Server Setup ---
mcp = FastMCP("AuthExample")

# --- Server-Side Reading Logic ---
def validate_client_metadata(meta: dict):
    print(f"SERVER: Validating client metadata: {meta}")
    if meta.get("client_id") != "trusted-client":
        raise HTTPException(401, "Invalid client_id")
    if not meta.get("client_request_id"):
        raise HTTPException(400, "Missing client_request_id")

# --- MCP Tool ---
@mcp.tool()
async def echo(msg: str, ctx: Context) -> str:
    # Server reads client metadata from context
    validate_client_metadata(ctx.metadata)
    client_info = f"client={ctx.metadata.get('client_id', 'N/A')}"
    # Server will inject its own metadata via middleware
    return f"Echoing: '{msg}' (Seen by server, processed for {client_info})"

# --- Mount MCP & Add Middleware ---
# IMPORTANT: Add middleware BEFORE mounting the MCP app
# The middleware needs to wrap the application that handles the /mcp route.
app.add_middleware(MetadataInjectingMiddleware, meta_fn=get_server_metadata)
app.mount("/mcp", mcp.sse_app()) # Mount the SSE app *after* adding middleware


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000) # Use 0.0.0.0 for accessibility