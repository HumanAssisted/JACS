# server.py - Standalone FastMCP Stdio Server Example
import uuid
# Remove FastAPI import, Keep HTTPException if used in tools
from fastapi import HTTPException # Keep for error handling if needed within tool
from fastmcp import FastMCP, Context
# No uvicorn needed

# Remove the server-side middleware import as it's FastAPI specific
# from jacs_mcp.fast_mcp_auth import MetadataInjectingMiddleware, get_server_metadata

# --- MCP Server Setup ---
mcp = FastMCP("AuthExampleStdio")

# --- Server-Side Reading Logic (Adapt for missing metadata) ---
def validate_client_metadata(meta: dict | None): # Allow meta to be None
    # Safely handle if metadata is missing from the request context
    if meta is None:
        print("SERVER: No metadata found in request context.")
        # Decide if this is an error or acceptable
        # For this example, we'll just log and continue
        return

    print(f"SERVER: Validating client metadata: {meta}")
    client_id = meta.get("client_id", "unknown")
    req_id = meta.get("client_request_id", "unknown")
    print(f"SERVER: Received call from client='{client_id}', request_id='{req_id}'")
    # Apply validation logic if metadata is present
    if client_id != "trusted-client":
         print(f"SERVER: Warning - Invalid client_id: {client_id}")
    if not meta.get("client_request_id"):
         print("SERVER: Warning - Missing client_request_id")

# --- MCP Tool (Adapt for missing metadata) ---
@mcp.tool()
async def echo(msg: str, ctx: Context) -> str:
    print(f"SERVER: echo tool called with msg='{msg}'")

    # Safely get metadata from context, defaulting to None if attribute doesn't exist
    request_metadata = getattr(ctx, 'metadata', None)

    # Server reads client metadata from context (if it was successfully passed)
    validate_client_metadata(request_metadata) # Pass the potentially None metadata

    # Use metadata in the response if it was available
    client_id_from_meta = "N/A"
    if request_metadata:
        client_id_from_meta = request_metadata.get('client_id', 'N/A')
    client_info = f"client={client_id_from_meta}"

    return f"Echoing: '{msg}' (Seen by server, processed for {client_info})"

# --- Run the standalone FastMCP server using default (Stdio) transport ---
if __name__ == "__main__":
    # Use mcp.run() with default transport (Stdio)
    print("Starting standalone FastMCP Stdio server using mcp.run...")
    mcp.run()

    # --- Original call that failed ---
    # print("Starting standalone FastMCP SSE server on port 8000...")
    # mcp.run(transport='sse', port=8000, host="0.0.0.0")