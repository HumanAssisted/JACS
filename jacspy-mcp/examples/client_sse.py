# client_sse.py
import asyncio
import datetime
import traceback
# Import ONLY the AuthClient wrapper
from jacs_mcp.fast_mcp_auth import AuthClient
# The default signing and validation functions are used by AuthClient internally

async def main():
    # Define the server URL - APPEND the default SSE path
    server_url = "http://localhost:8000/sse" # <-- Added /sse

    print(f"CLIENT: Attempting to connect to SSE server at {server_url}")

    # Use the AuthClient wrapper, passing the URL.
    # It will use default_sign_request and default_validate_response internally.
    try:
        async with AuthClient(
            server_url, # Pass the corrected URL directly
            read_timeout_seconds=datetime.timedelta(seconds=30)
            # No need to pass sign_request_fn or validate_response_fn if using defaults
        ) as client:
            print("CLIENT: Connected. Calling echo tool via SSE...")

            # call_tool sends signed request transparently
            # response metadata is validated transparently by handler in AuthClient
            result = await client.call_tool("echo", {"msg": "Hello SSE"})
            print(f"CLIENT: Tool Result: {result}")

    except Exception as e:
        print(f"CLIENT: Error during connection or tool call: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())