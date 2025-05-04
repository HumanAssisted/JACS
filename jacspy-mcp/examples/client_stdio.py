# client_stdio.py
import asyncio
import sys  # To specify python executable path
import datetime

# Import the specific transport needed
from fastmcp.client.transports import PythonStdioTransport

# Import the Auth wrapper and defaults
from jacs_mcp.fast_mcp_auth import (
    AuthClient,
    default_sign_request,
    default_validate_response,
)
import traceback  # Add import for traceback


async def main():
    # Define the path to the server script - CORRECT THE FILENAME HERE
    server_script_path = "server_stdio.py"  # <-- Corrected filename

    # --- Explicitly create the Stdio Transport ---
    # Use sys.executable to ensure the correct Python interpreter is used
    stdio_transport = PythonStdioTransport(
        script_path=server_script_path, python_cmd=sys.executable
    )
    # ---------------------------------------------

    # Use the AuthClient wrapper, passing the *configured* transport object
    async with AuthClient(
        stdio_transport,  # Pass the transport instance directly
        sign_request_fn=default_sign_request,
        validate_response_fn=default_validate_response,
        read_timeout_seconds=datetime.timedelta(seconds=30),
    ) as client:
        print("CLIENT: Calling echo tool via Stdio...")
        try:
            # call_tool sends signed request transparently
            # response metadata is validated transparently by handler in AuthClient
            # AuthClient.call_tool returns the *actual* result
            result = await client.call_tool("echo", {"msg": "Hello Stdio"})
            print(
                f"CLIENT: Tool Result: {result}"
            )  # Should be the echo string directly
        except Exception as e:
            print(f"CLIENT: Error during tool call: {e}")
            traceback.print_exc()  # Print detailed traceback


if __name__ == "__main__":
    asyncio.run(main())
