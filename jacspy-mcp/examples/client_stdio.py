# client_stdio.py
import asyncio
import sys # To specify python executable path
import datetime # <-- Import datetime
from fastmcp import Client
# Use PythonStdioTransport
from fastmcp.client.transports import PythonStdioTransport
# Import the client-side components
from jacs_mcp.fast_mcp_auth import (
    AuthInjectTransport,
    get_client_metadata,
    create_metadata_reading_handler,
)

# Define what to do when server metadata is received
async def handle_server_metadata(metadata: dict):
    # Note: This won't be called as server isn't injecting metadata in Stdio mode
    print(f"CLIENT: Received server metadata: {metadata}")

async def main():
    # Use PythonStdioTransport pointing to the server script
    # Ensure the path to the server script is correct relative to where you run the client
    # Using sys.executable ensures we use the same Python interpreter
    server_script_path = "server.py" # Assumes client is run from 'examples' dir
    base = PythonStdioTransport(server_script_path, python_cmd=sys.executable)

    # 1. Wrap the base transport for client-side INJECTION
    auth_injector = AuthInjectTransport(base, get_client_metadata)

    # 2. Create the client-side READER handler
    metadata_reader = create_metadata_reading_handler(handle_server_metadata)

    # 3. Pass the injector transport AND the reader handler to the Client
    try:
        # Pass timeout as a timedelta object
        timeout = datetime.timedelta(seconds=30.0) # <-- Create timedelta
        async with Client(auth_injector, message_handler=metadata_reader, read_timeout_seconds=timeout) as client: # <-- Use timeout object
            print("CLIENT: Calling echo tool via Stdio...")
            # Make the call
            result = await client.call_tool("echo", {"msg": "Hello Stdio"})
            # Process the result
            if hasattr(result, 'content') and result.content:
                 print(f"CLIENT: Tool Result Content: {result.content[0].text}")
            else:
                 print(f"CLIENT: Tool Result (raw): {result}")

    except Exception as e:
        print(f"CLIENT: An error occurred: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())