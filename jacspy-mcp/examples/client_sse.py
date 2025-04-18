# client_sse.py
import asyncio
from fastmcp import Client
from fastmcp.client.transports import SSETransport
# Import the new components
from jacs_mcp.fast_mcp_auth import (
    AuthInjectTransport,
    get_client_metadata,
    create_metadata_reading_handler,
)

# Define what to do when server metadata is received
async def handle_server_metadata(metadata: dict):
    print(f"CLIENT: Received server metadata: {metadata}")

async def main():
    base = SSETransport("http://localhost:8000/mcp")

    # 1. Wrap the base transport for client-side INJECTION
    auth_injector = AuthInjectTransport(base, get_client_metadata)

    # 2. Create the client-side READER handler
    metadata_reader = create_metadata_reading_handler(handle_server_metadata)

    # 3. Pass the injector transport AND the reader handler to the Client
    async with Client(auth_injector, message_handler=metadata_reader) as client:
        print("CLIENT: Calling echo tool...")
        result = await client.call_tool("echo", {"msg": "Hello SSE with BiDi Auth"})
        print(f"CLIENT: Tool Result: {result}") # Result object structure depends on fastmcp version

if __name__ == "__main__":
    asyncio.run(main())