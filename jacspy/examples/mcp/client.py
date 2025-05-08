# use request to send a response to the server

import asyncio
import os
from pathlib import Path
import jacs
from middleware import JACSMCPClient

# Load JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.client.config.json"

# Set password if needed
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"  # You should use a secure method in production

# Initialize JACS
jacs.load(str(jacs_config_path))


async def main():
    # Server URL - assuming it's running locally on the default port
    server_url = "http://localhost:8000/sse"
    
    print(f"Connecting to server at {server_url}")
    
    try:
        client = JACSMCPClient(server_url)
        
        # Use the client within an async context manager
        async with client:
            result = await client.call_tool("echo_tool", {"text": "Hello from authenticated client!"})
            print(f"\nFinal result: {result}")
            
    except Exception as e:
        print(f"Error during client operation: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
