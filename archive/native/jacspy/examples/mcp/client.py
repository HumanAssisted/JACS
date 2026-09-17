# use request to send a response to the server

import asyncio
import os
from pathlib import Path
from jacs.mcp import JACSMCPClient


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} is required; generate fresh JACS identities before running "
            "this example (see examples/mcp/README.md)"
        )
    return value


jacs_config_path = Path(_required_env("JACS_CONFIG_PATH")).expanduser()
if not jacs_config_path.is_file():
    raise RuntimeError(f"JACS_CONFIG_PATH does not exist: {jacs_config_path}")
expected_server_agent_id = _required_env("JACS_MCP_EXPECTED_SERVER_AGENT_ID")
expected_server_key_hash = os.environ.get("JACS_MCP_EXPECTED_SERVER_KEY_HASH")


async def main():
    # Server URL - assuming it's running locally on the default port
    server_url = "http://localhost:8000/sse"

    print(f"Connecting to server at {server_url}")

    try:
        client = JACSMCPClient(
            server_url,
            str(jacs_config_path),
            expected_peer_agent_id=expected_server_agent_id,
            expected_peer_public_key_hash=expected_server_key_hash,
        )

        # Use the client within an async context manager
        async with client:
            result = await client.call_tool(
                "echo_tool", {"text": "Hello from authenticated client!"}
            )
            print(f"\nFinal result: {result}")

    except Exception as e:
        print(f"Error during client operation: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
