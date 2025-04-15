"""
MCP Client Example
"""
import asyncio
import urllib.parse
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from lib import jacspy

async def main():
    # Create parameters for connecting to the server
    server_params = StdioServerParameters(
        command="python",
        args=["main.py"],  # Path to your server script
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print(f"Available tools: {tools}")
            
            # Call the echo tool
            result = await session.call_tool("echo_tool", {"text": "Hello from client!"})
            print(f"Tool result: {result}")
            
            # Read a resource
            response = await session.read_resource("echo://static")
            # Correctly access the contents attribute
            content_text = response.contents[0].text if response.contents else "No content"
            print(f"Resource content: {content_text}")
            
            # Read a parameterized resource (properly encoded)
            encoded_text = urllib.parse.quote("Hello World")
            response = await session.read_resource(f"echo://{encoded_text}")
            content_text = response.contents[0].text if response.contents else "No content"
            print(f"Parameterized resource: {content_text}")
            
            # Get the echo prompt
            prompt = await session.get_prompt("echo", {"text": "This is a prompt test"})
            print(f"Prompt: {prompt}")


if __name__ == "__main__":
    asyncio.run(main())