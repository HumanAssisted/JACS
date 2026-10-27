"""Exercise the example against the installed MCP SDK over stdio."""

from pathlib import Path
import sys
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class EchoServerTest(unittest.IsolatedAsyncioTestCase):
    async def test_echo_protocol(self):
        server = StdioServerParameters(
            command=sys.executable,
            args=[str(Path(__file__).with_name("main.py"))],
        )
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                self.assertIn("echo_tool", [tool.name for tool in tools.tools])

                result = await session.call_tool("echo_tool", {"text": "hello"})
                self.assertFalse(result.isError)
                self.assertEqual(result.content[0].text, "hello")

                resource = await session.read_resource("echo://static")
                self.assertEqual(resource.contents[0].text, "Echo!")
                resource = await session.read_resource("echo://hello%20world")
                self.assertEqual(resource.contents[0].text, "Echo: hello%20world")

                prompt = await session.get_prompt("echo", {"text": "hello"})
                self.assertEqual(prompt.messages[0].content.text, "hello")


if __name__ == "__main__":
    unittest.main()
