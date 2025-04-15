"""
FastMCP Echo Server
"""
import signal
from mcp.server.fastmcp import FastMCP
from lib import jacspy
import sys
# Create server
mcp = FastMCP("Echo Server")


@mcp.tool()
def echo_tool(text: str) -> str:
    """Echo the input text"""
    return text


@mcp.resource("echo://static")
def echo_resource() -> str:
    return "Echo!"


@mcp.resource("echo://{text}")
def echo_template(text: str) -> str:
    """Echo the input text"""
    return f"Echo: {text}"


@mcp.prompt("echo")
def echo_prompt(text: str) -> str:
    return text


def signal_handler(sig, frame):
    """Handle keyboard interrupt"""
    print("\nShutting down gracefully...")
    sys.exit(0)


if __name__ == "__main__":
    # Register signal handler for clean shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run server (without handle_signals parameter)
    mcp.run()