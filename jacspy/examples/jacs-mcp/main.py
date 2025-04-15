"""
FastMCP Echo Server
"""
import os
import sys
import signal
from mcp.server.fastmcp import FastMCP

# Add parent directories to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.append(parent_dir)

# Import based on platform
if sys.platform == "darwin":
    try:
        import jacspy  # For macOS, assuming jacspy.so is in the parent directory
        print("jacspy imported successfully")
    except ImportError:
        print("Failed to import jacspy. Make sure jacspy.so is available.")
        sys.exit(1)
elif sys.platform == "linux":
    try:
        # For Linux, assuming jacspy is in a 'linux' subdirectory
        linux_dir = os.path.join(parent_dir, "linux")
        sys.path.append(linux_dir)
        from linux import jacspylinux as jacspy
    except ImportError:
        print("Failed to import jacspylinux. Make sure it's available in the linux directory.")
        sys.exit(1)
else:
    print(f"Unsupported platform: {sys.platform}")
    sys.exit(1)

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