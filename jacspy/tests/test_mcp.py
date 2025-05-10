from jacs.mcp import JACSMCPServer 
from mcp.server.fastmcp import FastMCP 
mcp = JACSMCPServer(FastMCP("Authenticated Echo Server"))