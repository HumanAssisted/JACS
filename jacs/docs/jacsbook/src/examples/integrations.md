# Integration Examples

This page is now a curated index of examples that still line up with the current APIs. The old monolithic example chapter mixed outdated agent APIs with supported workflows.

## MCP

- `jacs-mcp/README.md`
  - Best starting point for the full Rust MCP server
- `jacspy/examples/mcp/server.py`
  - Python FastMCP server wrapped with `JACSMCPServer`
- `jacspy/examples/mcp/client.py`
  - Python FastMCP client wrapped with `JACSMCPClient`
- `jacsnpm/examples/mcp.stdio.server.js`
  - Node stdio server with `createJACSTransportProxy()`
- `jacsnpm/examples/mcp.stdio.client.js`
  - Node stdio client with signed transport

## LangChain / LangGraph

- `jacspy/examples/langchain/signing_callback.py`
  - Best current Python example for signed LangGraph tool execution
- `jacsnpm/examples/langchain/basic-agent.ts`
  - Node LangChain.js agent using JACS tools
- `jacsnpm/examples/langchain/signing-callback.ts`
  - Node auto-signing pattern for LangGraph-style flows

## A2A

- `jacspy/tests/test_a2a_server.py`
  - Best current Python reference for generated `.well-known` routes
- `jacsnpm/src/a2a-server.js`
  - Node Express A2A discovery middleware
- `jacsnpm/examples/a2a-agent-example.js`
  - Node A2A card and artifact demo
- `jacs/tests/a2a_cross_language_tests.rs`
  - Cross-language behavior reference for signing and verification

## HTTP / App Middleware

- `jacspy/examples/http/server.py`
  - FastAPI app with `JacsMiddleware`
- `jacspy/examples/http/client.py`
  - Python client consuming signed responses
- `jacsnpm/examples/expressmiddleware.js`
  - Express middleware example

## Rule Of Thumb

If an example and a higher-level prose page disagree, trust:

1. the current binding README
2. the current tests
3. the example that imports the API you intend to use today
