# Integration Examples

Choose a maintained guide for the integration you need. Each guide identifies its supported surface and trust requirements.

| Integration | Walkthrough |
|-------------|-------------|
| Standard MCP clients | [Portable MCP setup](https://humanassisted.github.io/JACS/mcp-quickstart.html) and [extended profiles](../integrations/mcp.md) |
| Signed MCP transport | [Node.js](../nodejs/mcp.md) or [Python](../python/mcp.md); matching wrappers and peer trust are required at both ends |
| A2A discovery and messaging | [A2A how-to](https://humanassisted.github.io/JACS/a2a.html) and [official SDK examples](https://github.com/HumanAssisted/JACS/tree/main/archive/native/examples/a2a_v1_sdk) |
| W3C DID export and request proofs | [W3C DID how-to](https://humanassisted.github.io/JACS/w3c-did.html) |
| HTTP request authentication | [Node.js HTTP protocol](../nodejs/http.md); bind method, URL, body and audience, then authorize independently |
| Document middleware | [Express](../nodejs/express.md), [Koa](../nodejs/koa.md), [FastAPI](../python/adapters.md); document verification is not route authorization |
| LangChain / LangGraph | [Node.js](../nodejs/langchain.md) and [Python adapters](../python/adapters.md) |

Source examples and tests describe this checkout. Consult the [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md) before relying on an API from an installed package.
