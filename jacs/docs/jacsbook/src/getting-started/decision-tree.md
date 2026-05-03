# Which JACS Path Should I Use?

Choose the smallest supported integration that matches the boundary you need to secure.

## Start Here

| If you need... | Start here | Why |
|---|---|---|
| Sign and verify JSON, files, or one-off artifacts | [Quick Start](quick-start.md) | Establish the agent identity and trust model first. |
| A ready-made local MCP server for Claude, Codex, or another MCP client | [MCP Overview](../integrations/mcp.md) and `jacs mcp` | Fastest full server path; stdio only, no HTTP port. |
| Signed tool outputs inside LangChain / LangGraph on Python | [Python Framework Adapters](../python/adapters.md) | Add provenance without changing the rest of the app. |
| Signed tool outputs inside LangChain.js / LangGraph on Node | [Node.js LangChain.js](../nodejs/langchain.md) | Same pattern for TypeScript. |
| Secure existing MCP server/client code | [Python MCP](../python/mcp.md) or [Node.js MCP](../nodejs/mcp.md) | Wrap the transport or register JACS tools. |
| Sign Markdown or text in place | [Inline Text Signatures](../guides/inline-text-signing.md) | Signature stays with the readable file; supports multi-signer review. |
| Attach provenance to PNG, JPEG, or WebP images | [Image and Media Signatures](../guides/media-signing.md) | Signature is embedded in the image; no sidecar JSON. |
| Sign and verify raw email | [Email Signing and Verification](../guides/email-signing.md) | Rust API for `.eml` messages with field-level content hashes. |
| Cross-organization agent discovery and artifact exchange | [A2A Interoperability](../integrations/a2a.md) | Use A2A for agent-to-agent boundaries. |
| Multi-party approval or quorum workflows | [Multi-Agent Agreements](multi-agent-agreement.md) | Agreements are the right primitive for sign-off. |

## When You Probably Do Not Need JACS

- Everything stays inside one service you control and logs are enough.
- You only need integrity, not signer identity or third-party verification.
- A plain checksum or database audit log already satisfies the requirement.

## Recommended Adoption Order

1. Prototype with quickstart and simple sign/verify calls.
2. Attach provenance at the boundary that already exists: file, API response, framework tool, MCP call, image, email, or A2A artifact.
3. Add trust policy when other agents, services, or organizations enter the workflow.
4. Add agreements, DNS, or attestations only when the deployment needs them.

Start with the boundary you need to secure now.
