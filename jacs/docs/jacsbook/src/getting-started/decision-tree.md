# Which JACS Path Should I Use?

Choose the smallest supported integration that matches your deployment.

## Start Here

| If you need... | Start here | Why |
|---|---|---|
| Signed tool outputs inside **LangChain / LangGraph** on Python | [Python Framework Adapters](../python/adapters.md) | Smallest path: sign tool results without adding MCP |
| Signed tool outputs inside **LangChain.js / LangGraph** on Node | [Node.js LangChain.js](../nodejs/langchain.md) | Same idea for TypeScript |
| A ready-made **local MCP server** for Claude, Codex, or another MCP client | [MCP Overview](../integrations/mcp.md) and `jacs-mcp` | Fastest full server path |
| To secure your **existing MCP server/client code** | [Python MCP](../python/mcp.md) or [Node.js MCP](../nodejs/mcp.md) | Use wrappers or transport proxies around code you already have |
| Cross-organization agent discovery and signed artifact exchange | [A2A Interoperability](../integrations/a2a.md) | MCP is not enough for this boundary |
| Signed HTTP APIs without adopting MCP | [Python Framework Adapters](../python/adapters.md), [Express](../nodejs/express.md), [Koa](../nodejs/koa.md) | Sign requests or responses at the web layer |
| Multi-party approval or quorum workflows | [Multi-Agent Agreements](multi-agent-agreement.md) | Agreements are the right primitive, not just one-off signatures |
| Direct signing from scripts, jobs, or services | [Quick Start](quick-start.md), [Python Basic Usage](../python/basic-usage.md), [Node Basic Usage](../nodejs/basic-usage.md) | Start from sign/verify before adding framework layers |

## When You Probably Do Not Need JACS

- Everything stays inside one service you control and your own logs are enough
- You only need integrity, not signer identity or third-party verification
- A plain checksum or database audit log already satisfies the requirement

## Recommended Adoption Order

1. **Prototype** with quickstart and simple sign/verify calls.
2. **Attach provenance** at the boundary that already exists in your system: LangChain tool, FastAPI response, MCP call, or A2A artifact.
3. **Add trust policy** only when other agents or organizations enter the picture.
4. **Add agreements, DNS, or attestations** only if your deployment actually needs them.

The mistake to avoid is starting with the broadest story. Start with the boundary you need to secure now.
