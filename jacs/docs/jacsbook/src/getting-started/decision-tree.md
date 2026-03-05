# Which JACS Integration Should I Use?

This page helps you find the right integration path in under 2 minutes.

## Step 1: Do You Need JACS?

**Yes, if:**
- Your AI agents communicate with external services or other organizations' agents
- Data leaves your control (sent to clients, partners, regulators)
- You need cryptographic proof of who produced what (non-repudiation)
- You operate in a regulated environment (healthcare, finance, government)

**Probably not, if:**
- Everything runs in a single service you control
- You trust your own logs and don't need third-party verification
- You just need checksums (use SHA-256 instead)

## Step 2: Pick Your Framework

| I use... | Start here | Docs |
|----------|-----------|------|
| Python + LangChain/LangGraph | `from jacs.adapters.langchain import signed_tool` | [LangChain Guide](../python/adapters.md) |
| Python + CrewAI | `from jacs.adapters.crewai import jacs_guardrail` | [CrewAI Guide](../python/adapters.md) |
| Python + FastAPI | `from jacs.adapters.fastapi import JacsMiddleware` | [FastAPI Guide](../python/adapters.md) |
| Node.js + Express | `require('@hai.ai/jacs/express')` | [Express Guide](../nodejs/express.md) |
| Node.js + Vercel AI SDK | `require('@hai.ai/jacs/vercel-ai')` | [Vercel AI Guide](../nodejs/vercel-ai.md) |
| Node.js + LangChain.js | `require('@hai.ai/jacs/langchain')` | [LangChain.js Guide](../nodejs/langchain.md) |
| MCP Server (Python) | `from jacs.mcp import JACSMCPServer` | [MCP Guide](../integrations/mcp.md) |
| MCP Server (Node.js) | `require('@hai.ai/jacs/mcp')` | [MCP Guide](../nodejs/mcp.md) |
| Go service / API | `import "github.com/HumanAssisted/JACS/jacsgo"` | [Go Quick Start](../go/installation.md) |
| A2A Protocol | `from jacs.a2a import JACSA2AIntegration` | [A2A Guide](../integrations/a2a.md) |
| A2A + Attestation (signed exchange with trust claims) | Combine `sign_artifact()` + `create_attestation()` | [A2A + Attestation Guide](../guides/a2a-attestation-composition.md) |
| DID-compatible identity (no blockchain required) | Keep JACS signing + add DID mapping | [DID Guide](../integrations/did.md) |
| Database-backed provenance | Store signed envelopes + query extracted fields | [Database Guide](../integrations/databases.md) |
| Rust / CLI | `cargo install jacs --features cli` | [Rust Guide](../rust/installation.md) |
| Any language (standalone) | `import jacs.simple as jacs` | [Simple API](../python/simple-api.md) |

## Step 3: Your Adoption Path

**Stage 1 -- Prototyping**: `jacs.quickstart(name="my-agent", domain="my-agent.example.com")`. No config. Explore the API. Keys on disk, auto-managed.

**Stage 2 -- Single-org production**: `jacs.load()` with persistent agent, strict mode, file-based keys. Add provenance to internal systems.

**Stage 3 -- Cross-org production**: DNS trust anchoring, A2A agent cards, agreements with external agents. Operate across trust boundaries. For workflows requiring both cross-boundary exchange and trust claims, see the [A2A + Attestation Composition Guide](../guides/a2a-attestation-composition.md).

**Stage 4 -- Regulated/enterprise**: Post-quantum algorithms (pq2025/ML-DSA-87), OpenTelemetry observability, audit trails for compliance.

Each stage adds capabilities without breaking what came before. You never configure features you don't need yet.
