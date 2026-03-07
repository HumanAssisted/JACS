# JACS: JSON Agent Communication Standard

JACS is a cryptographic provenance layer for agent systems. Use it when an output, tool call, or agent handoff crosses a trust boundary and logs alone are not enough.

## Start With The Deployment

Most teams adopt JACS in one of four ways:

- **LangChain / LangGraph / CrewAI / FastAPI**: add signing at tool or API boundaries without changing the rest of the app
- **MCP**: secure a local tool server or expose JACS itself as an MCP tool suite
- **A2A**: publish an Agent Card, exchange signed artifacts, and apply trust policy across organizations
- **Core signing**: sign JSON, files, or agreements directly from Rust, Python, Node.js, or Go

The book now focuses on those supported workflows first. Older roadmap-style integration chapters have been reduced or removed from navigation.

## What JACS Gives You

- **Signed JSON and file envelopes** with tamper detection
- **Persistent agent identity** with encrypted private keys
- **Trust bootstrap primitives** such as `share_public_key`, `share_agent`, and `trust_agent_with_key`
- **A2A artifact signing and trust policies** (`open`, `verified`, `strict`)
- **MCP integration paths** for ready-made servers, transport security, or tool registration
- **Framework adapters** for Python and Node.js ecosystems
- **Multi-party agreements** with quorum, timeout, and algorithm constraints
- **Cross-language compatibility** across Rust, Python, Node.js, and Go

## Best Entry Points

If you are choosing where to start:

1. [Which Integration?](getting-started/decision-tree.md)
2. [Use Cases](usecases.md)
3. [MCP Overview](integrations/mcp.md)
4. [A2A Interoperability](integrations/a2a.md)
5. [Python Framework Adapters](python/adapters.md)
6. [Node.js LangChain.js](nodejs/langchain.md)

## Implementations

### Rust

- Deepest feature surface
- CLI plus library APIs
- Best fit when you want a ready-made MCP server via `jacs mcp`

### Python (`jacs`)

- Best fit for LangChain, LangGraph, CrewAI, FastAPI, and local MCP/A2A helpers
- Strong adapter story for adding provenance inside an existing app

### Node.js (`@hai.ai/jacs`)

- Best fit for Express, Koa, Vercel AI SDK, LangChain.js, and MCP transport/tool integration
- Also exposes A2A helpers and Express discovery middleware

### Go (`jacsgo`)

- Good fit for services that need signing and verification without framework adapters

## Quick Start

### Rust CLI

```bash
cargo install jacs-cli
jacs quickstart --name my-agent --domain my-agent.example.com
```

### Python

```bash
pip install jacs
```

### Node.js

```bash
npm install @hai.ai/jacs
```

### Go

```bash
go get github.com/HumanAssisted/JACS/jacsgo
```

Rust, Python, and Node quickstart flows create or load a persistent agent and return agent metadata including config and key paths.

## What This Book Does Not Claim

- It does **not** treat MCP and A2A as the same thing. MCP is for model-to-tool calls inside an application boundary; A2A is for agent discovery and exchange across boundaries.
- It does **not** assume every aspirational integration is first-class. If a chapter describes a feature that is not fully supported today, it has been moved out of the main path and tracked separately.
- It does **not** require a registry or blockchain to work. JACS identity is key-based and can be used entirely locally.

## Community

- [GitHub Repository](https://github.com/HumanAssisted/JACS)
- [Issue Tracker](https://github.com/HumanAssisted/JACS/issues)
