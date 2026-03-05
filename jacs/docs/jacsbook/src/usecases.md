# Use Cases

This chapter stays close to current product use, not roadmap integrations.

## 1. Secure A Local MCP Tool Server

**Use this when:** Claude Desktop, Codex, or another MCP client is calling tools that should not run on blind trust.

**Recommended JACS path:**

- Use `jacs-mcp` if you want a full server immediately
- Use [Python MCP Integration](python/mcp.md) or [Node.js MCP Integration](nodejs/mcp.md) if you already have server code

**What JACS adds:**

- Signed JSON-RPC messages
- Fail-closed verification by default
- Agent identity and auditability for tool calls

## 2. Add Provenance To LangChain Or LangGraph

**Use this when:** your model already runs inside LangChain or LangGraph and you want signed tool outputs without introducing MCP.

**Recommended JACS path:**

- [Python Framework Adapters](python/adapters.md)
- [Node.js LangChain.js](nodejs/langchain.md)

**What JACS adds:**

- Signed tool results
- Optional strict mode at the adapter boundary
- Minimal changes to existing framework code

## 3. Exchange Signed Artifacts Across Organizations

**Use this when:** one agent produces work that another organization, service, or team must verify before acting on it.

**Recommended JACS path:**

- [A2A Interoperability](integrations/a2a.md)
- [A2A Quickstart](guides/a2a-quickstart.md)

**What JACS adds:**

- Agent Cards with JACS provenance metadata
- Signed A2A artifacts
- Trust policies for admission control

## 4. Sign HTTP Or API Boundaries Without MCP

**Use this when:** the boundary is an API route, not an MCP transport.

**Recommended JACS path:**

- [Python Framework Adapters](python/adapters.md) for FastAPI
- [Express Middleware](nodejs/express.md)
- [Koa Middleware](nodejs/koa.md)

**What JACS adds:**

- Signed JSON responses
- Verified inbound requests
- A clean upgrade path to A2A discovery on the same app boundary

## 5. Run Multi-Agent Approval Workflows

**Use this when:** multiple agents must sign off on the same document, deployment, or decision.

**Recommended JACS path:**

- [Multi-Agent Agreements](getting-started/multi-agent-agreement.md)
- [Rust Agreements](rust/agreements.md)

**What JACS adds:**

- M-of-N quorum
- Timeout and algorithm constraints
- Verifiable signature chain across signers

## 6. Keep Signed Files Or JSON As Durable Artifacts

**Use this when:** you need an artifact to stay verifiable after it leaves the process that created it.

**Recommended JACS path:**

- [Verifying Signed Documents](getting-started/verification.md)
- [Working with Documents](rust/documents.md)
- [Python Basic Usage](python/basic-usage.md)
- [Node.js Basic Usage](nodejs/basic-usage.md)

**What JACS adds:**

- Self-contained signed envelopes
- Re-verification at read time
- Cross-language interoperability

## 7. Publish Public Identity Without A Central Auth Service

**Use this when:** external systems need to verify your agent identity but you do not want a shared auth server in the middle.

**Recommended JACS path:**

- [DNS-Based Verification](rust/dns.md)
- [DNS Trust Anchoring](advanced/dns-trust.md)

**What JACS adds:**

- Public key fingerprint anchoring
- DNS-based verification flows
- Local private-key custody
