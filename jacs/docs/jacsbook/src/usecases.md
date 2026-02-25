# Use Cases

This chapter is organized around deployment outcomes, not APIs.

If you want end-to-end fictional scenarios, see [USECASES.md](https://github.com/HumanAssisted/JACS/blob/main/USECASES.md). The sections below are practical playbooks for real systems.

## 1. Secure an MCP Server Used by Multiple Agents

**Problem:** your MCP server exposes high-impact tools and you cannot trust unsigned JSON-RPC calls.

**JACS pattern:**
- Sign outgoing MCP requests and responses at the transport layer
- Verify every inbound signed payload before tool execution
- Run fail-closed transport policy (default) or explicit strict settings so unsigned/failed verification traffic is rejected

**Where to implement:**
- [MCP Overview](integrations/mcp.md)
- [Python MCP Integration](python/mcp.md)
- [Node.js MCP Integration](nodejs/mcp.md)

## 2. Add Provenance to Agent Framework Workflows

**Problem:** orchestration frameworks generate valuable outputs, but downstream systems cannot prove origin.

**JACS pattern:**
- Sign tool outputs and final answers in adapters/middleware
- Verify before routing into critical steps (billing, approvals, external calls)
- Keep framework ergonomics while adding cryptographic provenance

**Where to implement:**
- [Python Framework Adapters](python/adapters.md) (LangChain, LangGraph, CrewAI, FastAPI)
- [Node.js Integrations](nodejs/langchain.md), [Express](nodejs/express.md), [Vercel AI](nodejs/vercel-ai.md)

## 3. Exchange Artifacts Across Organizations with A2A

**Problem:** agents in different trust domains need machine-verifiable exchange and discovery.

**JACS pattern:**
- Publish A2A well-known discovery documents
- Wrap artifacts with signed provenance envelopes
- Apply trust policies (`open`, `verified`, `strict`) before accepting external artifacts

**Where to implement:**
- [A2A Interoperability](integrations/a2a.md)
- [A2A Quickstart](guides/a2a-quickstart.md)

## 4. Store Signed Files and JSON with Chain-of-Custody

**Problem:** you must preserve integrity for files and structured payloads over time.

**JACS pattern:**
- Sign JSON and file artifacts at creation time
- Store signed envelopes, not detached metadata only
- Re-verify on read and before downstream processing

**Where to implement:**
- [Working with Documents](rust/documents.md)
- [Storage Backends](advanced/storage.md)
- [Go Quick Start](go/installation.md)

## 5. Verify Agent Identity Publicly with DNS

**Problem:** external systems need to verify your agent identity without sharing private infrastructure.

**JACS pattern:**
- Publish public key fingerprints in DNS TXT
- Use DNSSEC-aware verification for stronger trust requirements
- Keep private keys local; publish only public material

**Where to implement:**
- [DNS-Based Verification](rust/dns.md)
- [DNS Trust Anchoring](advanced/dns-trust.md)

## 6. Build Database-Native Provenance Queries

**Problem:** you need signed data that is both verifiable and queryable at scale.

**JACS pattern:**
- Persist full signed envelopes
- Add extracted/indexed columns for high-value query predicates
- Re-verify signatures periodically and on retrieval paths

**Where to implement:**
- [Databases](integrations/databases.md)
- [Configuration Reference](reference/configuration.md)

## 7. Integrate with DID Workflows Without Blockchain Dependency

**Problem:** you need DID interoperability but do not want to operate blockchain infrastructure.

**JACS pattern:**
- Use JACS as the cryptographic identity/provenance layer
- Project JACS identity into DID forms (`did:web`, `did:key`, or app-specific DID) at the integration layer
- Resolve trust through DNS/local/registry without requiring on-chain components

**Where to implement:**
- [DID Integration (No Blockchain Required)](integrations/did.md)
- [A2A Interoperability](integrations/a2a.md)
