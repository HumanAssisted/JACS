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

## 4. Sign Markdown In Place For Cross-Team Review

**Use this when:** a shared README or design doc moves through a multi-agent review and you want each reviewer's identity and claimed timestamp attached to the exact bytes they signed off on — without a sidecar JSON.

**Recommended JACS path:**

- [Inline Text Signatures](guides/inline-text-signing.md)

```bash
JACS_CONFIG=./reviewer-a.config.json jacs sign-text DESIGN.md
JACS_CONFIG=./reviewer-b.config.json jacs sign-text DESIGN.md
jacs verify-text DESIGN.md
```

```python
import jacs.simple as jacs
jacs.load("./jacs.config.json")
jacs.sign_text("DESIGN.md")
result = jacs.verify_text("DESIGN.md")
print(result.status)  # 'signed'
```

**What JACS adds:**

- Signature appended at the end in a YAML-bodied block; file still renders as markdown on GitHub
- Unordered multi-signer; each block carries signer ID, claimed time, and content hash
- Permissive verify by default (missing-signature is exit 2, not an error); `--strict` opts in to error-on-missing

## 5. Embed Image Provenance For AI-Era Authorship Claims

**Use this when:** a photo, AI render, or chart needs a verifiable signed-at-claimed-time provenance signature embedded *inside* the image so downstream consumers can verify identity without a sidecar.

**Recommended JACS path:**

- [Image and Media Signatures](guides/media-signing.md)

```bash
jacs sign-image photo.png --out signed.png
jacs verify-image signed.png
jacs extract-media-signature signed.png | jq .signedAt
```

```typescript
import * as jacs from '@hai.ai/jacs/simple';
await jacs.load('./jacs.config.json');
await jacs.signImage('photo.png', 'signed.png');
const v = await jacs.verifyImage('signed.png');
console.log(v.status);  // 'valid'
```

**What JACS adds:**

- Signature embedded in PNG iTXt / JPEG APP11 / WebP XMP — no sidecar file
- 100% Rust, Apache-2.0 / MIT, zero AGPL dependencies
- Optional `--robust` LSB fallback for PNG/JPEG when metadata-strip is a concern

## 6. Sign HTTP Or API Boundaries Without MCP

**Use this when:** the boundary is an API route, not an MCP transport.

**Recommended JACS path:**

- [Python Framework Adapters](python/adapters.md) for FastAPI
- [Express Middleware](nodejs/express.md)
- [Koa Middleware](nodejs/koa.md)

**What JACS adds:**

- Signed JSON responses
- Verified inbound requests
- A clean upgrade path to A2A discovery on the same app boundary

## 7. Run Multi-Agent Approval Workflows

**Use this when:** multiple agents must sign off on the same document, deployment, or decision.

**Recommended JACS path:**

- [Multi-Agent Agreements](getting-started/multi-agent-agreement.md)
- [Rust Agreements](rust/agreements.md)

**What JACS adds:**

- M-of-N quorum
- Timeout and algorithm constraints
- Verifiable signature chain across signers

## 8. Keep Signed Files Or JSON As Durable Artifacts

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

## 9. Publish Public Identity Without A Central Auth Service

**Use this when:** external systems need to verify your agent identity but you do not want a shared auth server in the middle.

**Recommended JACS path:**

- [DNS-Based Verification](rust/dns.md)
- [DNS Trust Anchoring](advanced/dns-trust.md)

**What JACS adds:**

- Public key fingerprint anchoring
- DNS-based verification flows
- Local private-key custody
