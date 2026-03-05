[Introduction](README.md)

# User Guide

## Getting Started
- [What is JACS?](getting-started/what-is-jacs.md)
- [Core Concepts](getting-started/concepts.md)
- [Quick Start](getting-started/quick-start.md)
- [Which Integration?](getting-started/decision-tree.md)
- [Multi-Agent Agreements](getting-started/multi-agent-agreement.md)
- [Verifying Signed Documents](getting-started/verification.md)
- [What Is an Attestation?](getting-started/attestation.md)
- [Use cases](usecases.md)
- [Deployment Compatibility](getting-started/deployment.md)
- [Troubleshooting](getting-started/troubleshooting.md)

## Rust CLI & Library
- [Installation](rust/installation.md)
- [CLI Tutorial](rust/cli.md)
- [Creating an Agent](rust/agent.md)
- [Working with Documents](rust/documents.md)
- [Creating and Using Agreements](rust/agreements.md)
- [DNS-Based Verification](rust/dns.md)
- [Rust Library API](rust/library.md)
- [Observability (Rust API)](rust/observability.md)

## Node.js (@hai.ai/jacs)
- [Installation](nodejs/installation.md)
- [Simplified API](nodejs/simple-api.md)
- [Basic Usage](nodejs/basic-usage.md)
- [LangChain.js](nodejs/langchain.md)
- [Vercel AI SDK](nodejs/vercel-ai.md)
- [Express Middleware](nodejs/express.md)
- [Koa Middleware](nodejs/koa.md)
- [MCP Integration (Node.js)](nodejs/mcp.md)
- [HTTP Server](nodejs/http.md)
- [API Reference](nodejs/api.md)

## Python (jacs)
- [Installation](python/installation.md)
- [Simplified API](python/simple-api.md)
- [Basic Usage](python/basic-usage.md)
- [Framework Adapters](python/adapters.md)
- [MCP Integration (Python)](python/mcp.md)
<!-- - [FastMCP Integration](python/fastmcp.md) -->
- [API Reference](python/api.md)

## Go (jacsgo)
- [Installation & Quick Start](go/installation.md)

## Schemas
- [JSON Schemas](schemas/overview.md)
- [Agent Schema](schemas/agent.md)
- [Document Schema](schemas/document.md)
- [Task Schema](schemas/task.md)
- [Agent State Schema](schemas/agentstate.md)
- [Commitment Schema](schemas/commitment.md)
- [Todo List Schema](schemas/todo.md)
- [Conversation Schema](schemas/conversation.md)
- [Config File Schema](schemas/configuration.md)

## Concepts
- [JACS Attestation vs. Other Standards](concepts/attestation-comparison.md)

## Advanced Topics
- [Security Model](advanced/security.md)
- [Key Rotation](advanced/key-rotation.md)
- [Cryptographic Algorithms](advanced/crypto.md)
- [Algorithm Selection Guide](advanced/algorithm-guide.md)
- [Storage Backends](advanced/storage.md)
- [Custom Schemas](advanced/custom-schemas.md)
- [Trust Store](advanced/trust-store.md)
- [Infrastructure vs Tools](advanced/infrastructure.md)
- [DNS Trust Anchoring](advanced/dns-trust.md)
- [Failure Modes](advanced/failure-modes.md)
- [Testing](advanced/testing.md)

## Integrations
- [MCP Overview](integrations/mcp.md)
- [A2A Interoperability](integrations/a2a.md)
- [DID Integration (No Blockchain Required)](integrations/did.md)
- [HAI.ai Platform](integrations/hai.md)
- [OpenClaw](integrations/openclaw.md)
- [Web Servers](integrations/web-servers.md)
- [Databases](integrations/databases.md)

## Guides
- [A2A Quickstart](guides/a2a-quickstart.md)
  - [Serve Your Agent Card](guides/a2a-serve.md)
  - [Discover & Trust Remote Agents](guides/a2a-discover.md)
  - [Exchange Signed Artifacts](guides/a2a-exchange.md)
- [Sign vs. Attest Decision Guide](guides/sign-vs-attest.md)
- [Attestation Tutorial](guides/attestation-tutorial.md)
- [Writing a Custom Evidence Adapter](guides/custom-adapters.md)
- [Framework Adapter Attestation Guide](guides/framework-attestation.md)
- [Observability & Monitoring Guide](guides/observability.md)
- [Email Signing & Verification](guides/email-signing.md)
- [Streaming Signing](guides/streaming.md)

## Examples
- [CLI Examples](examples/cli.md)
- [Node.js Examples](examples/nodejs.md)
- [Python Examples](examples/python.md)
- [Integration Examples](examples/integrations.md)

# Reference
- [CLI Command Reference](reference/cli-commands.md)
- [Configuration Reference](reference/configuration.md)
- [Error Codes](reference/errors.md)
- [Attestation Verification Results](reference/attestation-errors.md)
- [Attestation CLI Reference](reference/attest-cli.md)
- [Migration Guide](reference/migration.md)

-----------

<!-- [Contributors](misc/contributors.md)  -->
