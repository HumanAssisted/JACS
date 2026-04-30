# JACS: JSON Agent Communication Standard

JACS is an open source provenance layer for agent systems. Use it when an output, tool call, file, image, email, or agent handoff crosses a trust boundary and logs alone are not enough.

## Start With The Boundary

Most deployments start in one of four places:

- **Core signing**: sign JSON, files, Markdown/text, images, or Rust email payloads directly.
- **MCP**: run `jacs mcp` as a local tool server, or add signing around an existing MCP transport.
- **Frameworks**: add provenance at LangChain, LangGraph, FastAPI, Express, Koa, or Vercel AI SDK boundaries.
- **A2A and agreements**: exchange signed artifacts or require multiple agents to sign off.

## What JACS Gives You

- Persistent agent identity with encrypted private keys
- Tamper-evident signed JSON and file envelopes
- Inline Markdown/text signatures that stay readable in place
- Embedded PNG/JPEG/WebP signatures for media provenance
- Rust email signing and verification with field-level content hashes
- Trust policies and local trust-store workflows
- Cross-language verification across Rust, Python, Node.js, and Go

For platform workflows around verified documents, agent behavior, benchmarks, and hosted JACS identity flows, see [HumanAssisted/haiai](https://github.com/HumanAssisted/haiai).

## Best Entry Points

1. [Which Integration?](getting-started/decision-tree.md)
2. [Quick Start](getting-started/quick-start.md)
3. [Use Cases](usecases.md)
4. [MCP Overview](integrations/mcp.md)
5. [Inline Text Signatures](guides/inline-text-signing.md)
6. [Image and Media Signatures](guides/media-signing.md)
7. [Email Signing and Verification](guides/email-signing.md)

## Install

### Rust CLI and MCP server

```bash
cargo install jacs-cli
jacs quickstart --name my-agent --domain my-agent.example.com
jacs mcp
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

## What This Book Does Not Claim

- MCP and A2A are different boundaries: MCP is model-to-tool; A2A is agent-to-agent discovery and exchange.
- JACS does not require a registry, blockchain, or central server.
- Email signing is currently documented as a Rust core API, not a CLI or Python/Node/Go binding surface.

## Community

- [GitHub Repository](https://github.com/HumanAssisted/JACS)
- [Issue Tracker](https://github.com/HumanAssisted/JACS/issues)
