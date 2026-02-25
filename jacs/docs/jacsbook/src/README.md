# JACS: JSON Agent Communication Specification

JACS is a cryptographic provenance layer for agent systems. It helps you prove who produced a payload, whether it changed, and whether you trust the signer.

## Start With Real Use Cases

Teams usually adopt JACS for one or more of these:

- **Secure MCP servers**: sign JSON-RPC requests/responses so tools are not blindly trusted
- **Agent frameworks**: add signing/verification to LangChain, LangGraph, CrewAI, FastAPI, Express, and Vercel AI flows
- **A2A interoperability**: exchange signed artifacts across organizations with trust policies
- **File and artifact custody**: sign JSON, files, and attachments to preserve origin and integrity
- **Database-backed provenance**: store signed records with queryable metadata and periodic re-verification
- **Internet-scale identity**: publish public key fingerprints in DNS and verify with DNSSEC
- **DID compatibility**: map JACS agent identity to DID workflows without requiring any blockchain

See [Use cases](usecases.md) for deployment-oriented narratives.

## Key Features

- **Cryptographic signing and verification** for JSON payloads, files, and artifacts
- **Encrypted private key handling** with password-based key protection
- **Algorithm support** for `ring-Ed25519`, `RSA-PSS`, and `pq2025` (ML-DSA-87 / FIPS-204)
- **Multi-agent agreements** including quorum and algorithm constraints
- **Schema-aware documents** built on JSON Schema
- **Auditability and versioning** through immutable signatures and document history
- **Storage flexibility** across local storage and database-backed deployments
- **MCP and A2A integration** for both intra-app and cross-boundary agent workflows
- **Observability hooks** for production operations
- **Cross-language implementations** in Rust, Node.js, Python, and Go

## Standards and Interop

JACS is designed to work with existing standards instead of replacing them:

- **MCP** for model-to-tool transport inside app boundaries
- **A2A** for agent discovery and exchange across org boundaries
- **JSON / JSON Schema** for payload compatibility
- **DNS / DNSSEC** for public key fingerprint anchoring
- **DID ecosystems** via application-level identity mapping guidance (no blockchain dependency)

## Implementations

### Rust (core library + CLI)
- Deepest feature surface and operational controls
- CLI for agent/key/document operations
- Strong production ergonomics (including observability options)

### Node.js (`@hai.ai/jacs`)
- Strong web and middleware integration
- Native MCP transport proxy support
- Good fit for Express/Koa/Vercel AI/LangChain.js

### Python (`jacs`)
- Strong framework adapters and AI workflow ergonomics
- Native MCP/A2A helpers
- Good fit for LangChain/LangGraph/CrewAI/FastAPI

### Go (`jacsgo`)
- Community-maintained bindings for signing and verification
- Strong fit for Go services needing signed JSON and file provenance
- See [Go quick start](go/installation.md)

## Quick Start

### Rust CLI
```bash
cargo install jacs --features cli
jacs init
```

### Node.js
```bash
npm install @hai.ai/jacs
```

### Python
```bash
pip install jacs
```

### Go
```bash
go get github.com/HumanAssisted/JACS/jacsgo
```

## Identity Model (Including DID)

JACS identity is based on cryptographic keys and stable agent IDs. You can operate entirely without a registry, blockchain, or token authority:

- Use local trust stores for private environments
- Use DNS TXT + DNSSEC for public verification
- Use registry lookup when desired
- Add DID representations as an interoperability layer in your app

JACS can participate in DID-centered architectures, but it does not require blockchain infrastructure to function.

> DID note: JACS does not currently ship a first-class DID resolver/method implementation in core bindings. The DID chapter documents integration patterns.

## Where to Go Next

1. [Which Integration?](getting-started/decision-tree.md)
2. [MCP Overview](integrations/mcp.md)
3. [A2A Interoperability](integrations/a2a.md)
4. [Databases](integrations/databases.md)
5. [DNS-Based Verification](rust/dns.md)
6. [DID Integration (No Blockchain Required)](integrations/did.md)

## Community

- [GitHub Repository](https://github.com/HumanAssisted/JACS)
- [Issue Tracker](https://github.com/HumanAssisted/JACS/issues)
