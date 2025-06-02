**JACS (JSON Agent Communication Standard)**, is a framework for creating, signing, and verifying JSON documents with cryptographic integrity, designed specifically for AI agent identity, authentication, authorizaiton, communication, and task management.

## Use cases 

- **Create and sign** JSON documents with cryptographic signatures
- **Verify authenticity** and integrity of documents, requests, identities
- **Manage tasks and agreements** between multiple agents
- **Maintain audit trails** with modifications and versioning
- **Provide mutual opt-in identity and trust** in multi-agent systems

## Features

JACS provides middleware applicable to http, email, mpc (json-rpc), a2a,

- **Cryptographic Security**: RSA, Ed25519, and post-quantum algorithms
- **JSON Schema Validation**: Enforced document structure
- **Multi-Agent Agreements**: Formats that allow for multiple signatures
- **Full Audit Trail**: Complete versioning and modification history
- **Multiple Languages**: Rust, Node.js, and Python implementations
- **MCP Integration**: Native Model Context Protocol support
- **Observabile**: Meta data available as OpenTelemetry




----- Outline for presentation

# How did I end up here

Small Starutps

Origin Story: Email, Web
Verified Humans needed.

# Trust, but how?

Protection of Content
Intent
Consent


# existing technologies

- secure, well understood, 
- aren't hetrogeneous, unified enough
- rules
- qualitative anomoly detection

# PGP

# kerberos

# JWT

# centralized RBAC



JACS

# JSON is used everywhere
JSON RPC is MCP, JSON Schema in Open API and structured responses in OpenAI

# checksums not enough
- timestamp
- author

# creates a header


