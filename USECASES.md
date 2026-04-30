# JACS use cases

JACS is useful when an artifact must remain verifiable after it leaves the process, service, or team that produced it. These examples focus on the current open source surfaces in this repo.

## Verify JSON and files from a specific agent

A build service, research agent, or data pipeline can sign reports, configs, memories, and audit artifacts as they are produced.

1. Create or load a JACS agent.
2. Sign with `jacs document create`, `sign_message`, or `sign_file`.
3. Verify later with `jacs verify`, `verify()`, or `verify_standalone()`.

This proves the artifact was signed by the expected agent key and has not been changed since signing.

## Counter-sign Markdown reviews

Shared READMEs, design docs, policies, and release notes can carry their own signatures.

```bash
JACS_CONFIG=./reviewer-a.config.json jacs sign-text DESIGN.md
JACS_CONFIG=./reviewer-b.config.json jacs sign-text DESIGN.md
jacs verify-text DESIGN.md
```

The file still renders as Markdown. Each signature block records signer identity, claimed time, and content hash.

## Embed provenance in images

Photos, screenshots, charts, and AI-generated images can carry JACS provenance inside the image file.

```bash
jacs sign-image photo.png --out signed.png
jacs verify-image signed.png
jacs extract-media-signature signed.png
```

PNG, JPEG, and WebP are supported. The signature verifies the signer and pixel-content integrity; it does not prove first creation or legal ownership.

## Sign raw email in Rust

The Rust `jacs::email` module signs RFC 5322 `.eml` bytes by adding a `jacs-signature.json` MIME attachment. Verification checks the JACS signature and compares hashes for important headers, body parts, and attachments.

See the [email signing guide](https://humanassisted.github.io/JACS/guides/email-signing.html).

## Secure local MCP workflows

The CLI installs a single `jacs` binary with a built-in stdio MCP server:

```bash
cargo install jacs-cli
jacs mcp
```

Use this when an MCP client needs local signing, verification, trust, audit, and provenance tools without exposing a network listener.

## Add provenance to framework boundaries

Python and Node adapters can sign and verify data at framework boundaries such as LangChain, LangGraph, FastAPI, Express, Koa, Vercel AI SDK, and MCP transports.

Start with the boundary that already exists in your application, then add stricter trust policy only when another service, team, or organization consumes the result.

## Exchange signed artifacts across agents

For agent-to-agent or cross-organization exchange, use A2A artifact signing and JACS trust policies. For multi-party sign-off, use JACS agreements with quorum, timeout, and algorithm constraints.

See the [A2A interoperability guide](https://humanassisted.github.io/JACS/integrations/a2a.html) and [multi-agent agreements](https://humanassisted.github.io/JACS/getting-started/multi-agent-agreement.html).

## Add hosted verification with HAI.AI

For verified documents, agent behavior, benchmarks, and platform workflows built around JACS identities, use [HumanAssisted/haiai](https://github.com/HumanAssisted/haiai). JACS remains the local open source signing and verification layer; HAI.AI is the hosted platform path.
