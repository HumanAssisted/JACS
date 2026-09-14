# Use Cases

These are current JACS use cases, not speculative integrations.

## 1. Keep JSON and files verifiable

Use JACS when a report, memory, config, policy, or audit artifact needs to stay verifiable after it leaves the process that created it.

**Start with:**

- [Quick Start](getting-started/quick-start.md)
- [Verifying Signed Documents](getting-started/verification.md)
- [Working with Documents](rust/documents.md)

**What JACS adds:**

- Self-contained signed envelopes
- Re-verification at read time
- Cross-language compatibility across Rust, Python, Node.js, and Go

## 2. Sign Markdown in place for review

Use JACS when a README, design doc, policy, or release note needs visible content and verifiable sign-off in the same file.

**Start with:**

- [Inline Text Signatures](guides/inline-text-signing.md)

```bash
JACS_CONFIG=./reviewer-a.config.json jacs sign-text DESIGN.md
JACS_CONFIG=./reviewer-b.config.json jacs sign-text DESIGN.md
jacs verify-text DESIGN.md
```

**What JACS adds:**

- A readable signature block appended at the end
- Multi-signer review without sidecar JSON
- Permissive or strict verification modes

## 3. Embed provenance in images

Use JACS when a photo, chart, screenshot, or AI-generated image needs verifiable signer identity without a separate metadata file.

**Start with:**

- [Image and Media Signatures](guides/media-signing.md)

```bash
jacs sign-image photo.png --out signed.png
jacs verify-image signed.png
jacs extract-media-signature signed.png
```

**What JACS adds:**

- Embedded PNG iTXt, JPEG APP11, or WebP XMP signatures
- Pixel-content integrity checks
- Optional robust mode for PNG/JPEG metadata-strip threat models

## 4. Sign email with Rust

Use JACS when raw RFC 5322 email needs a verifiable signature attachment and field-level content verification.

**Start with:**

- [Email Signing and Verification](guides/email-signing.md)

**What JACS adds:**

- `jacs-signature.json` MIME attachment
- Header, body, and attachment hashes
- Forwarding chains through parent signature hashes

Email signing is currently documented as a Rust core API via `jacs::email`, not as a CLI or Python/Node/Go binding surface.

## 5. Secure a local MCP tool server

Use JACS when an MCP client needs local document signing or supplied-key integrity checks.

**Start with:**

- [MCP Overview](integrations/mcp.md)

For keyless verification, install the CLI and start the explicit verification profile:

```bash
cargo install jacs-cli
jacs mcp --profile verify-only
```

For document signing, configure a [password source](getting-started/quick-start.md#password-bootstrap)
before creating an identity, or use an existing signing config. Then start the
explicit signing profile:

```bash
jacs quickstart --name mcp-agent --domain mcp-agent.example
jacs mcp --profile local-sign --config ./jacs.config.json
```

To also enable scoped text/image tools, prefix the final command with
`JACS_MCP_BASE_DIR=/path/to/content`. Each server command runs until the MCP
client closes it; verification and signing are alternative startup choices.

**What JACS adds:**

- A ready-made stdio MCP server
- Explicit-key document verification by default; JSON/Agreement tools with `local-sign`
- Five text/image tools only with `local-sign`, a signing config and `JACS_MCP_BASE_DIR`
- Local private-key custody; no HTTP listener

Signatures establish key-backed provenance, not per-action human approval,
truth or authority. Loading a config alone does not grant signing. Trust/admin
capabilities remain unavailable through these profiles; inspect `tools/list`
for the running process's actual inventory.

## 6. Add provenance to framework boundaries

Use JACS when an existing app already has a boundary such as LangChain tool output, FastAPI response, Express middleware, or Koa middleware.

**Start with:**

- [Python Framework Adapters](python/adapters.md)
- [Node.js LangChain.js](nodejs/langchain.md)
- [Express Middleware](nodejs/express.md)
- [Koa Middleware](nodejs/koa.md)

**What JACS adds:**

- Signed tool results and responses
- Optional strict verification at adapter boundaries
- Minimal changes to existing framework code

## 7. Exchange artifacts across agents or organizations

Use JACS when one agent produces work that another agent, service, or organization must verify before acting on it.

**Start with:**

- [A2A Interoperability](integrations/a2a.md)
- [A2A Quickstart](guides/a2a-quickstart.md)
- [Multi-Agent Agreements](getting-started/multi-agent-agreement.md)

**What JACS adds:**

- Signed A2A artifacts
- Trust policies for admission control
- Agreement-v2 inspection of mathematical signature coverage; M-of-N, role,
  status and algorithm policy claims require separate application evaluation

Agreement-v2 math is not policy acceptance: its native `valid` and
`policyAccepted` stay false. Quorum counts, human/notary labels and final status
cannot establish human approval or authority. See the
[Agreement-v2 guide](guides/agreement-v2.md) for the inspection/report distinction.

## 8. Publish identity without a central auth service

Use JACS when external systems need to verify an agent identity without putting a shared server in the middle.

**Start with:**

- [DNS-Based Verification](rust/dns.md)
- [DNS Trust Anchoring](advanced/dns-trust.md)

**What JACS adds:**

- Public key fingerprint anchoring
- Local trust-store workflows
- Local private-key custody

## 9. Add hosted verification with HAI.AI

Use [HumanAssisted/haiai](https://github.com/HumanAssisted/haiai) when you want platform workflows for verified documents, agent behavior, benchmarks, and hosted JACS identity flows.

JACS remains the local open source signing and verification layer. HAI.AI is the hosted platform path around those identities and artifacts.
