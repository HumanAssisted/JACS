# OpenClaw Integration

OpenClaw is a personal AI assistant platform. This chapter covers integrating JACS with OpenClaw to enable cryptographically signed agent-to-agent communication.

## Overview

The JACS OpenClaw plugin enables:
- **Bootstrap JACS identity** via `openclaw plugin setup jacs`
- **Securely store cryptographic keys** using OpenClaw's configuration system
- **Sign and verify all agent communications** with post-quantum cryptographic provenance
- **Publish agent identity** via `.well-known` endpoints
- **P2P agent verification** without requiring a central registry

## Installation

```bash
# Install the JACS plugin for OpenClaw
openclaw plugins install @openclaw/jacs
```

## Setup

### Initialize JACS Identity

```bash
# Interactive setup wizard
openclaw jacs init
```

This will:
1. Select a key algorithm (pq2025/dilithium/rsa/ecdsa)
2. Generate a cryptographic key pair
3. Create an agent identity
4. Store keys in `~/.openclaw/jacs_keys/`

### Configuration

The plugin configuration is stored in `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "jacs": {
        "enabled": true,
        "config": {
          "keyAlgorithm": "pq2025",
          "autoSign": false,
          "autoVerify": false,
          "agentId": "89fb9d88-6990-420f-8df9-252ccdfdfd3d",
          "agentName": "My OpenClaw Agent",
          "agentDescription": "Personal AI assistant with JACS identity"
        }
      }
    }
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keyAlgorithm` | string | `pq2025` | Signing algorithm (pq2025, pq-dilithium, rsa, ecdsa) |
| `autoSign` | boolean | `false` | Automatically sign outbound messages |
| `autoVerify` | boolean | `false` | Automatically verify inbound JACS-signed messages |
| `agentName` | string | - | Human-readable agent name |
| `agentDescription` | string | - | Agent description for A2A discovery |
| `agentDomain` | string | - | Domain for agent identity (DNSSEC validated) |

## Directory Structure

```
~/.openclaw/
├── openclaw.json              # Plugin config (non-sensitive)
├── jacs/                      # JACS data directory
│   ├── jacs.config.json       # JACS configuration
│   └── agent/                 # Agent documents
└── jacs_keys/                 # Key directory (encrypted)
    ├── agent.private.pem.enc  # AES-256-GCM encrypted
    └── agent.public.pem       # Public key (shareable)
```

## CLI Commands

### Status
```bash
openclaw jacs status
```
Shows JACS status, agent ID, algorithm, and registration state.

### Sign Document
```bash
openclaw jacs sign <file>
```
Sign a JSON document with your JACS identity.

### Verify Document
```bash
openclaw jacs verify <file>
```
Verify a JACS-signed document.

### Lookup Agent
```bash
openclaw jacs lookup <domain>
```
Look up another agent's public key from their domain.

### Export Agent Card
```bash
openclaw jacs export-card
```
Export your agent as an A2A Agent Card.

### Generate DNS Record
```bash
openclaw jacs dns-record <domain>
```
Generate DNS TXT record commands for publishing your agent fingerprint.

## Agent Tools

The plugin provides tools for use in agent conversations:

### jacs_sign

Sign a document with JACS cryptographic provenance.

```json
{
  "name": "jacs_sign",
  "parameters": {
    "document": { "message": "hello" },
    "artifactType": "message"
  }
}
```

### jacs_verify

Verify a JACS-signed document.

```json
{
  "name": "jacs_verify",
  "parameters": {
    "document": { "...signed document..." }
  }
}
```

### jacs_fetch_pubkey

Fetch another agent's public key from their domain.

```json
{
  "name": "jacs_fetch_pubkey",
  "parameters": {
    "domain": "other-agent.example.com"
  }
}
```

### jacs_verify_with_key

Verify a document using a fetched public key.

```json
{
  "name": "jacs_verify_with_key",
  "parameters": {
    "document": { "...signed document..." },
    "publicKey": "-----BEGIN PUBLIC KEY-----..."
  }
}
```

### jacs_lookup_agent

Lookup a JACS agent by domain or ID.

```json
{
  "name": "jacs_lookup_agent",
  "parameters": {
    "domain": "agent.example.com"
  }
}
```

### jacs_create_agreement

Create a multi-party agreement requiring signatures from multiple agents.

```json
{
  "name": "jacs_create_agreement",
  "parameters": {
    "document": { "terms": "..." },
    "agentIds": ["agent-1-uuid", "agent-2-uuid"],
    "question": "Do you agree to these terms?"
  }
}
```

## Well-Known Endpoints

When OpenClaw's gateway is running, the plugin serves:

### `/.well-known/agent-card.json`

A2A v0.4.0 Agent Card with JACS extension.

### `/.well-known/jacs-pubkey.json`

Your agent's public key for verification:

```json
{
  "publicKey": "-----BEGIN PUBLIC KEY-----...",
  "publicKeyHash": "sha256-hash",
  "algorithm": "pq2025",
  "agentId": "agent-uuid",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## P2P Agent Verification

Agents can verify each other without a central registry:

### Flow

1. **Agent A** publishes their public key at `/.well-known/jacs-pubkey.json`
2. **Agent A** optionally sets DNS TXT record at `_v1.agent.jacs.<domain>.`
3. **Agent A** signs a document with `jacs_sign`
4. **Agent B** receives the signed document
5. **Agent B** fetches Agent A's key with `jacs_fetch_pubkey`
6. **Agent B** verifies with `jacs_verify_with_key`

### Example Workflow

```
Agent A (agent-a.example.com)          Agent B (agent-b.example.com)
================================       ================================

1. Initialize JACS
   openclaw jacs init

2. Publish public key
   (served at /.well-known/jacs-pubkey.json)

3. Sign a message
   jacs_sign({ message: "hello" })
   → signed_doc

4. Send signed_doc to Agent B
                                       5. Receive signed_doc

                                       6. Fetch Agent A's public key
                                          jacs_fetch_pubkey("agent-a.example.com")
                                          → pubkey_a

                                       7. Verify signature
                                          jacs_verify_with_key(signed_doc, pubkey_a)
                                          → { valid: true, signer: "agent-a-uuid" }
```

## DNS-Based Discovery

For additional verification, agents can publish their public key fingerprint in DNS:

### Generate DNS Record

```bash
openclaw jacs dns-record agent.example.com
```

This outputs commands for your DNS provider:

```
_v1.agent.jacs.agent.example.com. 3600 IN TXT "v=hai.ai; jacs_agent_id=<UUID>; alg=SHA-256; enc=base64; jac_public_key_hash=<44-char-b64>"
```

### DNS Lookup

```bash
openclaw jacs lookup agent.example.com
```

The plugin will:
1. Query DNS TXT record at `_v1.agent.jacs.agent.example.com`
2. Fetch full public key from `/.well-known/jacs-pubkey.json`
3. Verify the DNS hash matches the fetched key

## Security

### Key Protection

- Private keys are encrypted with AES-256-GCM
- Password-derived key using PBKDF2 (100k iterations)
- Keys stored with restricted file permissions

### Post-Quantum Cryptography

The default algorithm (`pq2025` / ML-DSA-87) is quantum-resistant, providing protection against future quantum computing attacks.

### Signature Binding

Signatures include:
- Document hash (prevents modification)
- Signer's agent ID and version
- Timestamp
- List of signed fields

## Skill Usage

The plugin provides a skill for agent conversations:

```
/jacs sign {"task": "analyze data", "result": "completed"}
/jacs verify <paste signed document>
/jacs lookup agent.example.com
```

## Troubleshooting

### "JACS not initialized"

Run `openclaw jacs init` to set up your JACS identity.

### "Failed to fetch public key"

Verify the domain is correct and serving `/.well-known/jacs-pubkey.json`.

### "Signature verification failed"

- Check that the document hasn't been modified
- Verify you have the correct public key for the signer
- Ensure the signing algorithm matches

## Next Steps

- [DNS-Based Verification](../rust/dns.md) - Detailed DNS setup
- [Agreements](../rust/agreements.md) - Multi-agent coordination
- [MCP Integration](mcp.md) - Model Context Protocol
