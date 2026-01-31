# @openclaw/jacs

JACS (JSON Agent Communication Standard) cryptographic provenance plugin for OpenClaw.

Add post-quantum cryptographic signatures to all your agent communications.

## Features

- **Post-Quantum Cryptography**: ML-DSA-87 (pq2025) signatures resistant to quantum attacks
- **Document Signing**: Sign any JSON document with verifiable provenance
- **A2A Discovery**: Expose `.well-known` endpoints for agent discovery
- **Multi-Party Agreements**: Create documents requiring multiple agent signatures
- **DNS-Based Discovery**: DNSSEC-validated agent discovery via DNS TXT records

## Installation

```bash
openclaw plugins install @openclaw/jacs
```

## Quick Start

### 1. Initialize JACS

```bash
openclaw jacs init
```

This will:
- Generate a post-quantum key pair
- Create your agent identity
- Set up encrypted key storage

### 2. Sign a Document

```bash
openclaw jacs sign document.json
```

Or use the tool in conversation:
```
Sign this with JACS: {"task": "completed", "result": "success"}
```

### 3. Verify a Document

```bash
openclaw jacs verify signed-document.json
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `openclaw jacs init` | Initialize JACS with key generation |
| `openclaw jacs status` | Show agent status and configuration |
| `openclaw jacs sign <file>` | Sign a document |
| `openclaw jacs verify <file>` | Verify a signed document |
| `openclaw jacs export-card` | Export A2A Agent Card |
| `openclaw jacs dns-record <domain>` | Generate DNS TXT record |
| `openclaw jacs hash <string>` | Hash a string |

## Agent Tools

| Tool | Description |
|------|-------------|
| `jacs_sign` | Sign a document with provenance |
| `jacs_verify` | Verify a signed document |
| `jacs_create_agreement` | Create multi-party agreement |
| `jacs_sign_agreement` | Sign an agreement |
| `jacs_check_agreement` | Check agreement status |
| `jacs_hash` | Hash content |
| `jacs_identity` | Get agent identity |

## Well-Known Endpoints

When running, your agent exposes:

- `/.well-known/agent-card.json` - A2A Agent Card
- `/.well-known/jacs-pubkey.json` - Public key
- `/.well-known/jacs-extension-descriptor.json` - JACS extension info
- `/jacs/verify` - Document verification (POST)
- `/jacs/status` - Health check (GET)

## Configuration

In `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "jacs": {
        "enabled": true,
        "config": {
          "keyAlgorithm": "pq2025",
          "autoSign": false,
          "autoVerify": true,
          "agentName": "My Agent",
          "agentDescription": "A helpful agent",
          "agentDomain": "example.com"
        }
      }
    }
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keyAlgorithm` | string | `pq2025` | Signing algorithm |
| `autoSign` | boolean | `false` | Auto-sign outbound messages |
| `autoVerify` | boolean | `true` | Auto-verify inbound messages |
| `agentName` | string | - | Human-readable name |
| `agentDescription` | string | - | Agent description |
| `agentDomain` | string | - | DNSSEC-validated domain |

## Algorithms

| Algorithm | Type | Quantum Safe |
|-----------|------|--------------|
| `pq2025` (ML-DSA-87) | Post-Quantum | Yes |
| `pq-dilithium` | Post-Quantum | Yes |
| `ring-Ed25519` | Traditional | No |
| `RSA-PSS` | Traditional | No |

## Security

- Private keys encrypted with AES-256-GCM
- PBKDF2 key derivation with 100,000 iterations
- Secure file permissions (0600/0700)
- Version UUIDs prevent replay attacks

## DNS Discovery

Set up DNS TXT record for agent discovery:

```bash
openclaw jacs dns-record example.com
```

Add the output to your DNS provider. Other agents can then verify your identity via DNSSEC.

## License

Apache-2.0

## Links

- [JACS Documentation](https://hai.ai/jacs)
- [A2A Protocol](https://google.github.io/a2a/)
- [OpenClaw](https://openclaw.ai)
