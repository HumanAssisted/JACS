# JACS MCP Server

MCP server for JACS agent identity, generic document signing and verification, agreements, A2A artifacts, attestations, trust-store operations, and media/text signing.

Uses **stdio transport only** for security. The server holds the agent's private key, so no HTTP endpoints are exposed.

The checked-in contract snapshot for downstream adapters lives at [`contract/jacs-mcp-contract.json`](contract/jacs-mcp-contract.json).

## What can it do?

The server exposes tools in these categories:

### Document Sign / Verify

| Tool | Description |
|------|-------------|
| `jacs_sign_document` | Sign arbitrary JSON content to create a signed JACS document |
| `jacs_verify_document` | Verify a signed JACS document given its full JSON string |

### Agent Management

| Tool | Description |
|------|-------------|
| `jacs_create_agent` | Create a new JACS agent with cryptographic keys, when explicitly enabled |
| `jacs_reencrypt_key` | Re-encrypt the agent's private key with a new password |
| `jacs_rotate_keys` | Rotate the active agent key material |

### Agreements

| Tool | Description |
|------|-------------|
| `jacs_create_agreement` | Create a multi-party agreement over arbitrary document content |
| `jacs_sign_agreement` | Co-sign an existing agreement |
| `jacs_check_agreement` | Check agreement status, quorum, expiration, and missing signatures |

### A2A Discovery and Artifacts

| Tool | Description |
|------|-------------|
| `jacs_export_agent_card` | Export the local agent's A2A Agent Card |
| `jacs_generate_well_known` | Generate A2A `.well-known` documents |
| `jacs_export_agent` | Export the local agent's full JACS JSON document |
| `jacs_wrap_a2a_artifact` | Wrap an A2A artifact with JACS provenance |
| `jacs_verify_a2a_artifact` | Verify a JACS-wrapped A2A artifact |
| `jacs_assess_a2a_agent` | Assess the trust level of a remote A2A agent |

### Trust Store

| Tool | Description |
|------|-------------|
| `jacs_trust_agent` | Add an agent to the local trust store |
| `jacs_untrust_agent` | Remove an agent from the local trust store, when explicitly enabled |
| `jacs_list_trusted_agents` | List trusted agent IDs |
| `jacs_is_trusted` | Check whether an agent is trusted |
| `jacs_get_trusted_agent` | Retrieve a trusted agent JSON document |

### Attestation

| Tool | Description |
|------|-------------|
| `jacs_attest_create` | Create a signed attestation with claims |
| `jacs_attest_verify` | Verify an attestation |
| `jacs_attest_lift` | Lift a signed document into an attestation |
| `jacs_attest_export_dsse` | Export an attestation as a DSSE envelope |

### Search, Text, and Media

| Tool | Description |
|------|-------------|
| `jacs_search` | Search signed documents |
| `jacs_sign_text` | Sign a markdown/text file in place |
| `jacs_verify_text` | Verify inline text signatures |
| `jacs_sign_image` | Sign PNG/JPEG/WebP media by embedding metadata |
| `jacs_verify_image` | Verify an embedded media signature |
| `jacs_extract_media_signature` | Extract embedded JACS media payloads |

## Quick Start

### Step 1: Install JACS CLI

```bash
cargo install jacs-cli
```

### Step 2: Create Agent and Keys

```bash
jacs init
```

### Step 3: Start the MCP Server

The MCP server is built into the `jacs` binary.

```bash
jacs mcp
```

### Step 4: Configure Your MCP Client

```json
{
  "mcpServers": {
    "jacs": {
      "command": "jacs",
      "args": ["mcp"],
      "env": {
        "JACS_CONFIG": "/path/to/jacs.config.json",
        "JACS_PRIVATE_KEY_PASSWORD": "your-secure-password"
      }
    }
  }
}
```

## Configuration

Required:

- `JACS_CONFIG` - Path to your `jacs.config.json` file
- `JACS_PRIVATE_KEY_PASSWORD` - Password for decrypting your private key

Optional:

- `RUST_LOG` - Logging level, default `info,rmcp=warn`
- `JACS_MCP_ALLOW_REGISTRATION` - Set to `true` to enable `jacs_create_agent`
- `JACS_MCP_ALLOW_UNTRUST` - Set to `true` to enable `jacs_untrust_agent`

## Core Document Tools

### `jacs_sign_document`

Sign arbitrary JSON content to create a cryptographically signed JACS document.

Parameters:

- `content` - JSON content to sign
- `content_type` - MIME type, default `application/json`

### `jacs_verify_document`

Verify a signed JACS document in memory.

Parameters:

- `document` - Full signed JACS document JSON string

## Agreement Tools

### `jacs_create_agreement`

Create an agreement that other agents can co-sign.

Parameters:

- `document` - JSON document that parties will agree to
- `agent_ids` - Required signer agent IDs
- `question` - Human-readable question for signers
- `context` - Additional context
- `timeout` - Optional ISO 8601 deadline
- `quorum` - Optional M-of-N signer threshold
- `required_algorithms` - Optional signing algorithm allowlist
- `minimum_strength` - Optional strength requirement

### `jacs_sign_agreement`

Co-sign an existing agreement.

### `jacs_check_agreement`

Check whether an agreement is complete, expired, or still missing signatures.
