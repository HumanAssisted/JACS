# JACS MCP Server

A Model Context Protocol (MCP) server for **data provenance and cryptographic signing** of agent state, messaging, agreements, and A2A interoperability.

JACS (JSON Agent Communication Standard) ensures that every file, memory, or configuration an AI agent touches can be signed, verified, and traced back to its origin -- no server required.

## What can it do?

The server exposes **29 tools** in eight categories:

### Agent State (Data Provenance)

Sign, verify, and manage files that represent agent state (memories, skills, plans, configs, hooks):

| Tool | Description |
|------|-------------|
| `jacs_sign_state` | Sign a file to create a cryptographically signed JACS document |
| `jacs_verify_state` | Verify state document integrity/signature by JACS document ID (`jacs_id`). Path-based verification is deprecated for MCP security. |
| `jacs_load_state` | Load a signed state document by JACS document ID (`jacs_id`), optionally verifying first |
| `jacs_update_state` | Update a signed state document by JACS document ID (`jacs_id`) and re-sign |
| `jacs_list_state` | List signed agent state documents with optional filtering |
| `jacs_adopt_state` | Adopt an external file as signed state, recording its origin |

### Agent Management

| Tool | Description |
|------|-------------|
| `jacs_create_agent` | Create a new JACS agent with cryptographic keys (requires `JACS_MCP_ALLOW_REGISTRATION=true`) |
| `jacs_reencrypt_key` | Re-encrypt the agent's private key with a new password |

### Security

| Tool | Description |
|------|-------------|
| `jacs_audit` | Run a read-only security audit and health checks (risks, health_checks, summary). Optional: `config_path`, `recent_n`. |

### Messaging

Send and receive cryptographically signed messages between agents:

| Tool | Description |
|------|-------------|
| `jacs_message_send` | Create and sign a message for another agent |
| `jacs_message_update` | Update and re-sign an existing message |
| `jacs_message_agree` | Verify and co-sign a received message |
| `jacs_message_receive` | Verify a received message and extract its content |

### Document Sign / Verify

Sign and verify arbitrary documents without requiring file paths or agent state metadata:

| Tool | Description |
|------|-------------|
| `jacs_sign_document` | Sign arbitrary JSON content to create a signed JACS document for attestation |
| `jacs_verify_document` | Verify a signed JACS document given its full JSON string (hash + signature check) |

### Agreements (Multi-Party)

Create multi-party cryptographic agreements — multiple agents formally commit to a shared decision:

| Tool | Description |
|------|-------------|
| `jacs_create_agreement` | Create an agreement specifying which agents must sign, with optional quorum (M-of-N), timeout, and algorithm constraints |
| `jacs_sign_agreement` | Co-sign an existing agreement, adding your agent's cryptographic signature |
| `jacs_check_agreement` | Check agreement status: who signed, quorum met, expired, who still needs to sign |

**Use agreements when agents need to:**
- Approve a deployment, data transfer, or configuration change
- Reach consensus on a proposal (e.g., 2-of-3 signers required)
- Enforce that only post-quantum algorithms are used for signing
- Set a deadline after which the agreement expires

### A2A Discovery

Export Agent Cards and well-known documents for [A2A protocol](https://github.com/a2aproject/A2A) interoperability:

| Tool | Description |
|------|-------------|
| `jacs_export_agent_card` | Export the local agent's A2A Agent Card (includes identity, skills, JACS extension) |
| `jacs_generate_well_known` | Generate all `.well-known` documents for A2A discovery (agent-card.json, jwks.json, jacs-agent.json, jacs-pubkey.json, jacs-extension.json) |
| `jacs_export_agent` | Export the local agent's full JACS JSON document (identity, public key hash, signed metadata) |

### A2A Artifacts

Sign, verify, and assess trust for A2A artifacts with JACS provenance:

| Tool | Description |
|------|-------------|
| `jacs_wrap_a2a_artifact` | Wrap an A2A artifact with JACS provenance signature (supports chain-of-custody via parent signatures) |
| `jacs_verify_a2a_artifact` | Verify a JACS-wrapped A2A artifact's signature and hash |
| `jacs_assess_a2a_agent` | Assess the trust level of a remote A2A agent given its Agent Card |

**Use A2A artifact tools to:**
- Sign task results, messages, or any A2A payload with cryptographic provenance
- Verify artifacts received from other agents before acting on them
- Assess whether a remote agent meets your trust policy before exchanging data
- Build chain-of-custody trails by referencing parent signatures

### Trust Store

Manage the local trust store -- which agents your agent trusts for signature verification:

| Tool | Description |
|------|-------------|
| `jacs_trust_agent` | Add an agent to the local trust store (self-signature is verified first) |
| `jacs_untrust_agent` | Remove an agent from the trust store (requires `JACS_MCP_ALLOW_UNTRUST=true`) |
| `jacs_list_trusted_agents` | List all agent IDs currently in the local trust store |
| `jacs_is_trusted` | Check whether a specific agent is in the trust store |
| `jacs_get_trusted_agent` | Retrieve the full agent JSON document for a trusted agent |

**Use the trust store to:**
- Build a list of known collaborators before exchanging signed artifacts
- Gate A2A interactions with `strict` trust policy (only trust-store agents accepted)
- Inspect a remote agent's full identity document before trusting

## Quick Start

### Step 1: Install JACS CLI

```bash
# From the JACS repository root
cargo install --path jacs
```

### Step 2: Create Agent and Keys

```bash
# Create an agent (generates keys, config, and data directories)
jacs init
```

Or programmatically:

```bash
export JACS_AGENT_PRIVATE_KEY_PASSWORD="Your-Str0ng-P@ss!"
jacs agent create --create-keys true
```

### Step 3: Build the MCP Server

```bash
cd jacs-mcp
cargo build --release
```

The binary will be at `target/release/jacs-mcp`.

### Step 4: Configure Your MCP Client

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "jacs": {
      "command": "/path/to/jacs-mcp",
      "env": {
        "JACS_CONFIG": "/path/to/jacs.config.json",
        "JACS_PRIVATE_KEY_PASSWORD": "your-secure-password"
      }
    }
  }
}
```

## Configuration

### Required Environment Variables

- `JACS_CONFIG` - Path to your `jacs.config.json` file
- `JACS_PRIVATE_KEY_PASSWORD` - Password for decrypting your private key

### Optional Environment Variables

- `RUST_LOG` - Logging level (default: `info,rmcp=warn`)

### Security Options

- `JACS_MCP_ALLOW_REGISTRATION` - Set to `true` to enable `jacs_create_agent` (default: disabled)
- `JACS_MCP_ALLOW_UNTRUST` - Set to `true` to enable `jacs_untrust_agent` (default: disabled). Prevents prompt injection attacks from removing trusted agents without user consent.

### Example jacs.config.json

```json
{
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_private_key_filename": "jacs.private.pem.enc",
  "jacs_agent_public_key_filename": "jacs.public.pem",
  "jacs_agent_key_algorithm": "pq2025",
  "jacs_agent_id_and_version": "YOUR-AGENT-ID:YOUR-VERSION-ID",
  "jacs_default_storage": "fs"
}
```

## Tools Reference

### jacs_sign_state

Sign an agent state file to create a cryptographically signed JACS document.
The resulting document is persisted in JACS storage for ID-based follow-up operations.

**Parameters:**
- `file_path` (required): Path to the file to sign
- `state_type` (required): Type of state: `memory`, `skill`, `plan`, `config`, or `hook`
- `name` (required): Human-readable name for the document
- `description` (optional): Description of the state document
- `framework` (optional): Framework identifier (e.g., `claude-code`, `openclaw`)
- `tags` (optional): Tags for categorization
- `embed` (optional): Whether to embed file content inline (defaults to true in MCP; always true for hooks)

### jacs_verify_state

Verify the integrity and authenticity of a signed agent state.

**Parameters:**
- `jacs_id` (required in MCP usage): JACS document ID (`uuid:version`) to verify
- `file_path` (deprecated): Path-based verification is disabled for MCP security policy

Use `jacs_id` from `jacs_sign_state` or `jacs_adopt_state`.

### jacs_load_state

Load a signed agent state document, optionally verifying before returning content.

**Parameters:**
- `jacs_id` (required in MCP usage): JACS document ID (`uuid:version`) to load
- `file_path` (deprecated): Path-based loading is disabled for MCP security policy
- `require_verified` (optional): Whether to require verification before loading (default: true)

### jacs_update_state

Update a previously signed agent state document with new embedded content and re-sign.

**Parameters:**
- `jacs_id` (required in MCP usage): JACS document ID (`uuid:version`) to update
- `file_path` (deprecated): Path-based updates are disabled for MCP security policy
- `new_content` (optional): New embedded content. If omitted, re-signs current content.

### jacs_list_state

List signed agent state documents with optional filtering.

**Parameters:**
- `state_type` (optional): Filter by type (`memory`, `skill`, `plan`, `config`, `hook`)
- `framework` (optional): Filter by framework identifier
- `tags` (optional): Filter by tags (documents must have all specified tags)

### jacs_adopt_state

Adopt an external file as signed agent state, marking its origin as "adopted".

**Parameters:**
- `file_path` (required): Path to the file to adopt
- `state_type` (required): Type of state
- `name` (required): Human-readable name
- `source_url` (optional): URL where the content was originally obtained
- `description` (optional): Description of the adopted state

### jacs_create_agreement

Create a multi-party cryptographic agreement that other agents can co-sign.

**Parameters:**
- `document` (required): JSON document that all parties will agree to
- `agent_ids` (required): List of agent IDs (UUIDs) that are parties to this agreement
- `question` (optional): Human-readable question for signers (e.g., "Do you approve deploying model v2?")
- `context` (optional): Additional context to help signers decide
- `timeout` (optional): ISO 8601 deadline after which the agreement expires (e.g., "2025-12-31T23:59:59Z")
- `quorum` (optional): Minimum signatures required (M-of-N). If omitted, all agents must sign.
- `required_algorithms` (optional): Only allow these signing algorithms: `RSA-PSS`, `ring-Ed25519`, `pq-dilithium`, `pq2025`
- `minimum_strength` (optional): `classical` (any algorithm) or `post-quantum` (pq-dilithium/pq2025 only)

### jacs_sign_agreement

Co-sign an existing agreement, adding your agent's cryptographic signature.

**Parameters:**
- `signed_agreement` (required): The full agreement JSON to sign
- `agreement_fieldname` (optional): Custom agreement field name (default: `jacsAgreement`)

### jacs_check_agreement

Check the status of an agreement.

**Parameters:**
- `signed_agreement` (required): The agreement JSON to check
- `agreement_fieldname` (optional): Custom agreement field name (default: `jacsAgreement`)

**Returns:** `complete`, `quorum_met`, `expired`, `signatures_collected`, `signatures_required`, `signed_by`, `unsigned`

### jacs_sign_document

Sign arbitrary JSON content to create a cryptographically signed JACS document.

**Parameters:**
- `content` (required): The JSON content to sign
- `content_type` (optional): MIME type of the content (default: `application/json`)

**Returns:** `success`, `signed_document` (full signed JACS envelope), `content_hash` (SHA-256), `jacs_document_id`

### jacs_verify_document

Verify a signed JACS document given its full JSON string. Checks both the content hash and cryptographic signature. Use this when you have a signed document in memory (e.g. from an approval context or message payload).

**Parameters:**
- `document` (required): The full signed JACS document JSON string

**Returns:** `success`, `valid`, `signer_id` (optional -- extracted from document if available), `message`

### jacs_export_agent_card

Export the local agent's A2A Agent Card. The Agent Card follows the A2A v0.4.0 format and includes the JACS provenance extension.

**Parameters:** None.

**Returns:** `success`, `agent_card` (JSON string of the A2A Agent Card)

### jacs_generate_well_known

Generate all `.well-known` documents for A2A discovery. Returns an array of `{path, document}` objects that can be served at each path.

**Parameters:**
- `a2a_algorithm` (optional): A2A signing algorithm override (default: `ring-Ed25519`)

**Returns:** `success`, `documents` (JSON array of `{path, document}` objects), `count`

### jacs_export_agent

Export the local agent's full JACS JSON document, including identity, public key hash, and signed metadata.

**Parameters:** None.

**Returns:** `success`, `agent_json` (full agent JSON document), `agent_id`

### jacs_trust_agent

Add an agent to the local trust store. The agent's self-signature is cryptographically verified before it is added. If verification fails, the agent is NOT trusted.

**Parameters:**
- `agent_json` (required): The full JACS agent JSON document to add to the trust store

**Returns:** `success`, `agent_id`, `message`

### jacs_untrust_agent

Remove an agent from the local trust store. **Requires `JACS_MCP_ALLOW_UNTRUST=true`.** This security gate prevents prompt injection attacks from removing trusted agents without user consent.

**Parameters:**
- `agent_id` (required): The JACS agent ID (UUID) to remove from the trust store

**Returns:** `success`, `agent_id`, `message`

### jacs_list_trusted_agents

List all agent IDs currently in the local trust store.

**Parameters:** None.

**Returns:** `success`, `agent_ids` (list of UUIDs), `count`, `message`

### jacs_is_trusted

Check whether a specific agent is in the local trust store.

**Parameters:**
- `agent_id` (required): The JACS agent ID (UUID) to check trust status for

**Returns:** `success`, `agent_id`, `trusted` (boolean), `message`

### jacs_get_trusted_agent

Retrieve the full agent JSON document for a trusted agent from the local trust store. Fails if the agent is not trusted.

**Parameters:**
- `agent_id` (required): The JACS agent ID (UUID) to retrieve from the trust store

**Returns:** `success`, `agent_id`, `agent_json` (full agent document), `message`

### jacs_wrap_a2a_artifact

Wrap an A2A artifact with JACS provenance signature. Supports chain-of-custody by optionally referencing parent signatures from previous steps in a multi-agent workflow.

**Parameters:**
- `artifact_json` (required): The A2A artifact JSON content to wrap with JACS provenance
- `artifact_type` (required): Artifact type identifier (e.g., `a2a-artifact`, `message`, `task-result`)
- `parent_signatures` (optional): JSON array of parent signatures for chain-of-custody provenance

**Returns:** `success`, `wrapped_artifact` (JSON string with JACS provenance envelope), `message`

### jacs_verify_a2a_artifact

Verify a JACS-wrapped A2A artifact's signature and content hash. Checks that the artifact has not been tampered with and that the signature is valid.

**Parameters:**
- `wrapped_artifact` (required): The JACS-wrapped A2A artifact JSON to verify

**Returns:** `success`, `valid` (boolean), `verification_details` (JSON with signer info, hash check, parent chain status), `message`

### jacs_assess_a2a_agent

Assess the trust level of a remote A2A agent given its Agent Card. Applies a trust policy to determine whether your agent should interact with the remote agent.

**Parameters:**
- `agent_card_json` (required): The A2A Agent Card JSON of the remote agent to assess
- `policy` (optional): Trust policy to apply: `open` (accept all), `verified` (require JACS extension, **default**), or `strict` (require trust store entry)

**Returns:** `success`, `allowed` (boolean), `trust_level` (`Untrusted`, `JacsVerified`, or `ExplicitlyTrusted`), `policy`, `reason`, `message`

## A2A Workflow Example

Use the A2A discovery, trust store, and artifact tools together to establish trust and exchange signed artifacts:

```
1. Agent A: jacs_generate_well_known                    -> Serve .well-known documents
2. Agent B: jacs_export_agent_card                      -> Get Agent B's card
3. Agent A: jacs_assess_a2a_agent(agent_b_card)         -> Check trust level before interacting
4. Agent A: jacs_trust_agent(agent_b_json)              -> Add Agent B to trust store
5. Agent A: jacs_wrap_a2a_artifact(task, "task")        -> Sign a task artifact for Agent B
6. Agent B: jacs_verify_a2a_artifact(wrapped_task)      -> Verify Agent A's artifact
7. Agent B: jacs_wrap_a2a_artifact(result, "task-result",
              parent_signatures=[step5])                -> Sign result with chain-of-custody
8. Agent A: jacs_verify_a2a_artifact(wrapped_result)    -> Verify result + parent chain
```

For the full A2A quickstart guide, see the [A2A Quickstart](https://humanassisted.github.io/JACS/guides/a2a-quickstart.html) in the JACS Book.

## Security

- **Destructive actions disabled by default**: `jacs_create_agent` and `jacs_untrust_agent` require explicit opt-in via environment variables, preventing prompt injection attacks.
- **Password protection**: Private keys are encrypted. Never store passwords in config files.
- **Stdio transport**: No network exposure -- communicates over stdin/stdout.

## Development

```bash
# Run tests
cargo test

# Build debug version
cargo build

# Run with debug logging
export JACS_CONFIG=/path/to/jacs.config.json
export RUST_LOG=debug
cargo run
```

## Documentation

- [JACS Book](https://humanassisted.github.io/JACS/) - Full documentation (published book)
- [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [A2A Quickstart](https://humanassisted.github.io/JACS/guides/a2a-quickstart.html) - A2A interoperability guide
- [A2A Interoperability](https://humanassisted.github.io/JACS/integrations/a2a.html) - Full A2A reference
- [Source](https://github.com/HumanAssisted/JACS) - GitHub repository

## License

See the LICENSE file in the parent directory.
