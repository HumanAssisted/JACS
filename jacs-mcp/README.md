# JACS MCP Server

MCP server for JACS verification and explicitly configured local agent signing.

Uses **stdio transport only**. The default process loads no agent configuration
or private key. Local JSON/Agreement signing requires an existing signed agent
config; it needs no server, extra policy file, or new key format.

The checked-in contract snapshot for downstream adapters lives at [`contract/jacs-mcp-contract.json`](contract/jacs-mcp-contract.json).

Ecosystem compatibility exports (ES256 JWKS, the native-root-signed compatibility key binding, ES256-signed A2A agent cards, AP2 mandates, and Agreement-v2 Verifiable Credentials) are CLI and language-binding surfaces only — by design there are no MCP tools for them.

## What can it do?

The default `verify-only` profile exposes only explicit-key document integrity
verification. The only profile names are `verify-only`,
`local-sign`, `trust-admin`, and compatibility-only `legacy-core`. An explicit
flag wins over the environment and unknown values fail startup. A privileged
profile name alone does not authorize signing. `local-sign` additionally loads
and verifies the operator-selected config and freezes that identity/key for the
process. `trust-admin` and `legacy-core` remain unavailable.

### Explicit local signing

After `jacs init`, start with your existing config and normal keychain/password
source (never send a password as tool input):

```bash
jacs mcp --profile local-sign --config ./jacs.config.json
```

`JACS_CONFIG` can supply the same path instead of `--config`. There is no
implicit config discovery, new-key fallback, or second grant file. The selected
config must be signed and use filesystem storage. Ambient identity/path
overrides are ignored; the password source is resolved at startup.

The closed local inventory is `jacs_sign_document`, `jacs_verify_document`, and
the compiled Agreement-v2 create/apply/sign/verify/detect-conflict/merge/resolve
tools. `jacs_sign_document` always puts the caller's JSON inside `content` of an
ordinary JACS document: even supplied `jacsType`, `$schema`, or signature fields
stay data. The optional MIME label is recorded as `contentType`. Signing and
Agreement tool arguments are limited to 1 MiB. Documents are returned and persisted under
`<config directory>/documents/`; normal encrypted keys and public-key storage
remain on disk. Agreement inspection may read configured local public keys,
but network opt-ins must be off for this local process.

This grants the MCP client permission to sign allowed content **as this agent**.
It does not prove a human reviewed any particular action, nor does Agreement-v2
signature coverage establish role/quorum/notary authority or policy acceptance.
The operator trusts the local host and protects the config, key and storage
directories; this is not a sandbox against another process controlling those
files. Startup reports `mcp_local_signing_authorized`; rejection logs
`mcp_local_signing_denied` at WARN without document bodies or secrets.

To also work with local text and images, explicitly select an existing content
directory at startup:

```bash
JACS_MCP_BASE_DIR=/path/to/content jacs mcp --profile local-sign --config ./jacs.config.json
```

This adds exactly five existing tools: `jacs_sign_text`, `jacs_verify_text`,
`jacs_sign_image`, `jacs_verify_image`, and `jacs_extract_media_signature`.
The same loaded agent signs JSON, Agreements, text and images; media calls do
not reload config or decrypt another key. Without `JACS_MCP_BASE_DIR`, the
nine-tool JSON/Agreement surface stays unchanged (when Agreement tools are
compiled). Setting a content root never expands a verification-only process.

Raw/key APIs, registration, trust administration, key rotation, W3C request signing,
A2A and attestation tools likewise are not enabled by `local-sign`. Their
ordinary CLI/SDK capabilities are unchanged.

The compiled contract contains the categories below. This inventory is not a
claim that every tool is available in a runtime profile; `tools/list` is the
actual process surface.

### Document Sign / Verify

| Tool | Description |
|------|-------------|
| `jacs_sign_document` | Sign arbitrary JSON content to create a signed JACS document |
| `jacs_verify_document` | Verify exact document bytes with a caller-selected raw public key and algorithm (integrity only) |

### Agent Management

| Tool | Description |
|------|-------------|
| `jacs_create_agent` | Create a new JACS agent with cryptographic keys, when explicitly enabled |
| `jacs_reencrypt_key` | Re-encrypt the agent's private key with a new password |
| `jacs_rotate_keys` | Rotate the active agent key material |

### Legacy Agreements (compiled inventory; unavailable in current profiles)

| Tool | Description |
|------|-------------|
| `jacs_create_agreement` | Create a multi-party agreement over arbitrary document content |
| `jacs_sign_agreement` | Co-sign an existing agreement |
| `jacs_check_agreement` | Inspect legacy signatures and claimed status; never policy acceptance |

### A2A Discovery and Artifacts

| Tool | Description |
|------|-------------|
| `jacs_export_agent_card` | Export the local agent's A2A Agent Card |
| `jacs_generate_well_known` | Generate the six stable ES256/native-root-bound A2A `.well-known` documents |
| `jacs_export_agent` | Export the local agent's full JACS JSON document |
| `jacs_wrap_a2a_artifact` | Wrap an A2A artifact with JACS provenance |
| `jacs_verify_a2a_artifact` | Verify a JACS-wrapped A2A artifact |
| `jacs_assess_a2a_agent` | Assess the trust level of a remote A2A agent |

### W3C DID Interop

| Tool | Description |
|------|-------------|
| `jacs_w3c_export_did` | Export the local agent's `did:wba` identifier |
| `jacs_w3c_export_did_document` | Export the local agent's W3C DID document |
| `jacs_w3c_export_agent_description` | Export the local agent's W3C agent description |
| `jacs_w3c_generate_well_known` | Generate W3C discovery documents keyed by path |
| `jacs_w3c_sign_request` | Create a request-bound DID authentication proof |
| `jacs_w3c_verify_request` | Verify a request-bound DID authentication proof, optionally against the actual method and URL |

### Trust Store

| Tool | Description |
|------|-------------|
| `jacs_trust_agent` | Add an agent to the local trust store |
| `jacs_untrust_agent` | Remove an agent from the local trust store, when explicitly enabled |
| `jacs_list_trusted_agents` | List trusted agent IDs |
| `jacs_is_trusted` | Check whether an agent is trusted |
| `jacs_get_trusted_agent` | Retrieve a trusted agent JSON document |

### Attestation (compiled inventory; unavailable in current profiles)

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
      "args": ["mcp"]
    }
  }
}
```

## Configuration

Optional:

- `RUST_LOG` - Logging level, default `info,rmcp=warn`
- `JACS_MCP_PROFILE` - one exact closed profile name; defaults to
  `verify-only` and is used only when `--profile` is absent
- `JACS_CONFIG` - existing signed config for local signing; `--config` wins

Local file settings are captured when the authorized signer starts; changing
the environment afterward cannot broaden them:

- `JACS_MCP_BASE_DIR` - Explicit existing directory for the five local file
  tools; absent means no file tools, not a working-directory grant
- `JACS_MCP_OVERWRITE_OK=1` - Explicitly allow file tools to overwrite an
  existing distinct output (disabled by default)
- `JACS_MCP_ALLOW_KEY_DIR=true` - Allow a caller-selected public-key directory
  inside the content root for verification (disabled by default). A valid
  signature using these supplied keys is integrity evidence, not identity or
  application authorization

These retained admin settings do not add tools or grant authority:

- `JACS_MCP_ALLOW_REGISTRATION` - retained handler setting; does not authorize registration
- `JACS_MCP_ALLOW_UNTRUST` - retained handler setting; does not authorize trust administration

### File path policy

File-tool arguments are relative paths beneath `JACS_MCP_BASE_DIR`. Absolute
paths, `.`/`..` traversal, NULs, and symlinks are rejected (including symlinked
ancestors). Hard-linked content files are refused on Unix. The selected
config, encrypted-key directory, agent-data directory, document store and
trust store are excluded even when they sit below the content root.
Case-equivalent reserved names are also refused before a protected backup or
document directory exists.

Signing text or choosing the same image input/output path is an explicit
in-place write. A distinct existing output is refused unless the operator
opts in with `JACS_MCP_OVERWRITE_OK=1`; the caller's `refuse_overwrite:false`
cannot grant that permission. Existing atomic file writes and sibling `.bak`
behavior are retained: text backups are on by default (`no_backup:true` opts
out); in-place/replaced image outputs keep backups. **Backups contain the
original plaintext content**, use owner-only permissions by default, and may
be refreshed on subsequent writes. Backup paths receive the same containment
and protected-material checks before signing. Protect the content directory
and backups as you would the original files.

File startup logs `mcp_local_files_authorized` with the selected directory and
captured options. Rejections are returned as `PATH_POLICY_BLOCKED` in the
existing tool error envelope; scope denials also emit
`mcp_local_signing_denied` at WARN. No extra daemon or file-policy service is
required. These checks constrain MCP requests; they do not isolate a process
from a malicious local host owner changing filesystem state concurrently.

## Core Document Tools

### `jacs_sign_document`

Sign JSON as nested content in an ordinary document using the selected local
agent. This does not issue a caller-selected protocol/identity document or
prove a person's approval.

Parameters:

- `content` - JSON content to sign
- `content_type` - MIME type, default `application/json`

### `jacs_verify_document`

Verify exact signed JACS document bytes for integrity. A successful result does
not establish signer identity, trust, authorization, freshness, or revocation.

Parameters:

- `document` - Full signed JACS document JSON string
- `public_key` - Exact raw Ed25519 or ML-DSA-87 public-key bytes
- `algorithm` - `ed25519` or `pq2025`

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

Inspect signature mathematics and claimed legacy status. This tool never
establishes completion or policy acceptance and is not currently enabled.
