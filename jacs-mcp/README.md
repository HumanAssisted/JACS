# JACS MCP Server

A Model Context Protocol (MCP) server for **data provenance and cryptographic signing** of agent state, plus optional [HAI.ai](https://hai.ai) integration for cross-organization key discovery and attestation.

JACS (JSON Agent Communication Standard) ensures that every file, memory, or configuration an AI agent touches can be signed, verified, and traced back to its origin -- no server required.

## What can it do?

The server exposes **11 tools** in two categories:

### Agent State (Data Provenance)

Sign, verify, and manage files that represent agent state (memories, skills, plans, configs, hooks):

| Tool | Description |
|------|-------------|
| `jacs_sign_state` | Sign a file to create a cryptographically signed JACS document |
| `jacs_verify_state` | Verify file integrity and signature authenticity |
| `jacs_load_state` | Load a signed state document, optionally verifying before returning content |
| `jacs_update_state` | Update a previously signed file -- re-hashes and re-signs |
| `jacs_list_state` | List signed agent state documents with optional filtering |
| `jacs_adopt_state` | Adopt an external file as signed state, recording its origin |

### HAI Integration (Optional)

Register with [HAI.ai](https://hai.ai) for cross-organization trust and key distribution:

| Tool | Description |
|------|-------------|
| `fetch_agent_key` | Fetch a public key from HAI's key distribution service |
| `register_agent` | Register the local agent with HAI (disabled by default) |
| `verify_agent` | Verify another agent's attestation level (0-3) |
| `check_agent_status` | Check registration status with HAI |
| `unregister_agent` | Unregister from HAI (disabled by default, not yet implemented) |

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

To enable HAI integration, add `HAI_API_KEY`:

```json
{
  "mcpServers": {
    "jacs": {
      "command": "/path/to/jacs-mcp",
      "env": {
        "JACS_CONFIG": "/path/to/jacs.config.json",
        "JACS_PRIVATE_KEY_PASSWORD": "your-secure-password",
        "HAI_API_KEY": "your-hai-api-key"
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

- `HAI_ENDPOINT` - HAI API endpoint (default: `https://api.hai.ai`). Validated against an allowlist.
- `HAI_API_KEY` - API key for HAI authentication
- `RUST_LOG` - Logging level (default: `info,rmcp=warn`)

### Security Options

- `JACS_MCP_ALLOW_REGISTRATION` - Set to `true` to enable `register_agent` (default: disabled)
- `JACS_MCP_ALLOW_UNREGISTRATION` - Set to `true` to enable `unregister_agent` (default: disabled)

### Example jacs.config.json

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
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

**Parameters:**
- `file_path` (required): Path to the file to sign
- `state_type` (required): Type of state: `memory`, `skill`, `plan`, `config`, or `hook`
- `name` (required): Human-readable name for the document
- `description` (optional): Description of the state document
- `framework` (optional): Framework identifier (e.g., `claude-code`, `openclaw`)
- `tags` (optional): Tags for categorization
- `embed` (optional): Whether to embed file content inline (always true for hooks)

### jacs_verify_state

Verify the integrity and authenticity of a signed agent state.

**Parameters:**
- `file_path` (optional): Path to the file to verify
- `jacs_id` (optional): JACS document ID to verify

At least one of `file_path` or `jacs_id` must be provided.

### jacs_load_state

Load a signed agent state document, optionally verifying before returning content.

**Parameters:**
- `file_path` (optional): Path to the file to load
- `jacs_id` (optional): JACS document ID to load
- `require_verified` (optional): Whether to require verification before loading (default: true)

### jacs_update_state

Update a previously signed agent state file with new content and re-sign.

**Parameters:**
- `file_path` (required): Path to the file to update
- `new_content` (optional): New content to write. If omitted, re-signs current content.

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

### fetch_agent_key

Fetch a public key from HAI's key distribution service.

**Parameters:**
- `agent_id` (required): The JACS agent ID (UUID format)
- `version` (optional): Key version to fetch, or `latest`

### register_agent

Register the local agent with HAI. **Requires `JACS_MCP_ALLOW_REGISTRATION=true`.**

**Parameters:**
- `preview` (optional): If true (default), validates without actually registering

### verify_agent

Verify another agent's attestation level with HAI.

**Parameters:**
- `agent_id` (required): The JACS agent ID to verify
- `version` (optional): Agent version to verify, or `latest`

**Attestation levels:**
- Level 0: No attestation
- Level 1: Key registered with HAI
- Level 2: DNS verified
- Level 3: Full HAI signature attestation

### check_agent_status

Check registration status of an agent with HAI.

**Parameters:**
- `agent_id` (optional): Agent ID to check. If omitted, checks the local agent.

### unregister_agent

Unregister the local agent from HAI. **Requires `JACS_MCP_ALLOW_UNREGISTRATION=true`.**

**Parameters:**
- `preview` (optional): If true (default), validates without actually unregistering

## Security

- **Registration disabled by default**: `register_agent` and `unregister_agent` require explicit opt-in via environment variables, preventing prompt injection attacks.
- **Preview mode by default**: Even when enabled, registration defaults to preview mode.
- **Endpoint validation**: `HAI_ENDPOINT` is validated against an allowlist (`*.hai.ai`, localhost).
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

## License

See the LICENSE file in the parent directory.
