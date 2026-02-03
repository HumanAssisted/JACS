# JACS MCP Server

A Model Context Protocol (MCP) server providing HAI (Human AI Interface) tools for agent registration, verification, and key management.

## Overview

The JACS MCP Server allows LLMs to interact with HAI services through the MCP protocol. It provides tools for:

- **Agent Key Management**: Fetch public keys from HAI's key distribution service
- **Agent Registration**: Register agents with HAI to establish identity
- **Agent Verification**: Verify other agents' attestation levels (0-3)
- **Status Checking**: Check registration status with HAI
- **Agent Unregistration**: Remove agent registration from HAI

## Quick Start

### Step 1: Install JACS CLI

First, install the JACS command-line tool:

```bash
# From the JACS repository root
cargo install --path jacs
```

### Step 2: Generate Keys

Generate cryptographic keys for your agent:

```bash
# Set a secure password for key encryption
export JACS_PRIVATE_KEY_PASSWORD="your-secure-password"

# Create a directory for your keys
mkdir -p jacs_keys

# Generate keys (choose an algorithm)
jacs create-keys --algorithm pq-dilithium --output-dir jacs_keys
# Or for Ed25519: jacs create-keys --algorithm ring-Ed25519 --output-dir jacs_keys
```

### Step 3: Create Agent

Create a new JACS agent:

```bash
# Create data directory
mkdir -p jacs_data

# Create a new agent
jacs create-agent --name "My Agent" --description "My HAI-enabled agent"
```

### Step 4: Create Configuration File

Create a `jacs.config.json` file:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_private_key_filename": "jacs.private.pem.enc",
  "jacs_agent_public_key_filename": "jacs.public.pem",
  "jacs_agent_key_algorithm": "pq-dilithium",
  "jacs_agent_id_and_version": "YOUR-AGENT-ID:YOUR-VERSION-ID",
  "jacs_default_storage": "fs"
}
```

Replace `YOUR-AGENT-ID:YOUR-VERSION-ID` with your actual agent ID (found in the agent file created in Step 3).

### Step 5: Build and Run the MCP Server

```bash
cd jacs-mcp
cargo build --release
```

The binary will be at `target/release/jacs-mcp`.

### Step 6: Configure Your MCP Client

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "jacs-hai": {
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

## Installation

Build from source:

```bash
cd jacs-mcp
cargo build --release
```

The binary will be at `target/release/jacs-mcp`.

## Configuration

The server requires a JACS agent configuration to operate. Set the following environment variables:

### Required

- `JACS_CONFIG` - Path to your `jacs.config.json` file
- `JACS_PRIVATE_KEY_PASSWORD` - Password for decrypting your private key

### Optional

- `HAI_ENDPOINT` - HAI API endpoint (default: `https://api.hai.ai`). Must be an allowed host.
- `HAI_API_KEY` - API key for HAI authentication
- `RUST_LOG` - Logging level (default: `info,rmcp=warn`)

### Security Options

- `JACS_MCP_ALLOW_REGISTRATION` - Set to `true` to enable the register_agent tool (default: disabled)
- `JACS_MCP_ALLOW_UNREGISTRATION` - Set to `true` to enable the unregister_agent tool (default: disabled)

### Example Configuration

```json
{
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_private_key_filename": "jacs.private.pem.enc",
  "jacs_agent_public_key_filename": "jacs.public.pem",
  "jacs_agent_key_algorithm": "pq-dilithium",
  "jacs_agent_id_and_version": "your-agent-id:version",
  "jacs_default_storage": "fs"
}
```

## Usage

### Starting the Server

```bash
export JACS_CONFIG=/path/to/jacs.config.json
export HAI_API_KEY=your-api-key  # optional
./jacs-mcp
```

The server communicates over stdin/stdout using the MCP JSON-RPC protocol.

### MCP Client Configuration

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "jacs-hai": {
      "command": "/path/to/jacs-mcp",
      "env": {
        "JACS_CONFIG": "/path/to/jacs.config.json",
        "HAI_API_KEY": "your-api-key"
      }
    }
  }
}
```

## Tools

### fetch_agent_key

Fetch a public key from HAI's key distribution service.

**Parameters:**
- `agent_id` (required): The JACS agent ID (UUID format)
- `version` (optional): Key version to fetch, or "latest" for most recent

**Returns:**
- `success`: Whether the operation succeeded
- `agent_id`: The agent ID
- `version`: The key version
- `algorithm`: Cryptographic algorithm (e.g., "ed25519", "pq-dilithium")
- `public_key_hash`: SHA-256 hash of the public key
- `public_key_base64`: Base64-encoded public key

**Example:**
```json
{
  "name": "fetch_agent_key",
  "arguments": {
    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
    "version": "latest"
  }
}
```

### register_agent

Register the local agent with HAI to establish identity and enable attestation.

**Parameters:**
- `preview` (optional): If true, validates without actually registering

**Returns:**
- `success`: Whether the operation succeeded
- `agent_id`: The registered agent's JACS ID
- `jacs_id`: The JACS document ID
- `dns_verified`: Whether DNS verification was successful
- `preview_mode`: Whether this was preview-only
- `message`: Human-readable status message

**Example:**
```json
{
  "name": "register_agent",
  "arguments": {
    "preview": false
  }
}
```

### verify_agent

Verify another agent's attestation level with HAI.

**Parameters:**
- `agent_id` (required): The JACS agent ID to verify
- `version` (optional): Agent version to verify, or "latest"

**Returns:**
- `success`: Whether the verification succeeded
- `agent_id`: The verified agent ID
- `attestation_level`: Trust level (0-3):
  - Level 0: No attestation
  - Level 1: Key registered with HAI
  - Level 2: DNS verified
  - Level 3: Full HAI signature attestation
- `attestation_description`: Human-readable description
- `key_found`: Whether the agent's public key was found

**Example:**
```json
{
  "name": "verify_agent",
  "arguments": {
    "agent_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### check_agent_status

Check registration status of an agent with HAI.

**Parameters:**
- `agent_id` (optional): Agent ID to check. If omitted, checks the local agent.

**Returns:**
- `success`: Whether the operation succeeded
- `agent_id`: The checked agent ID
- `registered`: Whether the agent is registered with HAI
- `registration_id`: HAI registration ID (if registered)
- `registered_at`: Registration timestamp (if registered)
- `signature_count`: Number of HAI signatures on the registration

**Example:**
```json
{
  "name": "check_agent_status",
  "arguments": {}
}
```

### unregister_agent

Unregister the local agent from HAI. **Requires `JACS_MCP_ALLOW_UNREGISTRATION=true`.**

**Parameters:**
- `preview` (optional): If true (default), validates without actually unregistering

**Returns:**
- `success`: Whether the operation succeeded
- `agent_id`: The unregistered agent's JACS ID
- `preview_mode`: Whether this was preview-only
- `message`: Human-readable status message

**Example:**
```json
{
  "name": "unregister_agent",
  "arguments": {
    "preview": false
  }
}
```

## Security

### Key Security Features

- **Registration Authorization**: The `register_agent` and `unregister_agent` tools are disabled by default. This prevents prompt injection attacks from registering agents without user consent.
- **Preview Mode by Default**: Even when enabled, registration defaults to preview mode for additional safety.
- **Endpoint Validation**: The `HAI_ENDPOINT` URL is validated against an allowlist to prevent request redirection attacks.
- **Password Protection**: Private keys are encrypted with a password. Never store passwords in config files - use the `JACS_PRIVATE_KEY_PASSWORD` environment variable.
- **Stdio Transport**: The server uses stdio transport, which is inherently local with no network exposure.

### Enabling Registration

To enable agent registration (only do this if you trust the LLM):

```bash
export JACS_MCP_ALLOW_REGISTRATION=true
export JACS_MCP_ALLOW_UNREGISTRATION=true  # Optional
```

### Allowed HAI Endpoints

The server validates `HAI_ENDPOINT` against this allowlist:
- `api.hai.ai`
- `dev.api.hai.ai`
- `staging.api.hai.ai`
- `localhost` / `127.0.0.1` (for development)
- Any subdomain of `*.hai.ai`

### Best Practices

- Use strong passwords for key encryption (12+ characters)
- Never commit config files with passwords to version control
- Use environment variables or secrets management for sensitive values
- Keep private key files secure (mode 0600)
- Review agent registrations before enabling automatic registration

## Development

### Running Tests

```bash
cargo test
```

### Building Debug Version

```bash
cargo build
```

### Environment for Development

```bash
export JACS_CONFIG=/path/to/test/jacs.config.json
export HAI_ENDPOINT=https://dev.api.hai.ai
export RUST_LOG=debug
cargo run
```

## License

See the LICENSE file in the parent directory.
