# LangChain + JACS Integration Examples

These examples demonstrate how to use JACS cryptographic signing with LangChain agents via the Model Context Protocol (MCP).

## Overview

JACS provides cryptographic signing and verification for AI agent outputs. By integrating with LangChain via MCP, you can:

- Sign AI agent outputs to prove their origin
- Verify that data came from a specific trusted agent
- Create multi-party agreements requiring multiple agent signatures
- Maintain audit trails of signed interactions
- **Verify agent trust levels via HAI** (Human AI Interface)
- **Fetch remote public keys** for cross-agent verification
- **Register agents** with the HAI network

## Prerequisites

1. **Install dependencies:**

```bash
pip install -r requirements.txt
```

2. **Set up a JACS agent:**

```bash
# Create a new agent in this directory
cd examples/langchain
jacs init
jacs create

# Or set the config path if you have an existing agent
export JACS_CONFIG_PATH=/path/to/your/jacs.config.json
```

3. **Set up your LLM API key:**

```bash
# For Anthropic Claude
export ANTHROPIC_API_KEY=your-key-here

# For OpenAI (if using OpenAI models)
export OPENAI_API_KEY=your-key-here
```

## Examples

### 1. Basic Agent (`basic_agent.py`)

Demonstrates connecting a LangChain agent to the JACS MCP server to use signing and verification tools.

```bash
# In one terminal, start the JACS MCP server
python -m jacs.mcp_server

# In another terminal, run the agent
python basic_agent.py
```

The agent can:
- Sign messages/data with `sign_message`
- Verify signatures with `verify_document`
- Get agent info with `get_agent_info`
- Check agent integrity with `verify_self`

### 2. Signing Callback (`signing_callback.py`)

Demonstrates using LangGraph with a custom callback that automatically signs all agent outputs.

```bash
python signing_callback.py
```

Features:
- `JACSSigningCallback` - Automatically signs tool outputs
- `SignedOutputsAuditTrail` - Maintains a log of all signed outputs
- Integration with LangGraph's streaming API

### 3. HAI Integration (`hai_integration.py`)

Demonstrates using HAI (Human AI Interface) tools for agent trust verification and registration.

```bash
# Start the jacs-mcp server with HAI tools
JACS_CONFIG=./jacs.config.json jacs-mcp

# In another terminal, run the example
python hai_integration.py
```

Features:
- Fetch remote agent public keys with `fetch_agent_key`
- Verify agent attestation levels (0-3) with `verify_agent`
- Register with HAI network using `register_agent`
- Check registration status with `check_agent_status`

## HAI Integration

### What is HAI?

HAI (Human AI Interface) provides a trust layer for AI agents. It enables:

1. **Identity Registration**: Agents can register their public keys with HAI
2. **Trust Verification**: Verify other agents' attestation levels before trusting them
3. **Key Distribution**: Fetch public keys for remote agents without prior contact

### Trust Levels (0-3)

HAI uses a tiered trust system:

| Level | Name | Description |
|-------|------|-------------|
| 0 | None | Agent not found in HAI system |
| 1 | Basic | Public key registered with HAI key service |
| 2 | Domain | DNS verification passed (agent controls claimed domain) |
| 3 | Attested | Full HAI signature attestation (highest trust) |

### HAI Tools via MCP

When using the `jacs-mcp` server, the following HAI tools are available to LangChain agents:

#### `fetch_agent_key`

Fetch a public key from HAI's key distribution service.

```python
# Agent can call this tool to get another agent's public key
result = await executor.ainvoke({
    "input": "Fetch the public key for agent 550e8400-e29b-41d4-a716-446655440000"
})
```

Returns:
- `agent_id`: The agent's ID
- `version`: Key version
- `algorithm`: Cryptographic algorithm (e.g., "ed25519", "pq-dilithium")
- `public_key_hash`: SHA-256 hash of the public key
- `public_key_base64`: The public key in base64 encoding

#### `verify_agent`

Verify another agent's attestation level.

```python
# Check trust level before accepting messages
result = await executor.ainvoke({
    "input": "Verify the trust level of agent ABC123 before I process their request"
})
```

Returns:
- `attestation_level`: 0-3 trust level
- `attestation_description`: Human-readable description
- `key_found`: Whether the agent's key was found

#### `register_agent`

Register the local agent with HAI.

```python
# Register with HAI (supports preview mode)
result = await executor.ainvoke({
    "input": "Register my agent with HAI in preview mode first"
})
```

Parameters:
- `preview`: If true, validates without registering

#### `check_agent_status`

Check registration status with HAI.

```python
# Check if registered
result = await executor.ainvoke({
    "input": "Am I registered with HAI?"
})
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JACS_CONFIG` | Path to jacs.config.json | `./jacs.config.json` |
| `HAI_ENDPOINT` | HAI API endpoint | `https://api.hai.ai` |
| `HAI_API_KEY` | Optional API key for HAI | (none) |

## Architecture

### Basic JACS Integration

```
+-------------------+      MCP Protocol       +------------------+
|   LangChain       | <-------------------->  |   JACS MCP       |
|   Agent           |                         |   Server         |
+-------------------+                         +------------------+
        |                                             |
        | Uses tools                                  | Uses
        v                                             v
+-------------------+                         +------------------+
| sign_message      |                         |   JACS Simple    |
| verify_document   |                         |   API            |
| get_agent_info    |                         +------------------+
| create_agreement  |                                 |
+-------------------+                                 v
                                              +------------------+
                                              |   Cryptographic  |
                                              |   Keys           |
                                              +------------------+
```

### With HAI Integration

```
+-------------------+      MCP Protocol       +------------------+
|   LangChain       | <-------------------->  |   jacs-mcp       |
|   Agent           |                         |   Server         |
+-------------------+                         +------------------+
        |                                             |
        | Uses tools                                  | Uses
        v                                             v
+-------------------+                         +------------------+
| JACS Tools:       |                         |   JACS Core      |
|  - sign_message   |                         |   + HAI Client   |
|  - verify_doc     |                         +------------------+
| HAI Tools:        |                                 |
|  - fetch_key      |                                 v
|  - verify_agent   |                         +------------------+
|  - register       |                         |   HAI.ai API     |
|  - check_status   | <---------------------->|   (keys.hai.ai)  |
+-------------------+                         +------------------+
```

## Use Cases

### Provenance Tracking

Sign all AI-generated content to prove it came from a specific agent:

```python
result = await agent.ainvoke({
    "messages": "Generate a report on Q4 sales"
})
# The result is automatically signed with the agent's key
```

### Multi-Agent Agreements

Create agreements requiring multiple agents to sign:

```python
# Agent 1 creates the agreement
agreement = await agent1.ainvoke({
    "messages": "Create an agreement for proposal X requiring agents A, B, and C"
})

# Agent 2 signs it
signed = await agent2.ainvoke({
    "messages": f"Sign this agreement: {agreement}"
})

# Check status
status = await agent1.ainvoke({
    "messages": f"Check agreement status: {signed}"
})
```

### Audit Trails

Maintain cryptographically verifiable audit trails:

```python
callback = JACSSigningCallback()
agent = create_agent(model, tools, callbacks=[callback])

# After interactions
for signed_output in callback.get_audit_trail():
    print(f"Tool: {signed_output['tool_name']}")
    print(f"Document ID: {signed_output['document_id']}")
    print(f"Signed at: {signed_output['timestamp']}")
```

### Agent Trust Verification (HAI)

Verify another agent before trusting their messages:

```python
# Before processing a request from another agent
result = await executor.ainvoke({
    "input": f"""Agent {sender_id} wants to execute a transaction.
    Verify their trust level and only proceed if they are at least Level 2 (domain verified)."""
})

# The agent will use verify_agent to check attestation level
```

### Multi-Agent Trust Establishment

Set up trusted communication between agents:

```python
# Step 1: Register your agent with HAI
result = await executor.ainvoke({
    "input": "Register my agent with HAI so other agents can verify me."
})

# Step 2: Fetch partner agent's key
result = await executor.ainvoke({
    "input": f"Fetch the public key for agent {partner_id} so I can verify their signatures."
})

# Step 3: Verify partner's trust level
result = await executor.ainvoke({
    "input": f"Verify agent {partner_id} is registered with HAI before we start collaborating."
})
```

### Remote Key Verification

Verify signatures from agents you haven't met before:

```python
# When you receive a signed message from an unknown agent
result = await executor.ainvoke({
    "input": f"""I received a signed message from agent {unknown_agent_id}.
    1. Fetch their public key from HAI
    2. Check their attestation level
    3. Tell me if I should trust this message based on their trust level"""
})
```

## Troubleshooting

### "No agent loaded" error

Make sure you have a valid `jacs.config.json` in the current directory or set `JACS_CONFIG_PATH`.

### MCP connection failed

Ensure the JACS MCP server is running. You can start it with:

```bash
python -m jacs.mcp_server
# or
fastmcp run jacs.mcp:mcp
```

### Signature verification failed

Ensure both the signer and verifier have access to the same trust store, or that the verifier has added the signer's agent to their trust store.

### HAI Troubleshooting

#### "Agent not found" when fetching key

The agent may not be registered with HAI. Ask them to:
1. Register with HAI using `register_agent`
2. Ensure their `jacs-mcp` server is configured with `HAI_API_KEY`

#### Low attestation level (Level 0 or 1)

Higher trust levels require:
- **Level 2**: DNS verification (agent must control the claimed domain)
- **Level 3**: Full HAI attestation (contact HAI for enterprise verification)

#### Connection errors to HAI

Check:
1. Network connectivity to `https://api.hai.ai`
2. `HAI_ENDPOINT` environment variable if using a custom endpoint
3. `HAI_API_KEY` is set correctly (some operations require authentication)

#### jacs-mcp not found

Install the jacs-mcp binary:
```bash
# From the JACS repository
cd jacs-mcp
cargo install --path .
```

Or use the Python-based server (without HAI tools):
```bash
python -m jacs.mcp_server
```

## Security Best Practices

### Trust Level Guidelines

| Operation | Minimum Trust Level |
|-----------|---------------------|
| Read-only data sharing | Level 1 (Basic) |
| Collaborative tasks | Level 2 (Domain) |
| Financial transactions | Level 3 (Attested) |
| Critical system access | Level 3 (Attested) |

### Key Management

1. **Never share private keys** - Only public keys are distributed via HAI
2. **Rotate keys periodically** - Use version tracking in fetch_agent_key
3. **Verify before trust** - Always check attestation levels before trusting new agents
4. **Cache carefully** - Public keys can be cached, but verify periodically
