# LangChain + JACS Integration Examples

These examples demonstrate how to use JACS cryptographic signing with LangChain agents via the Model Context Protocol (MCP).

## Overview

JACS provides cryptographic signing and verification for AI agent outputs. By integrating with LangChain via MCP, you can:

- Sign AI agent outputs to prove their origin
- Verify that data came from a specific trusted agent
- Create multi-party agreements requiring multiple agent signatures
- Maintain audit trails of signed interactions

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

## Architecture

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

## Troubleshooting

### "No agent loaded" error

Make sure you have a valid `jacs.config.json` in the current directory or set `JACS_CONFIG_PATH`.

### MCP connection failed

Ensure the JACS MCP server is running. You can start it with:

```bash
python -m jacs.mcp_server
# or
fastmcp run jacs.mcp_simple:mcp
```

### Signature verification failed

Ensure both the signer and verifier have access to the same trust store, or that the verifier has added the signer's agent to their trust store.
