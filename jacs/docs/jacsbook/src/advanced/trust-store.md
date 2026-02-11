# Trust Store Operations

The JACS trust store is a local directory of agent public keys and metadata that your agent has explicitly chosen to trust. It enables offline signature verification without a central authority -- once you trust an agent, you can verify its signatures without network access.

## How it works

When you add an agent to your trust store, JACS:

1. Parses the agent's JSON document
2. Extracts the public key and verifies the agent's self-signature
3. Saves the agent document, public key, and metadata to `~/.jacs/trust_store/`

After that, any document signed by that agent can be verified locally using the cached public key.

## API

All bindings expose five trust store functions:

| Function | Description |
|----------|-------------|
| `trust_agent(agent_json)` | Add an agent to the trust store (verifies self-signature first) |
| `list_trusted_agents()` | List all trusted agent IDs |
| `is_trusted(agent_id)` | Check if an agent is in the trust store |
| `get_trusted_agent(agent_id)` | Retrieve the full agent JSON |
| `untrust_agent(agent_id)` | Remove an agent from the trust store |

## Python example

```python
import jacs

# Receive an agent document from a partner organization
remote_agent_json = receive_from_partner()

# Add to trust store (self-signature is verified automatically)
agent_id = jacs.trust_agent(remote_agent_json)
print(f"Now trusting: {agent_id}")

# Later, check trust before processing a signed document
if jacs.is_trusted(sender_id):
    # Verify their signature using the cached public key
    result = jacs.verify(signed_document)

# List all trusted agents
for aid in jacs.list_trusted_agents():
    print(aid)

# Remove trust
jacs.untrust_agent(agent_id)
```

## Node.js example

```typescript
import { trustAgent, isTrusted, listTrustedAgents, untrustAgent } from '@hai.ai/jacs';

// Add a partner's agent to the trust store
const agentId = trustAgent(remoteAgentJson);

// Check trust
if (isTrusted(senderId)) {
  const result = verify(signedDocument);
}

// List and remove
const trusted = listTrustedAgents();
untrustAgent(agentId);
```

## Cross-organization scenario

A realistic deployment involves two organizations that need to verify each other's agent signatures:

1. **Org B** creates an agent and publishes its public key via DNS TXT records or a HAI key distribution endpoint
2. **Org A** fetches Org B's agent document (via `fetch_remote_key` or direct exchange)
3. **Org A** calls `trust_agent()` with Org B's agent JSON -- JACS verifies the self-signature and caches the public key
4. From this point on, Org A can verify any document signed by Org B's agent **offline**, using only the local trust store

This is the same model as SSH `known_hosts` or PGP key signing: trust is established once through a verified channel, then used repeatedly without network round-trips.

## Security notes

- `trust_agent()` cryptographically verifies the agent's self-signature before adding it to the store. A tampered agent document will be rejected.
- Agent IDs are validated against path traversal attacks before any filesystem operations.
- The trust store directory (`~/.jacs/trust_store/`) should be protected with appropriate file permissions.
- Revoking trust with `untrust_agent()` removes both the agent document and cached key material.
