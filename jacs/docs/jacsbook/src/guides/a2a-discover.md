# Discover & Trust Remote Agents

Find other A2A agents and decide whether to trust them.

<div class="tabs">
<div class="tab">
<input type="radio" id="discover-python" name="discover-group" checked>
<label for="discover-python">Python</label>
<div class="content">

```python
from jacs.a2a_discovery import discover_and_assess_sync

result = discover_and_assess_sync("https://agent.example.com")
if result["allowed"]:
    print(f"Trusted: {result['card']['name']} ({result['trust_level']})")
```

### Add to Your Trust Store

For `strict` policy, agents must be in your local trust store:

```python
from jacs.client import JacsClient
from jacs.a2a import JACSA2AIntegration

client = JacsClient.quickstart()
a2a = JACSA2AIntegration(client, trust_policy="strict")

# Assess a remote agent's trustworthiness
assessment = a2a.assess_remote_agent(remote_card_json)
print(f"JACS registered: {assessment['jacs_registered']}")
print(f"Allowed: {assessment['allowed']}")

# Add to trust store (verifies agent's self-signature first)
a2a.trust_a2a_agent(remote_card_json)
```

### Async API

```python
from jacs.a2a_discovery import discover_agent, discover_and_assess

card = await discover_agent("https://agent.example.com")
result = await discover_and_assess("https://agent.example.com", policy="verified", client=client)
```

</div>
</div>

<div class="tab">
<input type="radio" id="discover-nodejs" name="discover-group">
<label for="discover-nodejs">Node.js</label>
<div class="content">

```javascript
const { discoverAndAssess } = require('@hai.ai/jacs/a2a-discovery');

const result = await discoverAndAssess('https://agent.example.com');
if (result.allowed) {
  console.log(`Trusted: ${result.card.name} (${result.trustLevel})`);
}
```

### Add to Your Trust Store

```javascript
const { JacsClient } = require('@hai.ai/jacs/client');
const { JACSA2AIntegration } = require('@hai.ai/jacs/a2a');

const client = await JacsClient.quickstart();
const a2a = new JACSA2AIntegration(client, 'strict');

// Assess a remote agent
const assessment = a2a.assessRemoteAgent(remoteCardJson);
console.log(`JACS registered: ${assessment.jacsRegistered}`);
console.log(`Allowed: ${assessment.allowed}`);

// Add to trust store
a2a.trustA2AAgent(remoteAgentId);
```

</div>
</div>
</div>

## Trust Policies

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `open` | Accept all agents without verification | Development, testing |
| `verified` | Require the `urn:hai.ai:jacs-provenance-v1` extension in the agent card | **Default** -- production use |
| `strict` | Require the signer to be in the local trust store | High-security environments |

### How Trust Flows

```
1. Discover  -- Fetch /.well-known/agent-card.json from a remote URL
2. Assess    -- Check for JACS extension, verify signatures
3. Decide    -- Trust policy determines if the agent is allowed
4. Trust     -- Optionally add the agent to your local trust store
```

With `open` policy, all agents pass step 3. With `verified`, agents must have the JACS extension. With `strict`, agents must be explicitly added to the trust store in step 4 before they pass.

## Next Steps

- **[Exchange Signed Artifacts](a2a-exchange.md)** -- Sign and verify artifacts with trusted agents
- **[Serve Your Agent Card](a2a-serve.md)** -- Make your agent discoverable
- **[Trust Store](../advanced/trust-store.md)** -- Managing the local trust store

<style>
.tabs { display: flex; flex-wrap: wrap; max-width: 100%; font-family: sans-serif; }
.tab { order: 1; flex-grow: 1; }
.tab input[type="radio"] { display: none; }
.tab label { display: block; padding: 1em; background: #f0f0f0; color: #666; border: 1px solid #ddd; cursor: pointer; margin-bottom: -1px; }
.tab label:hover { background: #e0e0e0; }
.tab input:checked + label { background: #007acc; color: white; }
.tab .content { order: 99; flex-grow: 1; width: 100%; display: none; padding: 1em; background: white; border: 1px solid #ddd; border-top: none; }
.tab input:checked ~ .content { display: block; }
</style>
