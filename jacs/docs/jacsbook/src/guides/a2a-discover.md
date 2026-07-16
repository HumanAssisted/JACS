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

For `strict` policy, establish native JACS trust from an authenticated agent
document and explicit native public key. An Agent Card is self-advertised and
cannot create strict identity trust by itself:

```python
from jacs.client import JacsClient
from jacs.a2a import JACSA2AIntegration

client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")
a2a = JACSA2AIntegration(client, trust_policy="strict")

# Assess a remote agent's trustworthiness
assessment = a2a.assess_remote_agent(remote_card_json)
print(f"JACS registered: {assessment['jacs_registered']}")
print(f"Allowed: {assessment['allowed']}")

# Obtain both values through an authenticated out-of-band channel.
a2a.trust_a2a_agent(remote_native_agent_json, remote_native_public_key_pem)
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

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});
const a2a = new JACSA2AIntegration(client, 'strict');

// Assess a remote agent
const assessment = a2a.assessRemoteAgent(remoteCardJson);
console.log(`JACS registered: ${assessment.jacsRegistered}`);
console.log(`Allowed: ${assessment.allowed}`);

// Obtain both through an authenticated out-of-band channel. Passing an
// Agent Card here is rejected.
a2a.trustA2AAgent(remoteNativeAgentDocument, remoteNativePublicKeyPem);
```

</div>
</div>
</div>

## Trust Policies

{{#include ../_snippets/a2a-trust-policies.md}}

### How Trust Flows

```
1. Discover  -- Fetch /.well-known/agent-card.json from a remote URL
2. Assess    -- Check for JACS extension, verify signatures
3. Decide    -- Trust policy determines if the agent is allowed
4. Trust     -- Optionally add the agent to your local trust store
```

With `open`, all agents pass step 3 without identity assurance. With
`verified`, the Agent Card JWS must verify against the same-origin JWKS and the
ES256 key must match its durable TOFU pin; this proves origin/key continuity,
not native identity. With `strict`, the native root must be explicitly trusted
and its signed compatibility binding must authorize the exact card key,
identity, version, scope, and current binding hash.

## Next Steps

- **[Exchange Signed Artifacts](a2a-exchange.md)** -- Sign and verify artifacts with trusted agents
- **[Serve Your Agent Card](a2a-serve.md)** -- Make your agent discoverable
- **[Trust Store](../advanced/trust-store.md)** -- Managing the local trust store
