# Trust Store Operations

The native trust store retains explicitly enrolled public identities for selection by verification and admission workflows. First enrollment requires both the full self-signed agent document and an independently authenticated public key. A fetched Agent Card or its same-origin JWKS does not establish that trust.

## Enroll a partner

Obtain `partner-agent.json` and `partner-public.pem` through an authenticated channel, then:

```python
from pathlib import Path
from jacs.client import JacsClient

client = JacsClient.quickstart(name="receiver", domain="receiver.example.com")
agent_json = Path("partner-agent.json").read_text()
public_key_pem = Path("partner-public.pem").read_text()
lookup_id = client.trust_agent_with_key(agent_json, public_key_pem)
assert client.is_trusted(lookup_id)
```

The partner can export these public values with `share_agent()` and `share_public_key()`. Enrollment checks the document's self-signature against the supplied key and returns the exact `agent_id:version` lookup ID. Protect the local trust directory and its writes; native storage uses the OS/XDG JACS data location under `trusted_agents`, not a universal `~/.jacs/trust_store` path.

The Rust equivalent is `jacs::trust::trust_agent_with_key(&agent_json, Some(&public_key_pem))?`. The older `trust_agent(agent_json)` refreshes an already enrolled identity; it cannot bootstrap an unknown key.

## Use and revoke trust

Check the exact identity/version and verify the signed document before applying application authorization. Configure the selected verifier's key resolver as well: native A2A artifact verification uses a separate local public-key cache or registry, not automatically this trust-store cache. Trust-store membership alone does not validate arbitrary input or approve an action. Retain independently trusted historical keys when old signatures must remain verifiable; UUID versions are identifiers, not ordered ranges.

`untrust_agent()` records stable-identity distrust and retains historical documents and keys. It does not erase public history. Subsequent trust decisions must honor that marker; re-enrollment is an explicit administrative decision.

DNS TXT records can corroborate a public-key fingerprint. They do not supply public-key bytes. See [DNS trust](dns-trust.md), [verification](../getting-started/verification.md), and [A2A discovery](../guides/a2a-discover.md) for the separate resolution and admission steps.
