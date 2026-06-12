# Multi-Agent Agreements

Agreement v2 is the recommended JACS model for new multi-agent consent workflows. It creates a standalone `jacsType: "agreement"` document with terms, parties, signature policy, transcript references, notary support, and verifiable status.

Use it when the question is: "did these agents agree to these terms?"

## The Lifecycle

```text
Create agreement -> append transcript refs -> signers consent -> HAI notarizes -> verify final status
```

## Python

The three agents are persistent and share one `data_directory` so each can resolve the others' public keys when verifying. Independent `ephemeral()` agents keep keys in memory only and cannot verify each other's signatures.

```python
import tempfile
from pathlib import Path

from jacs import SimpleAgent

PASSWORD = "MultiAgentDemo!2026"
workspace = Path(tempfile.mkdtemp(prefix="jacs_multi_agent_"))
shared_data = workspace / "shared_data"  # all agents share this so keys resolve


def make_agent(name, agent_type="ai"):
    agent, info = SimpleAgent.create_agent(
        name=name,
        password=PASSWORD,
        algorithm="ring-Ed25519",
        data_directory=str(shared_data),
        key_directory=str(workspace / f"{name}_keys"),
        config_path=str(workspace / f"{name}.config.json"),
        agent_type=agent_type,
    )
    return agent, info


agent_a, a = make_agent("agent-a")
agent_b, b = make_agent("agent-b", agent_type="human")
hai, h = make_agent("hai-notary")

agreement = agent_a.create_agreement_v2({
    "title": "Bounded refund authorization",
    "description": "Two parties agree on a bounded refund; HAI notarizes the final state.",
    "terms": "Agent B may issue a refund up to $25 for order 123 after Agent A approval.",
    "termsFormat": "text/markdown",
    "status": "proposed",
    "parties": [
        {"agentId": a["agent_id"], "agentType": "ai", "role": "signer"},
        {"agentId": b["agent_id"], "agentType": "human", "role": "signer"},
        {"agentId": h["agent_id"], "agentType": "ai", "role": "notary"},
    ],
    "signaturePolicy": {
        "partyQuorum": "all",
        "witnessRequired": 0,
        "notaryRequired": 1,
        "minimumStrength": "classical",
    },
    "controllers": [a["agent_id"], b["agent_id"], h["agent_id"]],
})

agreement = agent_a.sign_agreement_v2(agreement, "signer")
agreement = agent_b.sign_agreement_v2(agreement, "signer")
agreement = hai.sign_agreement_v2(agreement, "notary")

# hai resolves agent_a's and agent_b's public keys from the shared data directory.
report = hai.verify_agreement_v2(agreement)
assert report["valid"]
assert report["expectedStatus"] == "final"
```

For a fuller runnable version with transcript references and adversarial checks:

```bash
python examples/agreement_v2_three_party.py
```

## What Gets Verified

- `jacsAgreementHash` matches the terms, parties, policy, and effective dates.
- Signer signatures satisfy `partyQuorum`.
- Witness and notary signatures satisfy their separate requirements.
- Signatures come from listed parties with matching roles.
- Transcript signatures bind the transcript hash when transcript entries exist.
- Header signature and controller checks prove the emitted version came from an authorized controller.
- `status` is recomputed before callers rely on it.

## Legacy Sidecar Agreements

The older `create_agreement()` / `sign_agreement()` / `check_agreement()` API still exists for adding `jacsAgreement` metadata to an arbitrary signed document. Use it for simple countersignature approval of an existing payload.

Use Agreement v2 for standalone terms, HAI notarization, transcript evidence, branch handling, or cross-language product workflows.

## Next Steps

- [Agreement v2 Developer Guide](../guides/agreement-v2.md)
- [Creating and Using Agreements](../rust/agreements.md)
- [Security Model](../advanced/security.md)
