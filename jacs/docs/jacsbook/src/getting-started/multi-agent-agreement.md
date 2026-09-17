# Multi-Agent Agreements

Agreement v2 records terms and agent consent signatures in a standalone `jacsType: "agreement"` document. Its verifier inspects mathematical and structural checks. It does not accept the full authorization policy or prove human approval, even when the supplied quorum produces a `final` status.

Use this walkthrough to inspect agent provenance. An application must separately establish the authority and any exact-action human approval required before acting.

## The Lifecycle

```text
Create agreement -> append transcript refs -> collect signer/notary signatures -> inspect math and policy scope
```

## Python

All three demo identities are controlled by this code, including the agent labeled `notary`; no person or external notary approves anything here.

The three agents are persistent and share one `data_directory` so each can resolve the others' public keys when verifying. Independent `ephemeral()` agents keep keys in memory only and cannot verify each other's signatures.

```python
import os
import secrets
import tempfile
from pathlib import Path

from jacs import SimpleAgent

os.environ["JACS_KEYCHAIN_BACKEND"] = "disabled"  # throwaway demo only
PASSWORD = secrets.token_urlsafe(32)
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
agent_b, b = make_agent("agent-b")
notary, n = make_agent("demo-notary")

agreement = agent_a.create_agreement_v2({
    "title": "Bounded refund authorization",
    "description": "Demo refund terms for agent signature inspection; no refund is authorized.",
    "terms": "Agent B may issue a refund up to $25 for order 123 after Agent A approval.",
    "termsFormat": "text/markdown",
    "status": "proposed",
    "parties": [
        {"agentId": a["agent_id"], "agentType": "ai", "role": "signer"},
        {"agentId": b["agent_id"], "agentType": "ai", "role": "signer"},
        {"agentId": n["agent_id"], "agentType": "ai", "role": "notary"},
    ],
    "signaturePolicy": {
        "partyQuorum": "all",
        "witnessRequired": 0,
        "notaryRequired": 1,
        "minimumStrength": "classical",
    },
    "controllers": [a["agent_id"], b["agent_id"], n["agent_id"]],
})

agreement = agent_a.sign_agreement_v2(agreement, "signer")
agreement = agent_b.sign_agreement_v2(agreement, "signer")
agreement = notary.sign_agreement_v2(agreement, "notary")

# The demo notary resolves the signers' public keys from shared storage.
report = notary.verify_agreement_v2(agreement)
assert report["mathematicalChecksValid"] is True
assert report["valid"] is False
assert report["policyAccepted"] is False
assert report["overallScope"] == "consent_signatures_only"
assert report["expectedStatus"] == "final"  # structural diagnostic only
```

This abbreviated snippet leaves its temporary workspace for inspection; remove it when finished. The runnable version includes transcript references and adversarial checks, and cleans up its temporary keys:

```bash
python examples/agreement_v2_three_party.py
```

## What the Report Means

- `mathematicalChecksValid` covers the native hash, signature and structural checks. Inspect `errors` for failures and `notes`, `verifiedChainDepth` and `chainFullyVerified` for lineage coverage limits.
- Consent signatures bind the agreement identity and consent hash; signatures made with a nonempty transcript also bind its prefix at signing. Later unsigned transcript entries are not retroactively covered.
- Signer counts, quorum, witness/notary requirements and `expectedStatus` are diagnostics against the supplied document. Neither a count nor `status: "final"` is an accepted policy verdict.
- Helpers check membership, role and controller lists. These checks do not establish portable role/controller authority or a person's approval. Changing an agent's label to `human` does not add human approval evidence.
- `valid` and `policyAccepted` remain false, including for the successful mathematical inspection above. Do not turn either field into true or treat `mathematicalChecksValid` as permission to act.

## Legacy Sidecar Agreements

The older `create_agreement()` / `sign_agreement()` / `check_agreement()` API still exists for adding `jacsAgreement` metadata to an arbitrary signed document. It supports signature inspection of an existing payload; those signatures alone do not establish human approval or the complete application policy.

V2 adds standalone terms, transcript-prefix evidence and branch helpers. Moving to v2 does not create an actionable authorization.

## Next Steps

- [Agreement v2 Developer Guide](../guides/agreement-v2.md)
- [Creating and Using Agreements](../rust/agreements.md)
- [Security Model](../advanced/security.md)
