# Multi-Agent Agreements

**Three agents from different organizations sign an agreement with 2-of-3 quorum.**

Imagine three departments -- Finance, Compliance, and Legal -- must approve a production deployment. Requiring all three creates bottlenecks. With JACS quorum agreements, any two of three is sufficient: cryptographically signed, independently verifiable, with a full audit trail.

No central authority. No shared database. Every signature is independently verifiable.

## The Lifecycle

```
Create Agreement --> Agent A Signs --> Agent B Signs --> Quorum Met (2/3) --> Verified
```

## Python

```python
from jacs.client import JacsClient

# Step 1: Create three agents (one per organization)
finance    = JacsClient.quickstart("ring-Ed25519", "./finance.config.json")
compliance = JacsClient.quickstart("ring-Ed25519", "./compliance.config.json")
legal      = JacsClient.quickstart("ring-Ed25519", "./legal.config.json")

# Step 2: Finance proposes an agreement with quorum
from datetime import datetime, timedelta, timezone

proposal = {
    "action": "Deploy model v2 to production",
    "conditions": ["passes safety audit", "approved by 2 of 3 signers"],
}
deadline = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

agreement = finance.create_agreement(
    document=proposal,
    agent_ids=[finance.agent_id, compliance.agent_id, legal.agent_id],
    question="Do you approve deployment of model v2?",
    context="Production rollout pending safety audit sign-off.",
    quorum=2,           # only 2 of 3 need to sign
    timeout=deadline,
)

# Step 3: Finance signs
agreement = finance.sign_agreement(agreement)

# Step 4: Compliance co-signs -- quorum is now met
agreement = compliance.sign_agreement(agreement)

# Step 5: Verify -- any party can confirm independently
status = finance.check_agreement(agreement)
print(f"Complete: {status.complete}")  # True -- 2 of 3 signed

for s in status.signers:
    label = "signed" if s.signed else "pending"
    print(f"  {s.agent_id[:12]}... {label}")
```

## Node.js / TypeScript

```typescript
import { JacsClient } from "@hai.ai/jacs/client";

async function main() {
  // Step 1: Create three agents
  const finance    = await JacsClient.ephemeral("ring-Ed25519");
  const compliance = await JacsClient.ephemeral("ring-Ed25519");
  const legal      = await JacsClient.ephemeral("ring-Ed25519");

  // Step 2: Finance proposes an agreement with quorum
  const proposal = {
    action: "Deploy model v2 to production",
    conditions: ["passes safety audit", "approved by 2 of 3 signers"],
  };
  const deadline = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const agentIds = [finance.agentId, compliance.agentId, legal.agentId];

  let agreement = await finance.createAgreement(proposal, agentIds, {
    question: "Do you approve deployment of model v2?",
    context: "Production rollout pending safety audit sign-off.",
    quorum: 2,
    timeout: deadline,
  });

  // Step 3: Finance signs
  agreement = await finance.signAgreement(agreement);

  // Step 4: Compliance co-signs -- quorum is now met
  agreement = await compliance.signAgreement(agreement);

  // Step 5: Verify
  const doc = JSON.parse(agreement.raw);
  const ag = doc.jacsAgreement;
  const sigCount = ag.signatures?.length ?? 0;
  console.log(`Signatures: ${sigCount} of ${agentIds.length}`);
  console.log(`Quorum met: ${sigCount >= (ag.quorum ?? agentIds.length)}`);
}

main().catch(console.error);
```

## What Just Happened?

1. **Three independent agents** were created, each with their own keys -- no shared secrets.
2. **Finance proposed** an agreement requiring 2-of-3 quorum with a one-hour deadline.
3. **Finance and Compliance signed.** Legal never needed to act -- quorum was met.
4. **Any party can verify** the agreement independently. The cryptographic proof chain is self-contained.

Every signature includes: the signer's agent ID, the signing algorithm, a timestamp, and a hash of the agreement content. If anyone tampers with the document after signing, verification fails.

## Next Steps

- [Agreements API Reference](../rust/agreements.md) -- timeout, algorithm constraints, and more
- [Python Framework Adapters](../python/adapters.md) -- use agreements inside LangChain, FastAPI, CrewAI
- [Security Model](../advanced/security.md) -- how the cryptographic proof chain works
