# What Is an Attestation?

> **Signing says WHO. Attestation says WHO plus WHY.**

A JACS attestation is a cryptographically signed document that goes beyond
proving *who* signed something. It records *why* a piece of data should be
trusted -- the evidence, the claims, and the reasoning behind that trust.

## Signing vs. Attestation

| | `sign_message()` | `create_attestation()` |
|---|---|---|
| **Proves** | Who signed it | Who signed it + why it's trustworthy |
| **Contains** | Signature + hash | Signature + hash + subject + claims + evidence |
| **Use case** | Data integrity | Trust decisions, audit trails, compliance |
| **Verification** | Was it tampered with? | Was it tampered with? Are the claims valid? Is the evidence fresh? |

## Key Concepts

### Subject
What is being attested. Every attestation targets a specific *subject* -- an
artifact, agent, workflow, or identity. The subject is identified by type, ID,
and cryptographic digests.

### Claims
What you assert about the subject. Claims are structured statements with a
name, value, optional confidence score (0.0-1.0), and assurance level
(`self-asserted`, `verified`, or `independently-attested`).

### Evidence
What supports the claims. Evidence references link to external proofs (A2A
messages, email headers, JWT tokens, TLS notary sessions) with their own
digests and timestamps.

### Derivation Chain
How the attestation was produced. When one attestation builds on another --
for example, a review attestation that references an earlier scan attestation
-- the derivation chain captures the full transformation history.

## Architecture Layers

```
Layer 2: Adapters (A2A, email, JWT, TLSNotary)
           |
Layer 1: Attestation Engine (create, verify, lift, DSSE export)
           |
Layer 0: JACS Core (sign, verify, agreements, storage)
```

Attestations build *on top of* existing JACS signing. Every attestation is also
a valid signed JACS document. You can verify an attestation with `verify()` for
signature checks, or use `verify_attestation()` for the full trust evaluation.

## Quick Example

```python
from jacs.client import JacsClient

client = JacsClient.ephemeral(algorithm="ed25519")

# Sign a document (Layer 0)
signed = client.sign_message({"action": "approve", "amount": 100})

# Attest WHY it's trustworthy (Layer 1)
att = client.create_attestation(
    subject={"type": "artifact", "id": signed.document_id,
             "digests": {"sha256": "..."}},
    claims=[{"name": "reviewed", "value": True, "confidence": 0.95}],
)

# Verify the full trust chain
result = client.verify_attestation(att.raw_json, full=True)
print(f"Valid: {result['valid']}")
```

## Attestation vs. A2A Trust Policy

Attestation (Layer C) provides trust context: claims, evidence, and derivation chains. It answers *"why should this data be trusted?"* A2A trust policy (Layer B) handles agent admission: *"is this agent allowed to communicate?"*

For transport trust decisions, see [A2A Interoperability](../integrations/a2a.md). For how attestation and A2A compose, see [A2A + Attestation Composition](../guides/a2a-attestation-composition.md). For the full three-layer model, see [Trust Layers](trust-layers.md).

## When to Use Attestations

Use attestations when you need to answer questions like:
- **Why should I trust this data?** (claims + evidence)
- **Who reviewed it and when?** (issuer, timestamps, assurance level)
- **How was it produced?** (derivation chain)
- **Can I independently verify the trust chain?** (DSSE export, evidence verification)

If you only need to prove *who* signed something and that it hasn't been
tampered with, `sign_message()` is sufficient. See
[Sign vs. Attest](../guides/sign-vs-attest.md) for a detailed decision guide.
