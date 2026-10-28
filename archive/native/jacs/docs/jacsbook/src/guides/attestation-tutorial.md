# Create and Verify an Attestation

An attestation signs claims about a subject. Verification authenticates the
issuer's statement; the truth of a claim and permission to act require separate
evidence and application policy.

The Python example below uses an ephemeral `pq2025` agent. It requires the
native attestation feature; source builds enable it with the `attestation`
Cargo feature. See [Python installation](../python/installation.md).

## Create a claim about a signed document

```python
import hashlib
from jacs.client import JacsClient

client = JacsClient.ephemeral()
signed = client.sign_message({"tool": "calculator", "answer": 42})
content_hash = hashlib.sha256(signed.raw.encode("utf-8")).hexdigest()

attestation = client.create_attestation(
    subject={
        "type": "artifact",
        "id": signed.document_id,
        "digests": {"sha256": content_hash},
    },
    claims=[{
        "name": "purpose",
        "value": "calculation example",
        "assuranceLevel": "self-asserted",
    }],
)
result = client.verify_attestation(attestation.raw)
assert result["valid"]
assert result["crypto"]["signatureValid"]
assert result["crypto"]["hashValid"]
```

The subject digest here covers the exact UTF-8 signed-document JSON. Preserve
those bytes when exchanging the subject. A subject reference alone does not
make the referenced artifact available to a verifier.

## Local and full verification

`verify_attestation()` extracts the document's `id:version` and checks the
copy already in this agent's document store. It is not an arbitrary inbound JSON
verification API. Full verification additionally examines evidence and derivation:

```python
full = client.verify_attestation(attestation.raw, full=True)
print(full["valid"], full.get("evidence"), full.get("chain"))
```

Inspect the complete report and errors before accepting it. The current full
verifier uses the loaded agent's key; do not assume it can fully verify an
arbitrary other agent's attestation. Exchanging bytes or resolving a public key
does not remove that implementation limitation.

Full verification does not fetch URI-only evidence. Non-embedded evidence whose
bytes are unavailable reports `digestValid=false`; an HTTPS URL and a claimed
digest do not form a passing evidence check by themselves. Built-in A2A and
Email evidence adapters only record and compare digests, not protocol signatures
or signer trust. See [custom evidence adapters](custom-adapters.md).

Claims such as `reviewed_by=human`, a confidence score or an assurance label
are assertions until supported by independently verified reviewer evidence.
Never use a self-selected label as a substitute for that evidence.

## DSSE export

```python
envelope = client.export_attestation_dsse(attestation.raw)
print(envelope["payloadType"], len(envelope["signatures"]))
```

This produces a DSSE-shaped export. Acceptance by in-toto, SLSA or Sigstore
consumers depends on their verifier, algorithms and policy; export alone does
not demonstrate interoperability or authorization.

Continue with [framework attestations](framework-attestation.md),
[sign versus attest](sign-vs-attest.md), or the
[attestation error catalog](../reference/attestation-errors.md).
