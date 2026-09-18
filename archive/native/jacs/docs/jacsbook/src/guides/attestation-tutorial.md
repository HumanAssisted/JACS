# Tutorial: Add Attestations to Your Workflow

This step-by-step tutorial walks you through adding attestation support to an
existing JACS workflow. You'll go from basic signing to full attestation
creation and verification in under 5 minutes.

## Prerequisites

- JACS installed (Python, Node.js, or CLI)
- Attestation feature enabled (built with `--features attestation`)

## Step 1: Create an Agent

Use an ephemeral agent for testing (no files on disk):

{{#tabs }}
{{#tab name="Python" }}
```python
from jacs.client import JacsClient

client = JacsClient.ephemeral(algorithm="ed25519")
print(f"Agent ID: {client.agent_id}")
```
{{#endtab }}
{{#tab name="Node.js" }}
```javascript
const { JacsClient } = require('@hai.ai/jacs/client');

const client = await JacsClient.ephemeral('ring-Ed25519');
console.log(`Agent ID: ${client.agentId}`);
```
{{#endtab }}
{{#tab name="CLI" }}
```bash
export JACS_PRIVATE_KEY_PASSWORD="YourP@ssw0rd"
jacs quickstart --algorithm ed25519
```
{{#endtab }}
{{#endtabs }}

## Step 2: Sign a Document

Sign some data to establish the base document:

{{#tabs }}
{{#tab name="Python" }}
```python
signed = client.sign_message({"action": "approve", "amount": 100})
print(f"Document ID: {signed.document_id}")
```
{{#endtab }}
{{#tab name="Node.js" }}
```javascript
const signed = await client.signMessage({ action: 'approve', amount: 100 });
console.log(`Document ID: ${signed.documentId}`);
```
{{#endtab }}
{{#endtabs }}

## Step 3: Create an Attestation

Now add trust context -- *why* this document should be trusted:

{{#tabs }}
{{#tab name="Python" }}
```python
import hashlib
content_hash = hashlib.sha256(signed.raw_json.encode()).hexdigest()
attestation = client.create_attestation(
    subject={
        "type": "artifact",
        "id": signed.document_id,
        "digests": {"sha256": content_hash},
    },
    claims=[
        {
            "name": "reviewed_by",
            "value": "human",
            "confidence": 0.95,
            "assuranceLevel": "verified",
        }
    ],
)
print(f"Attestation ID: {attestation.document_id}")
```
{{#endtab }}
{{#tab name="Node.js" }}
```javascript
const { createHash } = require('crypto');
const contentHash = createHash('sha256').update(signed.raw).digest('hex');
const attestation = await client.createAttestation({
  subject: {
    type: 'artifact',
    id: signed.documentId,
    digests: { sha256: contentHash },
  },
  claims: [{
    name: 'reviewed_by',
    value: 'human',
    confidence: 0.95,
    assuranceLevel: 'verified',
  }],
});
console.log(`Attestation ID: ${attestation.documentId}`);
```
{{#endtab }}
{{#endtabs }}

## Step 4: Verify the Attestation

### Local Verification (fast -- signature + hash only)

{{#tabs }}
{{#tab name="Python" }}
```python
result = client.verify_attestation(attestation.raw_json)
print(f"Valid: {result['valid']}")
print(f"Signature OK: {result['crypto']['signature_valid']}")
print(f"Hash OK: {result['crypto']['hash_valid']}")
```
{{#endtab }}
{{#tab name="Node.js" }}
```javascript
const result = await client.verifyAttestation(attestation.raw);
console.log(`Valid: ${result.valid}`);
console.log(`Signature OK: ${result.crypto.signature_valid}`);
console.log(`Hash OK: ${result.crypto.hash_valid}`);
```
{{#endtab }}
{{#endtabs }}

### Full Verification (thorough -- includes evidence + derivation chain)

{{#tabs }}
{{#tab name="Python" }}
```python
full = client.verify_attestation(attestation.raw_json, full=True)
print(f"Valid: {full['valid']}")
print(f"Evidence: {full.get('evidence', [])}")
print(f"Chain: {full.get('chain')}")
```
{{#endtab }}
{{#tab name="Node.js" }}
```javascript
const full = await client.verifyAttestation(attestation.raw, { full: true });
console.log(`Valid: ${full.valid}`);
console.log(`Evidence: ${JSON.stringify(full.evidence)}`);
console.log(`Chain: ${JSON.stringify(full.chain)}`);
```
{{#endtab }}
{{#endtabs }}

## Step 5: Add Evidence (Optional)

Evidence references link to external proofs that support your claims:

{{#tabs }}
{{#tab name="Python" }}
```python
attestation_with_evidence = client.create_attestation(
    subject={
        "type": "artifact",
        "id": "doc-001",
        "digests": {"sha256": "abc123..."},
    },
    claims=[{"name": "scanned", "value": True, "confidence": 1.0}],
    evidence=[
        {
            "kind": "custom",
            "digests": {"sha256": "evidence-hash..."},
            "uri": "https://scanner.example.com/results/123",
            "collectedAt": "2026-03-04T00:00:00Z",
            "verifier": {"name": "security-scanner", "version": "2.0"},
        }
    ],
)
```
{{#endtab }}
{{#tab name="Node.js" }}
```javascript
const attWithEvidence = await client.createAttestation({
  subject: {
    type: 'artifact',
    id: 'doc-001',
    digests: { sha256: 'abc123...' },
  },
  claims: [{ name: 'scanned', value: true, confidence: 1.0 }],
  evidence: [{
    kind: 'custom',
    digests: { sha256: 'evidence-hash...' },
    uri: 'https://scanner.example.com/results/123',
    collectedAt: '2026-03-04T00:00:00Z',
    verifier: { name: 'security-scanner', version: '2.0' },
  }],
});
```
{{#endtab }}
{{#endtabs }}

## Step 6: Export as DSSE (Optional)

Export your attestation as a DSSE (Dead Simple Signing Envelope) for
compatibility with in-toto, SLSA, and Sigstore:

{{#tabs }}
{{#tab name="Python" }}
```python
envelope = client.export_attestation_dsse(attestation.raw_json)
print(f"Payload type: {envelope['payloadType']}")
print(f"Signatures: {len(envelope['signatures'])}")
```
{{#endtab }}
{{#tab name="Node.js" }}
```javascript
const envelope = await client.exportAttestationDsse(attestation.raw);
console.log(`Payload type: ${envelope.payloadType}`);
console.log(`Signatures: ${envelope.signatures.length}`);
```
{{#endtab }}
{{#endtabs }}

## What's Next?

- [Sign vs. Attest decision guide](sign-vs-attest.md) -- when to use which API
- [Attestation error catalog](../reference/attestation-errors.md) -- understand verification results
- [What is an attestation?](../getting-started/attestation.md) -- concept deep dive
