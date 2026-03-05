# Sign vs. Attest: When to Use Which

This guide helps you choose the right JACS API for your use case.

## Decision Tree

**Start here: What do you need to prove?**

1. **"This data hasn't been tampered with"**
   - Use `sign_message()` / `signMessage()`
   - This gives you a cryptographic signature and integrity hash.

2. **"This data hasn't been tampered with AND here's why it should be trusted"**
   - Use `create_attestation()` / `createAttestation()`
   - This gives you signature + integrity + claims + evidence + derivation chain.

3. **"I have an existing signed document and want to add trust context"**
   - Use `lift_to_attestation()` / `liftToAttestation()`
   - This wraps an existing JACS-signed document into a new attestation.

4. **"I need to export a trust proof for external systems"**
   - Use `export_attestation_dsse()` / `exportAttestationDsse()`
   - This creates an in-toto DSSE envelope compatible with SLSA and Sigstore.

## Quick Reference

| Scenario | API | Output |
|---|---|---|
| Log an AI action | `sign_message()` | Signed document |
| Record a human review decision | `create_attestation()` | Attestation with claims |
| Attach evidence from another system | `create_attestation()` with `evidence` | Attestation with evidence refs |
| Wrap an existing signed doc with trust context | `lift_to_attestation()` | New attestation referencing original |
| Export for SLSA/Sigstore | `export_attestation_dsse()` | DSSE envelope |
| Verify signature only | `verify()` | Valid/invalid + signer |
| Verify signature + claims + evidence | `verify_attestation(full=True)` | Full verification result |

## Examples

### Just need integrity? Use signing.

```python
signed = client.sign_message({"action": "approve"})
result = client.verify(signed.raw_json)
# result["valid"] == True
```

### Need trust context? Use attestation.

```python
att = client.create_attestation(
    subject={"type": "artifact", "id": "doc-001", "digests": {"sha256": "..."}},
    claims=[{"name": "reviewed", "value": True, "confidence": 0.95}],
)
result = client.verify_attestation(att.raw_json, full=True)
# result["valid"] == True, result["evidence"] == [...]
```

### Already signed? Lift to attestation.

```python
signed = client.sign_message({"content": "original"})
att = client.lift_to_attestation(signed, [{"name": "approved", "value": True}])
# att now has attestation metadata referencing the original document
```

## Common Patterns

### AI Agent Action Logging
Use `sign_message()` for each tool call or action. The signature proves the
agent took the action and the data hasn't been modified.

### Human Review Attestation
Use `create_attestation()` with claims like `reviewed_by: human` and
`confidence: 0.95`. This creates an auditable record that a human reviewed
and approved the output.

### Multi-step Pipeline
Use `create_attestation()` with a `derivation` field to capture input/output
relationships. Each step attests to its own transformation with references
to upstream attestations.

### Cross-system Verification
Use `export_attestation_dsse()` to generate an in-toto DSSE envelope that
external systems (SLSA verifiers, Sigstore) can validate independently.
