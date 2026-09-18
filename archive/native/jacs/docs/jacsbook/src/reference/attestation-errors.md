# Attestation Verification Results

This reference explains every field in the `AttestationVerificationResult`
returned by `verify_attestation()` and `verify_attestation_full()`.

## Result Structure

```json
{
  "valid": true,
  "crypto": {
    "signature_valid": true,
    "hash_valid": true
  },
  "evidence": [
    {
      "kind": "custom",
      "digest_valid": true,
      "freshness_valid": true,
      "errors": []
    }
  ],
  "chain": {
    "depth": 1,
    "all_links_valid": true,
    "links": []
  },
  "errors": []
}
```

## Top-Level Fields

| Field | Type | Description |
|---|---|---|
| `valid` | `boolean` | Overall result. `true` only if all sub-checks pass. |
| `crypto` | `object` | Cryptographic verification results. |
| `evidence` | `array` | Per-evidence-ref verification results (full tier only). |
| `chain` | `object\|null` | Derivation chain verification (full tier only, if derivation exists). |
| `errors` | `array` | Human-readable error messages for any failures. |

## `crypto` Object

| Field | Type | Description |
|---|---|---|
| `signature_valid` | `boolean` | The cryptographic signature matches the document content and the signer's public key. |
| `hash_valid` | `boolean` | The `jacsSha256` hash matches the canonicalized document content. |

**Common failure scenarios:**
- `signature_valid: false` -- The document was tampered with after signing, or the wrong public key was used.
- `hash_valid: false` -- The document body was modified after the hash was computed.

## `evidence` Array (Full Tier Only)

Each entry corresponds to one evidence reference in the attestation's
`evidence` array.

| Field | Type | Description |
|---|---|---|
| `kind` | `string` | Evidence type (`a2a`, `email`, `jwt`, `tlsnotary`, `custom`). |
| `digest_valid` | `boolean` | The evidence digest matches the expected value. |
| `freshness_valid` | `boolean` | The `collectedAt` timestamp is within acceptable bounds. |
| `errors` | `array` | Error messages specific to this evidence item. |

**Common failure scenarios:**
- `digest_valid: false` -- The evidence content has changed since the attestation was created.
- `freshness_valid: false` -- The evidence is too old. Check `collectedAt` and your freshness policy.

## `chain` Object (Full Tier Only)

Present only when the attestation has a `derivation` field.

| Field | Type | Description |
|---|---|---|
| `depth` | `number` | Number of links in the derivation chain. |
| `all_links_valid` | `boolean` | Every derivation link verified successfully. |
| `links` | `array` | Per-link verification details. |

Each link in `links`:

| Field | Type | Description |
|---|---|---|
| `input_digests_valid` | `boolean` | Input digests match the referenced documents. |
| `output_digests_valid` | `boolean` | Output digests match the transformation result. |
| `transform` | `object` | Transform metadata (name, hash, reproducible). |

## Verification Tiers

### Local Tier (`verify_attestation()`)
- Checks: `crypto.signature_valid` + `crypto.hash_valid`
- Speed: < 1ms typical
- Network: None
- Use for: Real-time validation, hot path

### Full Tier (`verify_attestation(full=True)`)
- Checks: Everything in local + evidence digests + freshness + derivation chain
- Speed: < 10ms typical (no network), varies with evidence count
- Network: Optional (for remote evidence resolution)
- Use for: Audit trails, compliance, trust decisions

## Troubleshooting

### "valid is false but crypto shows all true"
The `valid` field aggregates all sub-checks. If `crypto` passes but evidence
or chain checks fail, `valid` will be `false`. Check the `evidence` and
`chain` fields for details.

### "evidence is empty"
If you created the attestation without evidence references, the `evidence`
array will be empty. This is not an error -- it means there are no external
proofs to verify.

### "chain is null"
If the attestation has no `derivation` field, `chain` will be `null`. This
is normal for standalone attestations that don't reference prior attestations.

### "signature_valid is false after serialization"
JACS uses JSON Canonicalization Scheme (JCS) for hashing. If you serialize
and re-parse the document, ensure the serializer preserves field order and
does not add/remove whitespace in a way that changes the canonical form.
