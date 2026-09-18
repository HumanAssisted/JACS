# CLI Reference: jacs attest

The `jacs attest` command creates and verifies attestation documents from
the command line. Attestation extends basic signing with structured claims,
evidence references, and derivation chains.

## jacs attest create

Create a signed attestation document.

### Synopsis

```bash
jacs attest create --claims '<JSON>' [options]
```

### Options

| Flag | Required | Description |
|------|----------|-------------|
| `--claims '<JSON>'` | Yes | JSON array of claims. Each claim must have `name` and `value` fields. |
| `--subject-type <TYPE>` | No | Type of subject: `agent`, `artifact`, `workflow`, `identity`. Default: derived from context. |
| `--subject-id <ID>` | No | Identifier of the subject being attested. |
| `--subject-digest <SHA256>` | No | SHA-256 digest of the subject content. |
| `--evidence '<JSON>'` | No | JSON array of evidence references. |
| `--from-document <FILE>` | No | Lift an existing signed JACS document into an attestation. Overrides subject flags. |
| `-o, --output <FILE>` | No | Write attestation to file instead of stdout. |

### Examples

**Create a basic attestation:**

```bash
jacs attest create \
  --subject-type artifact \
  --subject-id "doc-001" \
  --subject-digest "abc123def456..." \
  --claims '[{"name": "reviewed_by", "value": "human", "confidence": 0.95}]'
```

**Attestation with multiple claims:**

```bash
jacs attest create \
  --subject-type agent \
  --subject-id "agent-abc" \
  --subject-digest "sha256hash..." \
  --claims '[
    {"name": "reviewed", "value": true, "confidence": 0.95},
    {"name": "source", "value": "internal_db", "assuranceLevel": "verified"}
  ]'
```

**Lift an existing signed document to attestation:**

```bash
jacs attest create \
  --from-document mydata.signed.json \
  --claims '[{"name": "approved", "value": true}]'
```

**With evidence references:**

```bash
jacs attest create \
  --subject-type artifact \
  --subject-id "report-456" \
  --subject-digest "def789..." \
  --claims '[{"name": "scanned", "value": true}]' \
  --evidence '[{
    "kind": "custom",
    "digests": {"sha256": "evidence-hash..."},
    "uri": "https://scanner.example.com/results/123",
    "collectedAt": "2026-03-04T00:00:00Z",
    "verifier": {"name": "security-scanner", "version": "2.0"}
  }]'
```

**Write to file:**

```bash
jacs attest create \
  --subject-type artifact \
  --subject-id "doc-001" \
  --subject-digest "abc123..." \
  --claims '[{"name": "ok", "value": true}]' \
  -o attestation.json
```

## jacs attest verify

Verify an attestation document.

### Synopsis

```bash
jacs attest verify <FILE> [options]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `<FILE>` | Yes | Path to the attestation JSON file to verify. |

### Options

| Flag | Required | Description |
|------|----------|-------------|
| `--full` | No | Use full verification (evidence + derivation chain). Default: local verification (crypto + hash only). |
| `--json` | No | Output the verification result as JSON. |
| `--key-dir <DIR>` | No | Directory containing public keys for verification. |
| `--max-depth <N>` | No | Maximum derivation chain depth. Default: 10. |

### Examples

**Basic verification (local tier):**

```bash
jacs attest verify attestation.json
```

Output:
```
Attestation verification: VALID
  Signature: OK
  Hash: OK
  Signer: agent-id-abc123
  Algorithm: ring-Ed25519
```

**Full verification:**

```bash
jacs attest verify attestation.json --full
```

Output:
```
Attestation verification: VALID
  Signature: OK
  Hash: OK
  Signer: agent-id-abc123
  Algorithm: ring-Ed25519
  Evidence: 1 item(s) verified
    [0] custom: digest OK, freshness OK
  Chain: not present
```

**JSON output (for scripting):**

```bash
jacs attest verify attestation.json --json
```

Output:
```json
{
  "valid": true,
  "crypto": {
    "signature_valid": true,
    "hash_valid": true,
    "signer_id": "agent-id-abc123",
    "algorithm": "ring-Ed25519"
  },
  "evidence": [],
  "chain": null,
  "errors": []
}
```

**Verify with external keys:**

```bash
jacs attest verify attestation.json --key-dir ./trusted_keys/
```

**Pipe through jq:**

```bash
jacs attest verify attestation.json --json | jq '.crypto'
```

## Piping and Scripting Patterns

### Create and verify in one pipeline

```bash
jacs attest create \
  --subject-type artifact \
  --subject-id "doc-001" \
  --subject-digest "abc..." \
  --claims '[{"name": "ok", "value": true}]' \
  -o att.json && \
jacs attest verify att.json --json | jq '.valid'
```

### Check validity in a script

```bash
#!/bin/bash
set -e

RESULT=$(jacs attest verify "$1" --json 2>/dev/null)
VALID=$(echo "$RESULT" | jq -r '.valid')

if [ "$VALID" = "true" ]; then
    echo "Attestation is valid"
    exit 0
else
    echo "Attestation is INVALID"
    echo "$RESULT" | jq '.errors'
    exit 1
fi
```

### Batch verify multiple attestations

```bash
for file in attestations/*.json; do
    echo -n "$file: "
    jacs attest verify "$file" --json | jq -r '.valid'
done
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (create: attestation created; verify: attestation valid) |
| 1 | Failure (create: error creating attestation; verify: attestation invalid or error) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `JACS_PRIVATE_KEY_PASSWORD` | Password for the agent's private key |
| `JACS_MAX_DERIVATION_DEPTH` | Override maximum derivation chain depth (default: 10) |
| `JACS_DATA_DIRECTORY` | Directory for JACS data files |
| `JACS_KEY_DIRECTORY` | Directory containing keys |
| `JACS_AGENT_ID_AND_VERSION` | Agent identity for signing |

## See Also

- [Sign vs. Attest Decision Guide](../guides/sign-vs-attest.md)
- [Attestation Tutorial](../guides/attestation-tutorial.md)
- [Attestation Verification Results](attestation-errors.md)
- [CLI Command Reference](cli-commands.md)
