# Verifying Signed Documents

Verify a JACS-signed document in under 2 minutes. Verification confirms two things: the document was signed by the claimed agent, and the content has not been modified since signing.

**Verification does NOT require creating an agent.** You only need the signed document (and optionally access to the signer's public key).

## CLI: `jacs verify`

The fastest way to verify a document from the command line. No config file, no agent setup.

```bash
# Verify a local file
jacs verify signed-document.json

# Verify with JSON output (for scripting)
jacs verify signed-document.json --json

# Verify a remote document by URL
jacs verify --remote https://example.com/signed-doc.json

# Specify a directory containing public keys
jacs verify signed-document.json --key-dir ./trusted-keys/
```

Output on success:

```
Status:    VALID
Signer:    550e8400-e29b-41d4-a716-446655440000
Signed at: 2026-02-10T12:00:00Z
```

JSON output (`--json`):

```json
{
  "valid": true,
  "signerId": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-10T12:00:00Z"
}
```

The exit code is `0` for valid, `1` for invalid or error. Use this in CI/CD pipelines:

```bash
if jacs verify artifact.json --json; then
  echo "Artifact is authentic"
else
  echo "Verification failed" >&2
  exit 1
fi
```

If a `jacs.config.json` and agent keys exist in the current directory, the CLI uses them automatically. Otherwise, it creates a temporary ephemeral verifier internally.

## Python

### With an agent loaded

```python
import jacs.simple as jacs

jacs.load("./jacs.config.json")

result = jacs.verify(signed_json)
if result.valid:
    print(f"Signed by: {result.signer_id}")
else:
    print(f"Errors: {result.errors}")
```

### Without an agent (standalone)

```python
import jacs.simple as jacs

result = jacs.verify_standalone(
    signed_json,
    key_resolution="local",
    key_directory="./trusted-keys/"
)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

`verify_standalone` does not use a global agent. Pass the key resolution strategy and directories explicitly.

### Verify by document ID

If the document is in local storage and you know its ID:

```python
result = jacs.verify_by_id("550e8400-e29b-41d4:1")
```

## Node.js

### With an agent loaded

```typescript
import * as jacs from '@hai.ai/jacs/simple';

await jacs.load('./jacs.config.json');

const result = await jacs.verify(signedJson);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

### Without an agent (standalone)

```typescript
import { verifyStandalone } from '@hai.ai/jacs/simple';

const result = verifyStandalone(signedJson, {
  keyResolution: 'local',
  keyDirectory: './trusted-keys/',
});
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

### Verify by document ID

```typescript
const result = await jacs.verifyById('550e8400-e29b-41d4:1');
```

## Verification Links

Generate a URL that lets anyone verify a signed document through a web verifier (e.g., hai.ai):

**Python:**

```python
url = jacs.generate_verify_link(signed_doc.raw_json)
# https://hai.ai/jacs/verify?s=<base64url-encoded-document>
```

**Node.js:**

```typescript
const url = jacs.generateVerifyLink(signed.raw);
```

The document is base64url-encoded into the URL query parameter. Documents must be under ~1.5 KB to fit within the 2048-character URL limit. For larger documents, share the file directly and verify with the CLI or SDK.

## DNS Verification

DNS verification checks that an agent's public key hash matches a DNS TXT record published at `_v1.agent.jacs.<domain>`. This provides a decentralized trust anchor: anyone can look up the agent's expected key fingerprint via DNS without contacting a central server.

### Publishing a DNS record

```bash
jacs agent dns --domain example.com --provider plain
```

This outputs the TXT record to add to your DNS zone. Provider options: `plain`, `aws`, `azure`, `cloudflare`.

### Looking up an agent by domain

```bash
jacs agent lookup example.com
```

This fetches the agent's public key from `https://example.com/.well-known/jacs-pubkey.json` and checks the DNS TXT record at `_v1.agent.jacs.example.com`.

### CLI verification with DNS

```bash
# Require DNS validation (fail if no DNS record)
jacs agent verify --require-dns

# Require strict DNSSEC validation
jacs agent verify --require-strict-dns
```

For full DNS setup instructions, see [DNS-Based Verification](../rust/dns.md) and [DNS Trust Anchoring](../advanced/dns-trust.md).

## Cross-Language Verification

JACS signatures are language-agnostic. A document signed by a Rust agent verifies identically in Python and Node.js, and vice versa. This holds for both Ed25519 and post-quantum (ML-DSA-87/pq2025) algorithms.

This is tested on every commit: Rust generates signed fixtures, then Python calls `verify_standalone()` and Node.js calls `verifyStandalone()` to verify them. Each binding also countersigns the fixture with a different algorithm, proving round-trip interoperability.

Test sources:
- Rust fixture generator: `jacs/tests/cross_language/mod.rs`
- Python consumer: `jacspy/tests/test_cross_language.py`
- Node.js consumer: `jacsnpm/test/cross-language.test.js`

## Key Resolution Order

When verifying a document, JACS resolves the signer's public key in a configurable order. Set `JACS_KEY_RESOLUTION` to control this:

| Value | Source |
|-------|--------|
| `local` | Local trust store (added via `trust_agent`) |
| `dns` | DNS TXT record lookup |
| `hai` | HAI key distribution service |

Default: `local,hai`. Example: `JACS_KEY_RESOLUTION=local,dns,hai`.
