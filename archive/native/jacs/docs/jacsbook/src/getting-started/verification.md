# Verifying Signed Documents

Verify a JACS-signed document in under 2 minutes. Verification checks that the document has not changed and was signed by the key selected under your trust policy. A signature alone does not establish a real-world identity or permission to act.

**Verification does NOT require creating an agent.** You need the signed document and independently trusted public evidence for its signer.

Raw JSON is decoded strictly before signing, canonicalization, or verification.
Duplicate object names are rejected at every nesting level, including names
that become equal after JSON escape decoding (for example, `agentID` and
`agent\u0049D`). This prevents two consumers from interpreting the same signed
bytes with different first-key/last-key rules. Repeated values in arrays are
ordinary JSON and remain supported.

## Strict vs permissive verification

`verify-text` and `verify-image` use a **permissive default**: a missing signature is a *typed status*, not an error. Strict mode opts in to error-on-missing. The choice maps onto every binding the same way.

| Surface | Permissive (default) | Strict (`--strict` / `strict=True` / `{ strict: true }` / `Strict: true`) |
|---------|---------------------|---------------------------------------------------------------------------|
| `jacs-compat verify-text` (CLI) | Exit `0` valid · `2` missing-sig · `1` invalid | Exit `0` valid · `1` missing OR invalid (stderr: `no JACS signature found`) |
| `jacs-compat verify-image` (CLI) | Same as above | Same as above |
| Python (`jacs.verify_text`, `jacs.verify_image`) | Returns result with `status == "missing_signature"` | Raises `MissingSignatureError` |
| Node (`jacs.verifyText`, `jacs.verifyImage`) | Returns result with `status === "missing_signature"` | Promise rejects with `MissingSignature`-bearing message |
| Go (`jacs.VerifyText`, `jacs.VerifyImage`) | Returns `Status == "missing_signature"` | Returns error matching `errors.Is(err, jacs.ErrMissingSignature)` |
| Rust (`jacs::simple::advanced`) | Successful result with a missing-signature variant/status | `Err(JacsError::MissingSignature)` |

Pre-existing verify surfaces (`jacs-compat verify`, `jacs-compat document verify`, `jacs.verify`) are unaffected — they keep their existing exit codes and return shapes.

For hands-on examples see [Inline Text Signatures](../guides/inline-text-signing.md) and [Image and Media Signatures](../guides/media-signing.md).

## Portable CLI

```bash
cargo install jacs-cli --locked
jacs verify --public-identity trusted-public-identity.json --input signed-document.json
```

Obtain `trusted-public-identity.json` independently of the untrusted document.
The portable CLI uses explicit `--input` and `--public-identity` arguments;
it does not use the native config or remote/key-directory options below.

Install `cargo install jacs-cli-compat --locked` for the extended native commands.

## CLI: `jacs-compat verify`

The fastest way to verify a document from the command line. No config file, no agent setup.

```bash
# Verify a local file
jacs-compat verify signed-document.json

# Verify with JSON output (for scripting)
jacs-compat verify signed-document.json --json

# Verify a remote document by URL
jacs-compat verify --remote https://example.com/signed-doc.json

# Specify a directory containing public keys
jacs-compat verify signed-document.json --key-dir ./trusted-keys/
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
if jacs-compat verify artifact.json --json; then
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

## DNS Verification

DNS verification checks that an agent's public key hash matches a DNS TXT record published at `_v1.agent.jacs.<domain>`. This provides a decentralized trust anchor: anyone can look up the agent's expected key fingerprint via DNS without contacting a central server.

### Publishing a DNS record

```bash
jacs-compat agent dns --domain example.com --provider plain
```

This outputs the TXT record to add to your DNS zone. Provider options: `plain`, `aws`, `azure`, `cloudflare`.

### Looking up an agent by domain

```bash
jacs-compat agent lookup example.com
```

This inspection command fetches and prints `https://example.com/.well-known/jacs-pubkey.json` and the DNS TXT record at `_v1.agent.jacs.example.com`. It does not compare the fetched key against the TXT fingerprint or establish trust. Use the verification APIs and an independently selected key for that decision.

### CLI verification with DNS

```bash
# Require DNS validation (fail if no DNS record)
jacs-compat agent verify --require-dns

# Require strict DNSSEC validation
jacs-compat agent verify --require-strict-dns
```

For full DNS setup instructions, see [DNS-Based Verification](../rust/dns.md) and [DNS Trust Anchoring](../advanced/dns-trust.md).

## Cross-Language Verification

JACS signatures are language-agnostic. A document signed by a Rust agent verifies identically in Python and Node.js, and vice versa. This holds for both Ed25519 and post-quantum (ML-DSA-87/pq2025) algorithms.

Legacy-v1 signatures that lack `signatureContentVersion` are denied by default
because their signer, timestamp, nonce, and algorithm metadata was never covered
by the signature. Use the migration API to re-sign them as v2. For a narrowly
audited archive workflow, `JACS_ALLOW_LEGACY_SIGNATURE_CONTENT=true` enables
payload-only compatibility; verification results deliberately leave signer,
agent-version, and timestamp fields empty. Do not use that mode for
authorization or identity attribution. The historical
`JACS_REJECT_LEGACY_SIGNATURE_CONTENT=true` setting remains supported and
takes precedence.

This is tested on every commit: current v2 fixtures verify by default across
bindings, while committed v1 fixtures prove both default rejection and explicit
payload-only compatibility. Each binding also countersigns the fixture with a
different algorithm, proving round-trip interoperability.

Test sources:
- Rust fixture generator: `jacs/tests/cross_language/mod.rs`
- Python consumer: `jacspy/tests/test_cross_language.py`
- Node.js consumer: `jacsnpm/test/cross-language.test.js`

## Key Resolution Order

Native document verification uses `JACS_KEY_RESOLUTION` (environment only),
defaulting to `local,registry`. Local storage supplies cached/trusted public
keys; registry lookup requires the relevant network policy. DNS does not fetch
historical public keys: its TXT record anchors a fingerprint, and native document
key lookup skips that source. See [DNS verification](../rust/dns.md) and
[trust enrollment](../advanced/trust-store.md).
