# Security Model

JACS implements a comprehensive security model designed to ensure authenticity, integrity, and non-repudiation for all agent communications and documents.

## Security Model (v0.6.0+)

- **Passwords**: The private key password can be provided via `JACS_PRIVATE_KEY_PASSWORD` environment variable, `JACS_PASSWORD_FILE`, or the OS keychain (macOS Keychain / Linux Secret Service). It is never stored in config files.
- **Keys**: Private keys are encrypted at rest (AES-256-GCM with PBKDF2, 600k iterations). Public keys and config may be stored on disk.
- **Path validation**: All paths built from untrusted input (e.g. `publicKeyHash`, filenames) are validated via `require_relative_path_safe()` to prevent directory traversal. This single validation function is used in data and key directory path builders and the trust store. It rejects empty segments, `.`, `..`, null bytes, and Windows drive-prefixed paths.
- **Trust ID canonicalization**: Trust-store operations normalize canonical agent docs (`jacsId` + `jacsVersion`) into a safe `UUID:VERSION_UUID` identifier before filesystem use, preserving path-safety checks while supporting standard agent document layout.
- **Filesystem schema policy**: Local schema loading is disabled by default and requires `JACS_ALLOW_FILESYSTEM_SCHEMAS=true`. When enabled, schema paths must remain within configured roots (`JACS_DATA_DIRECTORY` and/or `JACS_SCHEMA_DIRECTORY`) after normalized/canonical path checks.
- **Network endpoint policy**: Registry verification requires HTTPS for `JACS_REGISTRY_URL` (legacy alias: `HAI_API_URL`). Localhost HTTP is allowed for local testing only.
- **Strict JSON ingress**: Raw JSON crossing a signing, verification, hashing,
  schema, or protocol boundary must pass the shared `jacs-core` strict decoder.
  Duplicate decoded object names are rejected recursively before a
  `serde_json::Value` can collapse them; escape-equivalent names are duplicates,
  while repeated array elements remain valid.
- **No secrets in config**: Config files must not contain passwords or other secrets. The example config (`jacs.config.example.json`) does not include `jacs_private_key_password`.
- **Dependency auditing**: Run `cargo audit` (Rust), `npm audit` (Node.js), or `pip audit` (Python) to check for known vulnerabilities.

## Core Security Principles

### 1. Cryptographic Identity

Every JACS agent has a unique cryptographic identity:

- **Key Pair**: Each agent possesses a private/public key pair
- **Agent ID**: Unique UUID identifying the agent
- **Public Key Hash**: SHA-256 hash of the public key for verification

```json
{
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "publicKeyHash": "sha256-of-public-key",
    "signingAlgorithm": "pq2025"
  }
}
```

Native signing defaults to post-quantum `pq2025` (ML-DSA-87 / FIPS-204).
Explicit `ed25519` creation is supported and emits the canonical
`ring-Ed25519` label. Routine rotation preserves the current algorithm;
Ed25519 can explicitly upgrade to `pq2025`, while PQ-to-Ed25519 downgrade is rejected.

### 2. Document Integrity

All documents include cryptographic guarantees:

- **Signature**: Cryptographic signature over specified fields
- **Hash**: SHA-256 hash of document contents
- **Version Tracking**: Immutable version history

### 3. Non-Repudiation

Signatures provide proof of origin:

- Agents cannot deny signing a document
- Timestamps record when signatures were made
- Public keys enable independent verification

## Security Audit (`audit()`)

JACS provides a read-only **security audit** that checks configuration, directories, secrets, trust store, storage, quarantine/failed files, and optionally re-verifies recent documents. It does not modify state.

**Purpose**: Surface misconfiguration, missing keys, unexpected paths, and verification failures in one report.

**Options** (all optional):

- `config_path`: Path to `jacs.config.json` (default: 12-factor load)
- `data_directory` / `key_directory`: Override paths
- `recent_verify_count`: Number of recent documents to re-verify (default 10, max 100)

**Return structure**: `AuditResult` with `overall_status`, `risks` (list of `AuditRisk`), `health_checks` (list of `ComponentHealth`), `summary`, `checked_at`, and optional `quarantine_entries` / `failed_entries`.

**Rust**:

```rust
use jacs::audit::{audit, AuditOptions};

let result = audit(AuditOptions::default())?;
println!("{}", jacs::format_audit_report(&result));
```

**Python**:

```python
import jacs.simple as jacs

result = jacs.audit()  # dict with risks, health_checks, summary, overall_status
print(f"Risks: {len(result['risks'])}, Status: {result['overall_status']}")
```

**Node.js**:

```typescript
import * as jacs from '@hai.ai/jacs/simple';

const result = jacs.audit({ recentN: 5 });
console.log(`Risks: ${result.risks.length}, Status: ${result.overall_status}`);
```

Available in the language bindings for local diagnostics and automation.

## Threat Model

### Protected Against

| Threat | Protection |
|--------|------------|
| **Tampering** | Content hashes detect modifications |
| **Impersonation** | Cryptographic signatures verify identity |
| **Replay Attacks** | HTTP/RPC payload and W3C request proofs use timestamp validation plus atomic nonce consumption; document signatures remain durable by design |
| **Man-in-the-Middle** | DNS verification via DNSSEC; TLS certificate validation |
| **Key Compromise** | Key rotation through versioning |
| **Weak Passwords** | Minimum 28-bit entropy enforcement (35-bit for single class) |

### Trust Assumptions

1. Private keys are kept secure
2. Cryptographic algorithms are sound
3. DNS infrastructure (when used) is trustworthy

### Replay Store Deployment

The default replay backend is a bounded, atomic, process-local Moka cache. It
accepts exactly one concurrent use of a nonce within one process and is suitable
for local development or a genuinely single-process service.

Multi-replica production services must install an implementation of the Rust
`ReplayStore` trait backed by a shared atomic primitive (for example Redis
`SET key value NX EX ttl` or a database unique insert), then set
`JACS_REQUIRE_SHARED_REPLAY_STORE=true`. With that setting JACS fails closed
if the installed backend reports itself as process-local or returns an error.
The library never silently falls back to memory after a shared-store failure.

Replay decisions emit structured events without nonce contents and increment
`jacs_replay_checks_total{backend,outcome}`. Use
`JACS_PAYLOAD_MAX_REPLAY_SECONDS` to configure the default payload window. For
an accepted future-skewed payload, JACS retains its nonce through the signed
timestamp plus that window, not merely for a fixed interval from verification.

### Remote JWKS Retrieval

A2A Agent Card verification keeps JWKS network access disabled unless
`JACS_ALLOW_JWKS_FETCH=true` (or the broader `JACS_ALLOW_NETWORK=true`) is set.
Even after that opt-in, JACS accepts only HTTPS origins, resolves and validates
every redirect hop, rejects private/reserved IP answers, pins the validated DNS
answer into the HTTP client, disables proxy resolution, allows at most three
same-origin redirects, and requires a JSON Content-Type. The whole operation is
limited to five seconds and 256 KiB.

Loopback HTTP remains available for deliberate local development only when
both the network capability and `JACS_ALLOW_PRIVATE_JWKS=true` are set. Do not
enable the private-JWKS override in a service that assesses Agent Cards supplied
by untrusted callers.

### Request-Bound HTTP Authorization

Use the request builder exposed by your API with the actual HTTP method,
absolute URL, exact body bytes (empty bytes for no body), and a
service-specific audience:

| API | Request-bound builder |
|-----|-----------------------|
| Rust `SimpleAgent` | `build_request_auth_header(method, url, body, audience)` |
| Python `SimpleAgent` | `build_request_auth_header(method, url, body, audience)` |
| Node `JacsSimpleAgent` | `buildRequestAuthHeader(method, url, body, audience)` |
| Go `JacsSimpleAgent` | `BuildRequestAuthHeader(method, url, body, audience)` |

The resulting `JACS v2...` header authenticates the signer/key ID, normalized
scheme/authority/path/query, SHA-256 content digest, audience, timestamp, and
nonce. `verify_request_auth_header` requires the trusted key and the actual
request context; any method, endpoint, query, body, signer, or audience
substitution fails before replay state is consumed.

Build the header after the final body serialization and send those same bytes.
On verification, reconstruct the absolute URL from trusted server/framework
configuration rather than trusting an attacker-controlled forwarding header.
The standard Rust verifier atomically consumes replay state after all other
checks pass. Servers with an application-owned shared store use
`verify_request_auth_header_with_trusted_key_without_replay`, then grant access
only if an atomic insert such as Redis `SET ... NX EX ...` accepts the returned
nonce. Use `request_auth_replay_ttl(&verified_claims, max_age)` for the Redis
expiry (or retain it longer). A fixed `max_age` TTL is insufficient when the
signer's accepted clock skew is positive: the credential's absolute expiry is
`issued_at + max_age`.

The older no-argument Rust `build_auth_header` and equivalent legacy class
methods sign only identity, time, and nonce. They remain available for source
compatibility and emit a WARN because a first-use credential could be moved to
a different request. The additive request-bound methods require method, URL,
body, and audience and emit v2. Strict deployments can reject legacy
construction with `JACS_REJECT_UNBOUND_AUTH_HEADER=true`.

### Encrypted-Key KDF Resource Policy

V2 private-key envelopes accept only the versioned Argon2id resource profile:
8,192–19,456 KiB memory, one or two passes, and parallelism one. JACS validates
these values before base64 allocation or Argon2 execution, and also caps the
serialized envelope/ciphertext and enforces exact salt/nonce sizes. A policy
rejection emits `encrypted_key_kdf_policy_rejected` at WARN and increments
`jacs_kdf_policy_rejections_total{kdf="Argon2id",profile="v2"}`; neither signal
contains passwords, key bytes, or ciphertext.

### Signed Response and Event Contract

`sign_response` emits response envelope version `2.0.0` with signature scope
`jacs-response-v2`. Its domain-separated signature authenticates the complete
envelope except for the signature bytes themselves: payload, protocol
version/type, issuer, document ID, payload hash, timestamp, signer, algorithm,
public-key hash, and any additional fields. This is a protocol-specific
contract; do not replace it with generic document verification or verification
of `data` alone.

Use `verify_response_json_with_key` in Rust or `unwrap_signed_event` /
`unwrapSignedEvent` in a native binding with a trusted map from signer ID to
public key. Trusted keys may be raw bytes/base64 or canonical PEM, depending on
the binding. On success the bindings return only verified data plus provenance:

```json
{
  "data": {"decision": "allow"},
  "verified": true,
  "status": "verified",
  "signerId": "agent-id:version",
  "timestamp": "2026-07-09T12:00:00Z",
  "algorithm": "pq2025",
  "documentId": "2f1e2bdb-55f4-4c99-8f42-d45249808f4b"
}
```

Plain events, legacy payload-only response envelopes, unknown signers, and
invalid signatures are errors. There is no successful `verified: false` result;
callers must never dispatch an event by catching that error and reparsing its
untrusted input.

These protocols authenticate control of the private key corresponding to the
public key that the verifier selected. Signed `agentID`, name, domain, and time
fields are not independent proof of a person, organization, service, or DNS
identity. Establish that association through a pinned key, strict local trust
configuration, or another explicitly chosen verification policy before making
an authorization decision.

## Signature Process

### Signing a Document

1. **Field Selection**: Determine which fields to sign
2. **Canonicalization**: Serialize fields deterministically
3. **Signature Generation**: Sign with private key
4. **Hash Computation**: Compute SHA-256 of signed document

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create signed document
doc = agent.create_document(json.dumps({
    'title': 'Confidential Report',
    'content': 'Sensitive data here'
}))

# Document now includes jacsSignature and jacsSha256
```

### Verifying a Document

1. **Hash Verification**: Recompute hash and compare
2. **Signature Verification**: Verify signature with public key
3. **Agent Verification**: Optionally verify agent identity via DNS

```python
is_valid = agent.verify_document(doc_json)
is_signature_valid = agent.verify_signature(doc_json)
```

## Key Management

### Compatibility key binding (P2)

An agent's ES256 `ecosystem_signing` key is authorized per-export by a
**compatibility key binding**: a `compatibilityKeyBinding` JACS document
signed by the **current native root**, persisted as one canonical-JSON file
(`jacs_keys/jacs.compat-binding.json`). Lifecycle rules:

- granting or widening a scope always requires the native root's signature —
  the ES256 holder cannot self-escalate;
- re-issue replaces the file (latest `issuedAt` wins; no version chains);
- native key rotation supersedes the binding — verification fails with a
  "re-issue" error until a new binding is signed by the current root;
- an expired binding denies export; `expiresAt: null` is permitted in P2;
- default issuance grants only the identity scopes (`jwks`, `did`,
  `a2a-agent-card`, `w3c-agent-identity`); content scopes (`ap2-mandate`,
  `agreement-vc`) require an explicit re-issue.

Be precise about what this is: scope checks are a **locally enforced
authorization policy** and an auditable delegation record for relying
parties — not isolation. Both private keys live in the same directory
under the same password; a compromised host is outside this model. The
sound property is non-self-escalation via the native-root signature requirement.

The ES256 private key is encrypted at rest with the same AES-256-GCM +
Argon2id envelope as the native root key — the post-quantum library is a
signing primitive, not an encryption primitive, so compatibility keys
reuse the existing audited envelope rather than inventing a PQ-encrypted
key format.

### Targeted content exports (P2)

Content exporters (the AP2 mandate export, the Agreement-v2-as-VC
export) sign **ecosystem artifacts** with the ES256 compatibility key
through purpose-built, schema-pinned paths — there is no generic
"sign this document with algorithm X" API. Two properties matter here:

- **Classical verification is not PQ trust.** A stock JOSE/Data
  Integrity verifier can check the ES256 signature with nothing but the
  public key; that proves possession of the compatibility key, not the
  agent's native identity. Tracing the export to that root additionally
  requires verifying the native-root-signed compatibility key
  binding (`jacs agent export-compat-binding`).
- **Native documents are never mutated.** Exports are derived views;
  the native `jacsSignature` keeps the agent's selected algorithm and the source document's
  bytes and verification are unchanged after every export. These are
  targeted ecosystem artifacts, not JACS projections — native documents
  never gain `proof` or other projection fields.

Exports are one-way in P2: JACS emits these artifacts, but verifying
incoming AP2 mandates or third-party VCs is out of scope — use the
target ecosystem's stock verifiers for that.

### Key Generation

JACS generates cryptographic key pairs during agent creation:

```bash
# Keys are created in the configured key directory
jacs_keys/
├── private.pem    # Private key (keep secure!)
└── public.pem     # Public key (can be shared)
```

### Key Protection

**Encryption at Rest**:

Private keys are encrypted using AES-256-GCM with a key derived via PBKDF2-HMAC-SHA256 (600,000 iterations). Never store the password in config files.

```bash
# Option 1: Environment variable (recommended for CI/servers)
export JACS_PRIVATE_KEY_PASSWORD="secure-password"

# Option 2: OS keychain (recommended for developer workstations)
jacs keychain set --agent-id <YOUR_AGENT_UUID>
```

> **Important**: The CLI can prompt for the password during `jacs init`, but scripts and servers must set `JACS_PRIVATE_KEY_PASSWORD` as an environment variable or use the OS keychain.

**OS Keychain Integration**:

On macOS and Linux desktops, JACS can store and retrieve the private key password from the OS credential store, eliminating the need for environment variables or plaintext password files during day-to-day development:

- **macOS**: Uses Security.framework (Keychain Access)
- **Linux**: Uses the freedesktop.org D-Bus Secret Service API (GNOME Keyring, KDE Wallet, KeePassXC)

Each password is keyed by agent ID, so multiple agents can coexist on the same machine without overwriting each other. Store your password once with `jacs keychain set --agent-id <ID>`, and all subsequent JACS operations will find it automatically. The password resolution order is:

1. `JACS_PRIVATE_KEY_PASSWORD` env var (highest priority -- explicit always wins)
2. `JACS_PASSWORD_FILE` / legacy `.jacs_password` file
3. OS keychain keyed by agent ID (lowest priority among explicit sources)

To disable keychain lookups (recommended for CI and headless environments):

```bash
export JACS_KEYCHAIN_BACKEND=disabled
```

Or in `jacs.config.json`:

```json
{
  "jacs_keychain_backend": "disabled"
}
```

The keychain stores the password under service name `jacs-private-key` with user `default`. Multiple agents on one machine can use agent-specific passwords via the `*_for_agent()` API variants.

> **Security note**: The OS keychain is encrypted at rest by the OS and unlocked by the user's login session. It is the same mechanism used by `git`, `ssh-agent`, `docker`, and other CLI tools. The `keychain` feature is optional and not compiled into the `jacs` core crate by default -- it is enabled by default only in `jacs-cli`.

**Password Entropy Requirements**:

JACS enforces password entropy minimums for private key encryption. Password validation is performed at encryption time, and weak passwords are rejected with helpful error messages:

- Minimum **28-bit entropy** for passwords with 2+ character classes (mixed case, numbers, symbols)
- Minimum **35-bit entropy** for single-character-class passwords (e.g., all lowercase)
- Entropy is calculated based on character class diversity and length
- Weak passwords result in immediate rejection during key encryption
- Error messages guide users toward stronger password choices

Example of rejected weak passwords:
- `password` - Too common and predictable
- `12345678` - Insufficient character diversity
- `abc` - Too short

**File Permissions**:

```bash
chmod 700 ./jacs_keys
chmod 600 ./jacs_keys/private.pem
```

### Key Rotation

Update agent version to rotate keys:

1. Generate new key pair
2. Create new agent version
3. Sign new version with old key
4. Update configuration to use new keys

Every rotation resolves to `pq2025`, including rotation of an
Ed25519 agent — rotation is the designated
Ed25519 → post-quantum migration path. Rotation also supersedes the
ES256 compatibility key binding: re-issue it under the new native root
(`jacs agent issue-compat-binding`) before the next ecosystem export.

## TLS Certificate Validation

JACS includes configurable TLS certificate validation for secure network communication.

### Default Behavior (Development)

By default, JACS warns about invalid TLS certificates but accepts them to facilitate development environments with self-signed certificates:

```
WARNING: Invalid TLS certificate detected. Set JACS_STRICT_TLS=true for production.
```

### Production Configuration

For production deployments, enable strict TLS validation:

```bash
export JACS_STRICT_TLS=true
```

When enabled, JACS will:
- Reject connections with invalid, expired, or self-signed certificates
- Enforce proper certificate chain validation
- Fail fast with clear error messages for certificate issues

**Implementation**: Certificate validation logic is located in `jacs/src/schema/utils.rs`.

### Security Implications

| Mode | Behavior | Use Case |
|------|----------|----------|
| Default (dev) | Warn on invalid certs, allow connection | Local development, testing |
| Strict (`JACS_STRICT_TLS=true`) | Reject invalid certs | Production, staging |

For registry verification endpoints, `JACS_REGISTRY_URL` (legacy `HAI_API_URL`) must use HTTPS. HTTP is only allowed for localhost test endpoints.

## Signature Timestamp Validation

JACS signatures include timestamps to prevent replay attacks and ensure temporal integrity.

### How It Works

1. **Timestamp Inclusion**: Every signature includes a UTC timestamp recording when it was created
2. **Future Timestamp Rejection**: Signatures with timestamps more than 5 minutes in the future are rejected
3. **Optional Signature Expiration**: Configurable via `JACS_MAX_SIGNATURE_AGE_SECONDS` (disabled by default since JACS documents are designed to be eternal)
4. **Validation**: Timestamp validation occurs during signature verification

### Configuring Signature Expiration

By default, signatures do not expire. JACS documents are designed to be idempotent and eternal. For use cases that require expiration:

```bash
# Enable expiration (e.g., 90 days)
export JACS_MAX_SIGNATURE_AGE_SECONDS=7776000

# Default: no expiration (0)
export JACS_MAX_SIGNATURE_AGE_SECONDS=0
```

### Protection Against Replay Attacks

The 5-minute future tolerance window:
- Allows for reasonable clock skew between systems
- Prevents attackers from creating signatures with future timestamps
- Ensures signatures cannot be pre-generated for later fraudulent use

```json
{
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "signature": "...",
    "date": "2024-01-15T10:30:00Z"  // Must be within 5 min of verifier's clock
  }
}
```

### Clock Synchronization

For reliable timestamp validation across distributed systems:
- Ensure all agents use NTP or similar time synchronization
- Monitor for clock drift in production environments
- Consider the 5-minute tolerance when debugging verification failures

## Verification Claims

Agents can claim a verification level that determines security requirements. This follows the principle: **"If you claim it, you must prove it."**

### Claim Levels

| Claim | Required Conditions | Behavior |
|-------|---------------------|----------|
| `unverified` (default) | None | Relaxed DNS/TLS settings allowed; self-asserted identity |
| `verified` | Domain with DNSSEC | Strict TLS, strict DNS with DNSSEC validation required |
| `verified-registry` | Above + registry verification | Must be registered and verified by a JACS registry |
| `verified-hai.ai` (legacy alias) | Same as `verified-registry` | Backward-compatible alias |

### Setting a Verification Claim

Add the `jacsVerificationClaim` field to your agent definition:

```json
{
  "jacsAgentType": "ai",
  "jacsVerificationClaim": "verified",
  "jacsAgentDomain": "myagent.example.com"
}
```

### Claim Enforcement

When an agent claims `verified`, `verified-registry`, or legacy `verified-hai.ai`:

1. **Domain Required**: The `jacsAgentDomain` field must be set
2. **Strict DNS**: DNS lookup uses DNSSEC validation (no insecure fallback)
3. **DNS Required**: Public key fingerprint must match DNS TXT record
4. **Strict TLS**: TLS certificate validation is mandatory (no self-signed certs)

For `verified-registry` (or legacy `verified-hai.ai`) claims, additional enforcement:

5. **Registry Registration**: Agent must be registered with the configured registry (for HAI-hosted registry, [hai.ai](https://hai.ai))
6. **Public Key Match**: Registered public key must match the agent's key
7. **Network Required**: Verification fails if the registry API is unreachable

### Backward Compatibility

- Agents without `jacsVerificationClaim` are treated as `unverified`
- Existing agents continue to work with their current DNS settings
- No breaking changes for agents that don't opt into verified status

### Error Messages

If verification fails, clear error messages explain what's wrong:

```
Verification claim 'verified' failed: Verified agents must have jacsAgentDomain set.
Agents claiming 'verified' must meet the required security conditions.
```

```
Verification claim 'verified-registry' failed: Agent 'uuid' is not registered with the configured registry.
Agents claiming 'verified-registry' must be registered with a reachable registry endpoint.
```

### Security Considerations

1. **No Downgrade**: Once an agent claims `verified`, it cannot be verified with relaxed settings
2. **Claim Changes**: Changing the claim requires creating a new agent version
3. **Network Dependency**: `verified-registry` requires network access to the registry endpoint
4. **Audit Trail**: Verification claim and enforcement results are logged

## DNS-Based Verification

JACS supports DNSSEC-validated identity verification:

### How It Works

1. Agent publishes public key fingerprint in DNS TXT record
2. Verifier queries DNS for `_v1.agent.jacs.<domain>.`
3. DNSSEC validates the response authenticity
4. Fingerprint is compared against agent's public key

### Configuration

```json
{
  "jacs_agent_domain": "myagent.example.com",
  "jacs_dns_validate": true,
  "jacs_dns_strict": true
}
```

### Security Levels

| Mode | Description |
|------|-------------|
| `jacs_dns_validate: false` | No DNS verification |
| `jacs_dns_validate: true` | Attempt DNS verification, allow fallback |
| `jacs_dns_strict: true` | Require DNSSEC validation |
| `jacs_dns_required: true` | Fail if domain not present |

## Trust Store Management

JACS maintains a trust store for managing trusted agent relationships.

### Trusting Agents

Before trusting an agent, JACS performs public key hash verification:

```python
# Trust an agent after verifying their public key hash
agent.trust_agent(agent_id, public_key_hash)
```

### Untrusting Agents

The `untrust_agent()` method properly handles the case when an agent is not in the trust store:

```python
try:
    agent.untrust_agent(agent_id)
except AgentNotTrusted as e:
    # Agent was not in the trust store
    print(f"Agent {agent_id} was not trusted: {e}")
```

### Trust Store Security

| Operation | Validation |
|-----------|------------|
| `trust_agent()` | UUID format validation, path traversal rejection, public key hash verification, self-signature verification before adding |
| `untrust_agent()` | UUID format validation, path containment check, returns `AgentNotTrusted` error if agent not found |
| `get_trusted_agent()` | UUID format validation, path containment check |
| `is_trusted()` | UUID format validation, safe lookup without side effects |
| Key cache (`load_public_key_from_cache`) | `require_relative_path_safe()` rejects traversal in `publicKeyHash` |
| Key cache (`save_public_key_to_cache`) | `require_relative_path_safe()` rejects traversal in `publicKeyHash` |

**Path Traversal Protection (v0.6.0)**: All trust store operations that construct file paths from agent IDs or key hashes use defense-in-depth:
1. **UUID format validation**: Agent IDs must match `UUID:UUID` format (rejects special characters)
2. **Path character rejection**: Explicit rejection of `..`, `/`, `\`, and null bytes
3. **Path containment check**: For existing files, canonicalized paths are verified to stay within the trust store directory
4. **`require_relative_path_safe()`**: Key hashes are validated to prevent traversal before constructing cache file paths

### Best Practices

1. **Verify Before Trust**: Always verify an agent's public key hash through an out-of-band channel before trusting
2. **Audit Trust Changes**: Log all trust store modifications for security auditing
3. **Periodic Review**: Regularly review and prune the trust store

## Agreement Security

Multi-party agreements provide additional security:

### Agreement Structure

```json
{
  "jacsAgreement": {
    "agentIDs": ["agent-1", "agent-2", "agent-3"],
    "signatures": [
      {
        "agentID": "agent-1",
        "signature": "...",
        "responseType": "agree",
        "date": "2024-01-15T10:00:00Z"
      }
    ]
  },
  "jacsAgreementHash": "hash-at-agreement-time"
}
```

### Agreement Guarantees

1. **Content Lock**: `jacsAgreementHash` ensures all parties agreed to same content
2. **Individual Consent**: Each signature records explicit agreement
3. **Response Types**: Support for agree, disagree, or reject
4. **Timestamp**: Records when each party signed

## Request/Response Security

For HTTP, use the [request-bound authorization](#request-bound-http-authorization)
and [signed response/event](#signed-response-and-event-contract) contracts
above. Generic document signing does not bind an HTTP method, URL, audience, or
request body, and generic verification of only the response payload does not
authenticate the v2 envelope metadata.

MCP messages that need portable artifact integrity can carry ordinary signed
JACS documents. That is separate from HTTP request authentication: the MCP
stdio transport has no HTTP target to bind, and authorization remains the MCP
host's responsibility.

## Algorithm Security

### Supported Algorithms

| Algorithm | Type | Role |
|-----------|------|------|
| `pq2025` | Post-Quantum (FIPS-204 ML-DSA-87) | Default native root; every rotation resolves to it |
| `ring-Ed25519` | Elliptic Curve | Supported native creation, signing, and verification; user-facing input alias: `ed25519` |
| ES256 | Elliptic Curve (P-256) | Compatibility key for targeted ecosystem exports only — never a valid native `jacsSignature` algorithm |

### Algorithm Selection

Native JACS signing defaults to `pq2025`; explicit Ed25519 creation is
supported without substitution. Rotation always converges to `pq2025`.

An ES256 content signature does **not** create native JACS trust:
classical verification proves possession of the compatibility key only.
The native-root-signed compatibility key binding is what ties that key to
the agent — see [Compatibility key binding (P2)](#compatibility-key-binding-p2).

## Security Best Practices

### 1. Key Storage

```bash
# Never commit keys to version control
echo "jacs_keys/" >> .gitignore

# Secure file permissions
chmod 700 ./jacs_keys
chmod 600 ./jacs_keys/private.pem
```

### 2. Password Handling

```bash
# Option A: Use environment variables (CI, servers)
export JACS_PRIVATE_KEY_PASSWORD="$(pass show jacs/key-password)"

# Option B: Use OS keychain (developer workstations)
jacs keychain set --agent-id <AGENT_UUID>  # stores password securely in OS credential store

# Option C: Disable keychain for headless/CI environments
export JACS_KEYCHAIN_BACKEND=disabled
```

### 3. Transport Security

Always use TLS for network communication:

```python
# HTTPS for web transport
client = JACSMCPClient(
    "https://localhost:8000/sse",
    expected_peer_agent_id="SERVER_AGENT_ID",
)  # TLS plus an explicit signer pin
# Plain HTTP remains loopback-only and should not be exposed remotely.
```

### 4. Verification Policies

```json
{
  "jacs_dns_strict": true,
  "jacs_dns_required": true,
  "jacs_enable_filesystem_quarantine": "true"
}
```

### 5. Audit Logging

Enable observability for security auditing:

```json
{
  "observability": {
    "logs": {
      "enabled": true,
      "level": "info"
    }
  }
}
```

## Security Checklist

### Development

- [ ] Generate unique keys for each environment
- [ ] Never commit private keys
- [ ] Use test keys separate from production

### Production

- [ ] Encrypt private keys at rest
- [ ] Use environment variables or OS keychain for secrets (never store `jacs_private_key_password` in config)
- [ ] Set `JACS_KEYCHAIN_BACKEND=disabled` on CI/headless servers
- [ ] Enable DNS verification
- [ ] Configure strict security mode
- [ ] Enable audit logging
- [ ] Use TLS for all network transport
- [ ] Restrict key file permissions (0600 for keys, 0700 for key directory)
- [ ] Implement key rotation policy
- [ ] Set `JACS_STRICT_TLS=true` for certificate validation
- [ ] Use strong passwords (28+ bit entropy, 35+ for single character class)
- [ ] Enable signature timestamp validation
- [ ] Verify public key hashes before trusting agents
- [ ] Run `cargo audit` / `npm audit` / `pip audit` regularly for dependency vulnerabilities

### Verification

- [ ] Always verify documents before trusting
- [ ] Verify agent signatures
- [ ] Check agreement completeness
- [ ] Validate DNS records when required

## Security Considerations

### Supply Chain

- Verify JACS packages are from official sources
- Use package checksums
- Keep dependencies updated

### Side Channels

- Use constant-time comparison for signatures
- Protect against timing attacks
- Secure memory handling for keys

### Recovery

- Backup key material securely
- Document key recovery procedures
- Plan for key compromise scenarios

## Troubleshooting Verification Claims

### Common Issues and Solutions

#### "Verified agents must have jacsAgentDomain set"

**Problem**: You set `jacsVerificationClaim` to `verified` but didn't specify a domain.

**Solution**: Either add a domain or use unverified:

```json
// Option 1: Add a domain (recommended for production)
{
  "jacsVerificationClaim": "verified",
  "jacsAgentDomain": "myagent.example.com"
}

// Option 2: Use unverified if DNS verification isn't needed
{
  "jacsVerificationClaim": "unverified"
}
```

#### "Agent is not registered with the registry"

**Problem**: You're using `verified-registry` (or legacy `verified-hai.ai`) but the agent isn't registered.

**Solution**:
1. Register your agent with your configured registry (for HAI-hosted registry, [hai.ai](https://hai.ai))
2. Or use `verified` for DNS-only verification:

```json
{
  "jacsVerificationClaim": "verified",
  "jacsAgentDomain": "myagent.example.com"
}
```

#### "Cannot downgrade from 'verified' to 'unverified'"

**Problem**: You're trying to change an existing agent's claim to a lower level.

**Solution**: Verification claims cannot be downgraded for security. Options:
1. Keep the current claim level
2. Create a new agent with the desired claim level
3. If this is a test/development scenario, start fresh

```bash
# Create a new agent instead
jacs quickstart --name replacement-agent --domain replacement.example.com
```

#### "DNS fingerprint mismatch"

**Problem**: The public key hash in DNS doesn't match your agent's key.

**Solution**:
1. Regenerate the DNS record with your current keys:
   ```bash
   jacs dns-record
   ```
2. Update your DNS TXT record with the new value
3. Wait for DNS propagation (can take up to 48 hours)

#### "Strict DNSSEC validation failed"

**Problem**: Your domain doesn't have DNSSEC enabled.

**Solution**:
1. Enable DNSSEC with your domain registrar
2. Publish DS records at the parent zone
3. Or use `verified` with non-strict DNS (development only)

### Claim Level Reference

| Claim | Security Level | Requirements |
|-------|----------------|--------------|
| `unverified` | 0 (lowest) | None - self-asserted identity |
| `verified` | 1 | Domain + DNS TXT record + DNSSEC |
| `verified-registry` | 2 (highest) | Above + registry registration |
| `verified-hai.ai` (legacy alias) | 2 (highest) | Alias of `verified-registry` |

### Upgrade vs Downgrade Rules

- **Upgrades allowed**: `unverified` → `verified` → `verified-registry` (legacy alias `verified-hai.ai` is same level)
- **Downgrades blocked**: Cannot go from higher to lower claim
- **Same level allowed**: Can update agent while keeping same claim

### Quick Diagnostic Commands

```bash
# Check your agent's current claim
jacs info | grep jacsVerificationClaim

# Verify DNS record is correct
jacs dns-check

# Test verification
jacs verify --agent your-agent-id:version
```

## See Also

- [Cryptographic Algorithms](crypto.md) - Algorithm details
- [DNS Verification](../dns.md) - DNS-based identity
- [Configuration](../schemas/configuration.md) - Security configuration
- [Agreements](../rust/agreements.md) - Multi-party agreements
