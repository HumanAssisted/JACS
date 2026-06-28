# P2 - PQ-Root Agent Identity + ES256 Ecosystem Compatibility

**Status:** Ready for user approval before `/execute`  
**Updated:** 2026-06-28  
**Scope owner:** JACS core, bindings, CLI, MCP

## 1. Purpose

JACS is a portable signing and verification library. Its native trust primitive is a verifiable JSON document with canonical JSON bytes, schema-declared structure, content hash, signer identity, signing algorithm, and cryptographic signature.

This P2 makes JACS compatible with ecosystems that expect ES256, JWKS, DID documents, A2A agent cards, and W3C-style identity documents without making ES256 part of the native JACS signing contract.

The design is:

1. New native JACS signatures are always PQ (`pq2025` / ML-DSA-87).
2. `jacs init` creates a PQ root key for the agent identity.
3. `jacs init` also creates an ES256 compatibility key for ecosystems that require classical P-256 signatures.
4. The ES256 private key is stored with the existing JACS encrypted-at-rest key storage path, not encrypted by ML-DSA.
5. JACS signs and verifies JACS documents with native `jacsSignature`.
6. JACS exports ecosystem identity documents with the ES256 compatibility key, plus a PQ-signed binding document that says this ES256 key belongs to this JACS agent.

In short: JACS remains PQ-rooted. ES256 is a compatibility credential, not a second native JACS identity.

## 2. Why This Exists

The current draft plan muddles two different jobs:

- Native JACS verification: durable, portable, PQ-first verification between JACS implementations.
- Ecosystem compatibility: exporting documents that other systems already know how to parse and verify.

Making ES256 a native `SigningAlgorithm` and adding generic projections to every JACS document would blur the core product. It would also add a large public surface: arbitrary-document JWS, Data Integrity proofs, DSSE, multi-proof verification, and native `ring-ES256` schema support.

The revised plan keeps the core simple:

- JACS answers "is this JACS document authentic?" with one native PQ signature.
- Compatibility exports answer "can this larger ecosystem recognize this agent?" with ES256 documents that are explicitly bound to the JACS PQ root.

## 3. Goals

- **G1. PQ-only native signing for new documents.** New JACS signatures use `pq2025`; native ES256 signing is out of scope.
- **G2. Rooted compatibility identity.** A JACS agent has a PQ root key and an ES256 compatibility key with explicit roles.
- **G3. PQ-signed compatibility key binding.** The ES256 public key is bound to the JACS agent id by a native JACS-signed document.
- **G4. Standard ecosystem exports.** JACS can export the ES256 key as JWKS/DID/A2A/W3C-compatible identity material where those formats require classical signatures.
- **G5. Minimal public surface.** Add only the CLI/SDK/MCP functions needed to create, inspect, and export the compatibility identity.
- **G6. Legacy verification remains.** Existing Ed25519 or older documents can still be verified where JACS already supports them, but new signing is PQ-only.

## 4. Non-Goals

- **NG1. No native ES256 `SigningAlgorithm`.** Do not add `SigningAlgorithm::Es256`, native `ring-ES256`, or ES256 to the `jacsSignature` schema enum.
- **NG2. No configurable native signing algorithm for new signatures.** New native JACS signing does not let callers choose Ed25519 or ES256.
- **NG3. No `jacsProjections` field on native JACS documents.** Compatibility proofs live in exported ecosystem documents or the separate compatibility binding document.
- **NG4. No generic arbitrary-document JWS.** P2 does not add `sign_jws(document, algorithm)` or `verify_jws(...)` for all JACS documents.
- **NG5. No generic W3C Data Integrity projection for every JACS document.** P2 may export W3C-compatible identity documents, but it does not turn every JACS document into a Verifiable Credential proof target.
- **NG6. No generic DSSE projection.** Existing attestation DSSE code remains separate.
- **NG7. No ML-DSA encryption.** The PQ signing library signs and verifies. It does not encrypt the ES256 private key. P2 uses the existing encrypted key envelope.
- **NG8. No new external service.** No registry, anchoring service, network verifier, revocation service, or HAI API change is required for this phase.

## 5. Functional Requirements

- **FR1. Native signing policy.** All new native JACS document signatures use `pq2025`. Public APIs, CLI commands, and config paths must not present ES256 as a native signing option.
- **FR2. Legacy verify.** JACS must continue to verify legacy documents whose algorithms are already supported by the verifier. Legacy support must not imply new legacy signing support.
- **FR3. Init behavior.** `jacs init`, quickstart/create paths, and equivalent SDK/MCP create paths create both:
  - a PQ root signing key for native JACS documents
  - an ES256 compatibility signing key for ecosystem exports
- **FR4. Key roles.** Key metadata records roles instead of treating all keys as peer native signing keys:
  - `native_root`: `pq2025`
  - `ecosystem_signing`: `es256`
- **FR5. Private key storage.** The ES256 private key is encrypted at rest using the existing JACS V2 envelope and filesystem hardening: AES-256-GCM + Argon2id, secure file creation, `0600` files, and `0700` directories. The PQ signing key is not used as an encryption primitive.
- **FR6. Compatibility key binding.** JACS emits a canonical JSON compatibility key binding document signed with the PQ root. It binds:
  - JACS agent id
  - PQ root public key identity
  - ES256 public JWK and stable `kid`
  - allowed compatibility scopes
  - issued time and optional expiration
  - native `jacsSignature` with `pq2025`
- **FR7. Exported ecosystem documents.** JACS exports compatibility identity material using the ES256 key where required by the target ecosystem. Exports include or reference the PQ-signed binding so a JACS-aware verifier can trace the ES256 key back to the PQ root.
- **FR8. JWKS and DID identity.** JACS can export a JWKS containing the ES256 public key and a DID/W3C-compatible identity document that lists the ES256 verification method. `kid` is stable and based on the public JWK thumbprint.
- **FR9. A2A compatibility.** A2A agent card export uses the ES256 compatibility key when that ecosystem requires ES256. The exported card includes a binding reference or embedded binding extension without changing native JACS document signing.
- **FR10. Minimal public API.** New binding methods go through `binding-core/src/simple_wrapper.rs::SimpleAgentWrapper` and are mirrored only where needed:
  - export compatibility JWKS JSON
  - export compatibility key binding JSON
  - export ecosystem agent identity/card JSON if not already covered by an existing method
- **FR11. Fixture parity.** Any added CLI command, MCP tool, binding method, or error kind updates the canonical parity fixtures listed in `AGENTS.md`.
- **FR12. Negative guardrails.** Tests prove that P2 does not add native ES256 signing, `ring-ES256`, generic projections, or arbitrary-document JWS.

## 6. Non-Functional Requirements

- **NFR1. Simplicity.** Keep compatibility code at the edges. Native JACS signing and verification remain easy to explain.
- **NFR2. Reversibility.** Each task is independently revertible in one commit.
- **NFR3. Cross-language parity.** Rust, Python, Node, Go, CLI, and MCP surfaces stay aligned through fixtures.
- **NFR4. Observability.** Compatibility export and verification failures log structured JSON events at the right level. Auth and verification failures log at WARN.
- **NFR5. Security.** ES256 exists only because external ecosystems require it. Native JACS durability comes from PQ signatures.
- **NFR6. Dependency restraint.** Prefer small, direct RustCrypto dependencies over broad JOSE frameworks. Every new dependency has a buy/build note in its task.
- **NFR7. No silent migrations.** Existing agents must load predictably. If an agent has no compatibility key, export commands fail with a clear typed error or create one only through an explicit migration path.

## 7. Technical Design

### 7.1 Key Model

The agent identity is rooted in the PQ key:

```text
JACS agent id
  native_root: pq2025 / ML-DSA-87
    signs native JACS documents
    signs compatibility key binding documents

  ecosystem_signing: es256 / ECDSA P-256
    signs or identifies ecosystem exports
    never signs native JACS documents
    is bound to native_root by a PQ-signed binding
```

This avoids a "multi-primary" model. There is one JACS root. Compatibility keys are delegated credentials with narrow purpose.

### 7.2 Private Key Storage

The current PQ signing library signs and verifies. It is not an encryption library.

JACS already has an encrypted key storage path. P2 uses that path for the ES256 private key:

- `jacs-core/src/envelope.rs` for the V2 AES-256-GCM + Argon2id envelope
- `jacs/src/keystore/mod.rs` for filesystem-safe private key writes and permissions
- existing password resolution behavior

`jacs/src/crypt/kem.rs` has ML-KEM helper code, but P2 does not move key storage to ML-KEM. That would be a separate KEM-backed wrapping design, not needed for ecosystem compatibility.

### 7.3 Compatibility Key Binding

The binding is a JACS document or JACS-compatible schema document whose native signature is PQ-only.

Illustrative shape:

```json
{
  "jacsDocumentType": "compatibilityKeyBinding",
  "jacsDocumentVersion": "1.0.0",
  "jacsId": "jacs:agent:...",
  "rootKey": {
    "algorithm": "pq2025",
    "kid": "..."
  },
  "compatibilityKey": {
    "algorithm": "ES256",
    "kid": "...",
    "publicJwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  },
  "scope": [
    "jwks",
    "did",
    "a2a-agent-card",
    "w3c-agent-identity"
  ],
  "issuedAt": "2026-06-28T00:00:00Z",
  "expiresAt": null,
  "jacsSignature": {
    "signatureContentVersion": "jacs-signature-v2",
    "signingAlgorithm": "pq2025"
  }
}
```

The exact schema should live beside the existing schemas, not by adding protocol-specific fields to the native agent schema.

### 7.4 Export Semantics

Exports are derived views over the same agent identity:

- **Native JACS agent document:** signed with PQ `jacsSignature`.
- **Compatibility binding:** signed with PQ `jacsSignature`; binds ES256 public key to JACS agent id.
- **JWKS:** contains the ES256 public JWK and stable `kid`; may include binding metadata by reference if the format allows.
- **DID/W3C identity:** lists ES256 verification method; includes service/alsoKnownAs/proof metadata only where the target format supports it.
- **A2A agent card:** uses the ES256 compatibility key for ecosystem compatibility and includes a binding reference or extension.

P2 should not add a generic projection mechanism that mutates every JACS document.

### 7.5 Verification Semantics

Native JACS verification remains:

1. canonicalize JACS document
2. verify `jacsSignature`
3. verify schema and hash contracts

Compatibility verification is separate:

1. verify the ecosystem document with normal ecosystem rules where applicable
2. verify the PQ-signed compatibility key binding with native JACS rules
3. confirm the ecosystem ES256 `kid` and public key match the bound key
4. confirm the binding scope covers the export type

This keeps "what a JACS agent does" clear: it creates verifiable documents and can publish compatibility identity views for other ecosystems.

### 7.6 Public Surface

Add only the smallest useful surface:

- SDK:
  - `export_compatibility_jwks_json()`
  - `export_compatibility_key_binding_json()`
  - `export_a2a_agent_card_json()` only if existing A2A export cannot be reused
- CLI:
  - `jacs agent export-jwks`
  - `jacs agent export-compat-binding`
  - reuse existing agent/A2A export commands where possible
- MCP:
  - mirror CLI export behavior only when it is useful to remote tools

Do not add:

- `sign_es256`
- `sign_jws`
- `verify_jws`
- `sign_data_integrity`
- `export_dsse_document`
- arbitrary `jacsProjections`

### 7.7 Observability

Required structured events:

| Event | Level | Required fields | Meaning |
| --- | --- | --- | --- |
| `native_non_pq_sign_rejected` | WARN | `requested_algorithm`, `jacs_id` | Caller tried to create a new native non-PQ signature. |
| `compatibility_key_missing` | WARN | `jacs_id`, `requested_export` | Export requested before the ES256 compatibility key exists. |
| `compatibility_binding_created` | INFO | `jacs_id`, `kid`, `binding_hash` | PQ-signed binding was created. |
| `ecosystem_export_generated` | INFO | `jacs_id`, `format`, `kid`, `binding_hash` | Compatibility export was generated. |
| `compatibility_binding_verify_failed` | WARN | `jacs_id`, `kid`, `reason` | Binding did not validate. |

Metrics should follow the existing JACS observability style:

- `jacs_native_non_pq_sign_rejected_total`
- `jacs_compatibility_export_total{format}`
- `jacs_compatibility_export_error_total{format,reason}`
- `jacs_compatibility_binding_verify_failed_total{reason}`

Docs must state what a sysadmin sees when a compatibility export or binding verification fails.

### 7.8 Dependency Buy/Build Note

JACS should not implement P-256 arithmetic itself. If ES256 signing/export requires a new Rust dependency, use a small RustCrypto path such as `p256`/`ecdsa`/`signature`/`rand_core` for:

- P-256 key generation
- ECDSA-SHA-256 signing for ecosystem documents
- public key encoding as JWK
- RFC 7638 thumbprint input generation

Avoid broad JOSE frameworks unless a task proves they are needed. Do not use `ring` in portable core paths.

## 8. Ordered Task Plan

Task files live in `P2_ES256_PROJECTIONS_PRD_TASKS/`.

| Task | Title | Depends on | Reversible unit |
| --- | --- | --- | --- |
| 001 | Native PQ signing policy | - | one commit |
| 002 | Role-based keyring and init behavior | 001 | one commit |
| 003 | Compatibility key binding document | 002 | one commit |
| 004 | ES256 ecosystem identity exports | 003 | one commit |
| 005 | CLI/SDK/MCP public surface parity | 004 | one commit |
| 006 | Legacy verification and scope guardrails | 001, 005 | one commit |
| 007 | Observability and documentation | 003, 005, 006 | one commit |

## 9. Answered Design Questions

### Is the revised model correct and ideal?

Yes. It keeps JACS native trust PQ-first and uses ES256 only where outside ecosystems require ES256. The key improvement is role separation: PQ root for JACS authenticity; ES256 compatibility key for ecosystem exports.

### Do we need new CLI/SDK functions?

Yes, but only a few. Add export and inspection functions, not general ES256 signing functions. Public binding methods must be added through `SimpleAgentWrapper` and parity fixtures.

### Can we encrypt the ES256 private key with the PQ library?

Not with ML-DSA. ML-DSA signs and verifies. JACS should encrypt the ES256 private key with the existing AES-256-GCM + Argon2id key envelope. ML-KEM exists in the codebase, but using it for key wrapping is a separate future design.

### Do we add other ecosystem fields to the JACS agent JSON schema?

No, not as protocol-specific native fields. Add a separate compatibility key binding schema and generate ecosystem documents as exports. Keep the native agent schema focused on JACS identity and signing.

### Where can we simplify?

Remove native ES256, multi-primary key selection, generic projections, arbitrary-document JWS, generalized Data Integrity proofs, generalized DSSE, and `jacsProjections`. Keep P2 focused on PQ-rooted identity plus ES256 ecosystem exports.

## 10. Architecture Review

Review performed with `/review-architecture` on 2026-06-28.

### Verdict

**Ready for user approval before `/execute`.**

### What Was Fixed

- Replaced the previous "first-class ES256 + standard projections" architecture with a PQ-root compatibility architecture.
- Removed native ES256 from the planned JACS signing contract.
- Removed generic JWS, Data Integrity, DSSE, and `jacsProjections` requirements.
- Clarified that the PQ signing library does not encrypt private keys.
- Added the compatibility key binding as the bridge between PQ JACS identity and ES256 ecosystems.
- Reduced the public API plan to compatibility exports and binding export only.
- Rebuilt the task list into seven small, reversible, test-first tasks.

### Coverage Check

| Review area | Result |
| --- | --- |
| Requirement coverage | Covered: PQ-only native signing, init key creation, ES256 storage, native verify, ecosystem exports, schema boundary, simplification. |
| TDD coverage | Covered in every task with Red/Green sections. |
| Cross-language parity | Covered in Task 005 with fixture updates. |
| DRY/YAGNI | Improved by removing generic projection surfaces and keeping ES256 at compatibility edges. |
| Observability | Covered in Task 007 and PRD section 7.7. |
| Dependency posture | Covered with a narrow RustCrypto buy/build note. |
| Reversibility | Each task remains a one-commit reversible unit. |

### Remaining Product Decision

The only remaining user-level decision is whether A2A export must embed the PQ-signed compatibility binding directly or may reference it by URI/hash when the target format has no natural embedded extension point. The task plan allows either, but implementation should choose the simplest format-compatible option during Task 004.
