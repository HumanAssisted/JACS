# Attestation Plan (Universal Adapter Direction, JACS-Compatible)

Last updated: 2026-03-03

## Direct Answers to the Core Questions

1. Is this additive, without removing existing functionality?
- Yes. The plan is additive by default.
- Existing JACS document signing, verification, A2A wrapping, trust policies, and agreement flows remain intact.
- New attestation capabilities are layered on top of current JACS primitives.

2. Does this replace JACS format with a Universal Cryptographic Adapter format?
- No.
- JACS document format remains the base format.
- "Universal Cryptographic Adapter" is an additional capability in JACS: JACS creates and verifies adapter-style attestations as JACS documents.

3. Does JACS stop knowing about JACS documents?
- No.
- JACS documents remain the canonical unit of signing, storage, and verification.
- Adapter documents are still JACS documents (new profile/type), not a separate format that replaces JACS.

## Why This Is Useful

JACS currently proves origin and integrity well. The next practical step is proving more than "who signed this":

- Prove what external evidence was used (for example: DNS proof, registry state, TLS transcript proof).
- Prove what transformation happened (input -> function/policy -> output).
- Prove policy compliance across trust boundaries (machine-checkable, repeatable).

This moves JACS from "signed payloads" to "proof-carrying workflows" without breaking current integrations.

> **[REVIEW NOTE — DevEx]** The pitch "Signing says WHO. Attestation says WHO plus WHY" should appear in the first paragraph of every attestation-facing doc. This single sentence resolves the biggest confusion developers will have: when to use `sign_message` vs `create_attestation`.

## Problem Statement

In multi-agent systems, verification failures are often not cryptographic failures. They are evidence and context failures:

- A receiver cannot reconstruct why a result is trustworthy.
- Provenance chains exist but do not encode enough policy-relevant context.
- Cross-system artifacts (A2A, email, JWT/OIDC claims, TLSNotary outputs) are hard to normalize.

Goal: make JACS a portable attestation fabric while preserving current JACS ergonomics.

> **[REVIEW NOTE — Product]** The problem is real, but the plan lacks explicit user stories. Add these three:
>
> 1. **Compliance Audit Trail** (persona: compliance engineer): "As a compliance engineer at a financial services firm, I need each AI agent in our approval pipeline to attach machine-readable evidence to its signed output, so that during an audit I can trace every decision back to its inputs and rules."
>
> 2. **Cross-Org Agent Trust** (persona: platform engineer): "As a platform engineer integrating a third-party AI agent via A2A, I need to verify not just that the agent signed its output, but that it used acceptable evidence sources and ran an approved transformation."
>
> 3. **Transform Receipt** (persona: ML pipeline developer): "As an ML pipeline developer, I need Agent B to produce a signed receipt showing what inputs it received, what function it applied, and the hash of its output."
>
> Sequence: Start with persona 1 (compliance/audit enrichment) — those users already exist, the value is clearest, and the scope is smallest.

## Design Principles

1. Backward compatible first.
2. Attestations are JACS documents, not an external replacement format.
3. Verification remains deterministic and offline-capable when evidence is present.
4. Policy decisions are explicit artifacts, not hidden runtime logic.
5. Start with practical adapters; keep advanced cryptography optional.

## Scope

### In Scope
- New attestation document profile(s) built on JACS.
- Adapter interface for ingesting external evidence into canonical attestation claims.
- Verification APIs that return both cryptographic validity and policy decision trace.
- Chain-of-custody expansion to include transform receipts.

### Out of Scope (for next 1-2 releases)
- Replacing existing JACS schemas and document lifecycle.
- Mandating SNARK/FHE/MPC for core flows.
- Requiring centralized infrastructure.

> **[REVIEW NOTE — Product]** Add an explicit "We will NOT" list:
> - No centralized attestation registry required
> - No separate document format replacing JACS
> - No mandatory advanced crypto (SNARK/FHE/MPC)
> - No full OPA/Rego policy engine in N+1

## Competitive Positioning

> **[REVIEW NOTE — Web Research / Product]** This section is missing from the plan and should be added. JACS should be explicitly positioned relative to existing standards.
>
> **As-of caveat (2026-03-03):** standards maturity and release status can change quickly. Revalidate before roadmap commitments.
>
> Reference links:
> - SLSA: https://slsa.dev/spec/
> - in-toto: https://in-toto.io/
> - Sigstore/Cosign releases: https://github.com/sigstore/cosign/releases
> - IETF SCITT docs: https://datatracker.ietf.org/wg/scitt/documents/
> - IETF RATS/EAT RFC 9711: https://www.rfc-editor.org/rfc/rfc9711
> - CSA Agentic Trust Framework: https://cloudsecurityalliance.org/
> - NIST AI Security Institute: https://www.nist.gov/aisi
>
> Suggested positioning table:
>
> | Standard | Status | Relationship to JACS |
> |---|---|---|
> | **SLSA / in-toto** | Production (v1.0+) | Different domain. SLSA = build provenance. JACS = AI agent runtime attestation. Non-overlapping but interoperable via in-toto predicate types. |
> | **Sigstore / Cosign** | Production (v3 GA) | Signing infrastructure, not evidence/policy framework. JACS has its own signing. Consider Sigstore bundle verification adapter for consuming upstream artifacts. |
> | **SCITT** | IETF Draft-22 | Most significant overlap. SCITT = centralized transparency service + signed claims. JACS = decentralized, offline-capable attestation. Key differentiator: JACS does not require a central notary. |
> | **IETF RATS / EAT** | Published (RFC 9711) | Platform/device attestation (TPM, TEE). JACS fills the agent software layer above the hardware layer RATS addresses. Align claim names with IANA registries where possible. |
> | **NIST AI Agent Standards** | Active (Feb 2026) | NIST CAISI initiative defining AI agent security/identity standards. JACS is one of the most complete implementations of what NIST is standardizing. **Action: Submit NIST RFI response.** |
> | **CSA Agentic Trust Framework** | Published (Feb 2026) | Progressive trust model for AI agents. Maps to JACS `open/verified/strict` levels. Consider expanding to match ATF's 5-gate model. |
>
> **JACS's unique combination** (no other framework covers all):
> 1. Agent-native identity (not just artifact identity)
> 2. Multi-agent agreement with quorum
> 3. Transform receipts (proving what happened between input and output)
> 4. Policy evaluation as a first-class attestation artifact
> 5. Fully offline/decentralized verification
> 6. Probabilistic claims (`confidence` field)
> 7. Post-quantum signature support (pq2025)
>
> **Position as:** "Agent-layer attestation framework" — sits above platform attestation (RATS/EAT), alongside supply chain attestation (SLSA/in-toto/Sigstore), and implements the trust patterns NIST/CSA are defining.

## Proposed Architecture

## Layer 0: Existing JACS (unchanged)
- Signing and verification
- A2A provenance wrappers
- Trust policy checks
- Agreement quorum/timeout/algorithm constraints

## Layer 1: Attestation Profile (new, additive)
- Add a new JACS document type/profile for attestations.
- Example `jacsType` values:
  - `attestation`
  - `attestation-policy-decision`
  - `attestation-transform-receipt`

These are still standard JACS documents with regular `jacsSignature`, `jacsSha256`, version fields, and storage behavior.

> **[REVIEW NOTE — Rust Arch]** `jacsLevel` assignment matters. The header schema constrains `jacsLevel` to `["raw", "config", "artifact", "derived"]`. `EDITABLE_JACS_DOCS` only allows editing for `"config"` and `"artifact"`. Recommended mapping:
> - `attestation` → `jacsLevel: "raw"` (immutable once created) ✓
> - `attestation-policy-decision` → `jacsLevel: "raw"` (immutable) ✓
> - `attestation-transform-receipt` → `jacsLevel: "derived"` (auditable, not editable)
>
> This should be explicitly documented since it affects storage and lifecycle behavior.

## Layer 2: Adapter Runtime (new, additive)
- Adapter modules normalize external proof/evidence formats into canonical attestation claims.
- Initial adapters:
  - A2A wrapped artifacts (already close)
  - Email signature documents
  - JWT/OIDC token claims (header + claims + issuer metadata)
  - TLSNotary/PCD-style evidence bundles (as opaque evidence + verifier metadata)

> **[REVIEW NOTE — Security: HIGH]** TLSNotary status is time-sensitive.
>
> **As-of caveat (2026-03-03):** treat TLSNotary as experimental/pre-stable until independently audited and broadly production-proven.
>
> Reference links:
> - TLSNotary releases: https://github.com/tlsnotary/tlsn/releases
> - TLSNotary docs: https://tlsnotary.org/
>
> **Recommendation:** Move TLSNotary from "initial adapters" to "future/experimental." If included, cap `confidence` at 0.5 for unaudited TLSNotary proofs and require policy-level opt-in. Focus initial adapters on A2A, JWT/OIDC, and email — all with mature verification paths.

> **[REVIEW NOTE — Rust Arch]** Adapter dependency isolation strategy:
> | Adapter | New deps? | Network? | Feature flag |
> |---|---|---|---|
> | A2A | None (reuses `a2a` module) | No | Base `attestation` feature |
> | Email | None (reuses `email` module) | No | Base `attestation` feature |
> | JWT/OIDC | `jsonwebtoken` + JWKS fetch | Yes | `attestation-jwt` |
> | TLSNotary | TLSNotary proof parser | No | `attestation-tlsnotary` (N+2+) |
>
> File layout: `jacs/src/attestation/{mod.rs, adapters/{mod.rs, a2a.rs, email.rs, jwt.rs}, policy/mod.rs}`

## Layer 3: Policy Engine Hooks (new, additive)
- Evaluate attestations under explicit policy documents.
- Return machine-readable decision records:
  - allowed/denied
  - reasons
  - which evidence/claims satisfied which rule

> **[REVIEW NOTE — Security: HIGH]** Policy engine isolation is a critical security decision. OPA/Rego policies have been exploited to make external network calls and exfiltrate credentials via `http.send`. Requirements:
> 1. Policy documents MUST be signed JACS documents themselves (recursive trust chain)
> 2. Policy evaluation MUST be pure/deterministic — no network I/O, no filesystem, no env vars
> 3. `policyContext.policyId` must be mandatory and include policy content hash, not just an identifier
> 4. `attestation-policy-decision` must record the exact policy version hash used
>
> **[REVIEW NOTE — Product / DevEx]** Defer Layer 3 from N+1 to N+2. The policy engine is the most complex piece and the least urgent. In N+1, attestations can exist and be verified without a formal policy engine. Users can write their own policy logic against the structured verification output. This significantly reduces N+1 scope.

## Canonical Attestation Document (Proposed)

This is a conceptual shape, implemented as a JACS document profile:

```json
{
  "jacsType": "attestation",
  "jacsLevel": "raw",
  "jacsId": "uuid",
  "jacsVersion": "uuid",
  "jacsVersionDate": "RFC3339",
  "jacsSignature": { "...": "existing JACS signature fields" },
  "jacsSha256": "hash",
  "content": {
    "subject": {
      "type": "agent|artifact|workflow|identity",
      "id": "string"
    },
    "claims": [
      {
        "name": "string",
        "value": "json",
        "confidence": 1.0,
        "issuer": "agent-id-or-domain",
        "issuedAt": "RFC3339"
      }
    ],
    "evidence": [
      {
        "kind": "a2a|email|jwt|tlsnotary|custom",
        "hash": "sha256",
        "uri": "optional URI",
        "embedded": false,
        "verifier": {
          "name": "adapter/verifier id",
          "version": "semver"
        }
      }
    ],
    "derivation": {
      "inputs": ["hash1", "hash2"],
      "transform": "program/policy identifier",
      "outputHash": "sha256"
    },
    "policyContext": {
      "policyId": "optional",
      "requiredTrustLevel": "open|verified|strict|custom"
    }
  }
}
```

> **[REVIEW NOTE — Security: HIGH]** Hash algorithm agility. The schema uses `sha256` as the sole hash algorithm. SLSA v1.2 and in-toto v1.1.0 both support algorithm-agile digest sets (`"digests": {"sha256": "...", "sha512": "..."}`). **Change the `hash` field to a `digests` object** supporting multiple algorithms. This is a low-cost change with high long-term value, especially for post-quantum migration.

> **[REVIEW NOTE — Security: MEDIUM]** Subject binding is weak. The `subject.id` is a plain string with no cryptographic binding. SLSA and in-toto both require subject digests. **Add a mandatory `subject.digest` field** (using a DigestSet). For agent subjects, hash the public key. For artifact subjects, hash the content.

> **[REVIEW NOTE — Security: MEDIUM]** `confidence` score is undefined and gameable. No defined semantics (what does 0.5 vs 0.9 mean?), no defined assigner (adapter? policy engine?), no cap mechanism. **Recommendation:** Define as adapter-assigned; let policy override/cap; consider supplementing with categorical assurance levels (`self-asserted`, `verified`, `independently-attested`) aligned with SLSA build levels.

> **[REVIEW NOTE — Security: HIGH]** Evidence freshness not bound to attestation creation time. Add a mandatory `evidence.collectedAt` field. Enforce a configurable `maxEvidenceAge` in policy. The attestation creation timestamp minus evidence collection timestamp must not exceed this threshold. Without this, a "stale evidence" attack is possible: collect valid evidence, lose control of the resource, then create an attestation with the old evidence.

> **[REVIEW NOTE — Security: MEDIUM]** Referenced evidence TOCTOU vulnerability. When `embedded: false`, the URI content may change between attestation creation and verification. **Define behavior:** For `strict`/`verified` trust levels, require embedded evidence or content-addressable URIs (`hash://sha256/...`, IPFS CIDs). Add `resolvedAt` timestamp to evidence objects.

> **[REVIEW NOTE — Web Research]** Consider splitting `content` into a Statement layer (subjects + predicate type) and a typed Predicate layer (claims, evidence, derivation, policy). This aligns with in-toto's proven 4-layer architecture (Predicate → Statement → Envelope → Bundle) and enables a JACS-specific in-toto predicate type (`https://jacs.dev/attestation/v1`), making JACS attestations exportable as standard in-toto Statements in DSSE envelopes — consumable by the entire SLSA/Sigstore/GitHub/npm ecosystem.

> **[REVIEW NOTE — DevEx]** This schema introduces ~12 new concepts (attestation profiles, claims, confidence, evidence, derivation, transform receipts, adapters, policy engine, policy context, decision traces, jacsLevel for attestations). Current JACS has ~4 core concepts (Agent, Document, Signature, Agreement). This roughly triples the concept surface. Consider progressive disclosure: start with just `subject` + `claims` for the hello-world path; evidence and derivation can be advanced features.

> **[REVIEW NOTE — DevEx]** `derivation.transform` is underspecified. "program/policy identifier" — is this a URI? A hash? A human-readable name? Show a concrete example: "Here is what a transform receipt looks like when Agent B summarizes Agent A's research." Without this, the most novel part of the plan is the least tangible.

> **[REVIEW NOTE — Rust Arch]** `derivation.transform` must be a content-addressable reference (hash of the transformation code/binary), not an opaque string. Without this, derivation chains are unverifiable assertions. Add `transform.reproducible: bool` and `transform.environment` for runtime parameters. Use existing `hash_string` from `jacs/src/crypt/hash.rs`.

Notes:
- `content` structure can evolve under schema versioning.
- Evidence may be embedded or referenced.
- Derivation block is key for "proof-carrying transformation," not just static signatures.

> **[REVIEW NOTE — Rust Arch]** Schema evolution mechanism: Create `schemas/attestation/v1/attestation.schema.json`. Register in existing `DEFAULT_SCHEMA_STRINGS` phf_map. Add `Validator` to `Schema` struct. Version the path (`v1/`, `v2/`). Documents bind to their schema version via `$schema` URL. Do NOT refactor the schema registry in this release — that is orthogonal scope.

## Attestation Verification Output (Proposed)

Verification should return:

- `crypto_valid`: signature/hash validity
- `evidence_valid`: per-evidence verification result
- `chain_valid`: parent/derivation chain status
- `policy_allowed`: final decision
- `decision_trace`: rule-level explanation

This avoids today's binary "valid/invalid only" limitation for policy-heavy workflows.

> **[REVIEW NOTE — DevEx]** Five fields where today there is one boolean (`valid`). The simple `valid` boolean path MUST still work. The five-field breakdown should be opt-in. Developers who call `verify()` on an attestation document should get `True/False` as before. The rich breakdown should be available via `verify_attestation()` or a `--verbose` flag. Do not fork the verify path.

> **[REVIEW NOTE — DevEx]** The `verify` vs `evaluate` distinction maps to "is the crypto valid?" vs "does it meet policy?" but most developers won't intuit that. Options:
> - Rename to `check_policy` / `jacs attest check-policy`
> - Collapse: `verify_attestation` returns crypto by default, add `--policy <file>` for policy evaluation in the same call
>
> The cosign model is worth studying: single `attest` command with `--type` for attestation kinds, predicate is always a file.

> **[REVIEW NOTE — Rust Arch]** Recommended Rust struct:
> ```rust
> pub struct AttestationVerificationResult {
>     pub crypto: VerificationResult,        // existing struct, composing
>     pub evidence: Vec<EvidenceVerificationResult>,
>     pub chain: Option<ChainVerificationResult>,
>     pub policy: Option<PolicyDecision>,     // None if no policy context
> }
> ```
> Separate `verify_attestation` into two tiers:
> - `verify_attestation_local(doc)` — crypto + hash only, no network, no derivation walk. Hot-path default.
> - `verify_attestation_full(doc)` — crypto + evidence fetch + derivation chain + policy. Explicit opt-in.
>
> Set maximum derivation chain depth (default: 10, configurable via `JACS_MAX_DERIVATION_DEPTH`). Unbounded recursion is a DoS vector.

## How This Maps to Existing JACS

Existing features become building blocks, not legacy:

- A2A provenance wrappers feed adapter inputs.
- Agreement engine provides multi-agent policy approval primitives.
- Trust policy (`open/verified/strict`) becomes one policy dimension in attestation evaluation.
- Key resolution and verification-claim checks stay authoritative for signer identity guarantees.

## Release Plan

## Release N+1 (Attestation Foundation)

1. Add attestation schemas and profile docs.
2. Add core APIs:
- Rust:
  - `create_attestation(...)`
  - `verify_attestation(...)`
  - `evaluate_attestation_policy(...)`
- Python/Node parity through existing wrappers.
3. Add one adapter path end-to-end:
- A2A wrapped artifact -> attestation -> policy decision.
4. Add CLI/MCP tools:
- `jacs attest create`
- `jacs attest verify`
- `jacs attest evaluate`
5. Maintain strict backward compatibility:
- No changes required for existing `sign_message`, `verify`, `sign_artifact`, agreements.

> **[REVIEW NOTE — API Naming]** Use one primary naming convention across Rust/Python/Node docs:
> - Primary: `create_attestation`, `verify_attestation`, `evaluate_attestation_policy`
> - Optional convenience alias: `attest(...)` maps to `create_attestation(...)`
> - If alias exists, docs must always show primary name first and alias second.

> **[REVIEW NOTE — Product]** N+1 is overloaded. This is five work streams: schemas + three APIs + adapter + CLI + MCP. Based on JACS release history, each version focuses on one major capability.
>
> **CUT from N+1:**
> - `evaluate_attestation_policy(...)` → move to N+2 (policy engine is most complex, least urgent)
> - MCP tools for attestation → move to N+2 (secondary interface; get Rust + Python + Node right first)
> - `jacs attest evaluate` CLI → follows the policy engine, cut
>
> **KEEP in N+1:**
> - Attestation schema/profile (single schema, not profile-specific)
> - `create_attestation` + `verify_attestation` in Rust + Python + Node
> - A2A adapter (one end-to-end path)
> - `jacs attest create` + `jacs attest verify` CLI
> - Backward compatibility guarantees
>
> **ADD to N+1:**
> - Hello-world attestation flow (5-10 lines in Python, Node, CLI)
> - Migration helpers ("lift existing signed artifacts into attestation documents") — currently in N+2 but this is the first thing existing users will ask for
> - in-toto predicate type definition + DSSE export path (interop with SLSA/Sigstore/GitHub ecosystem)

> **[REVIEW NOTE — DevEx]** Missing: a hello-world example. What the simplest attestation should look like:
> ```python
> # I already have a signed document
> signed = jacs.sign_message({"action": "approve", "amount": 100})
>
> # Now attest WHY this is trustworthy
> attestation = jacs.create_attestation(
>     signed,
>     claims={"reviewed_by": "human", "confidence": 0.95}
> )
>
> # Verify (still returns a simple boolean for the common case)
> result = jacs.verify(attestation)
> print(result.valid)           # True/False
> print(result.details)         # opt-in rich breakdown
> ```
> Alias note: `jacs.attest(...)` may exist as a convenience alias for `jacs.create_attestation(...)`.
> If the hello-world can't be approximately this simple, adoption will be limited to compliance-driven use cases.

> **[REVIEW NOTE — Rust Arch]** Recommended trait design for N+1:
> ```rust
> pub trait AttestationTraits {
>     fn create_attestation(&mut self, subject: &AttestationSubject,
>         claims: &[Claim], evidence: &[EvidenceRef],
>         derivation: Option<&Derivation>) -> Result<JACSDocument, Box<dyn Error>>;
>     fn verify_attestation(&self, document_key: &str)
>         -> Result<AttestationVerificationResult, Box<dyn Error>>;
> }
>
> pub trait EvidenceAdapter: Send + Sync {
>     fn kind(&self) -> &str;
>     fn normalize(&self, raw: &[u8], metadata: &Value)
>         -> Result<(Vec<Claim>, EvidenceRef), Box<dyn Error>>;
>     fn verify_evidence(&self, evidence: &EvidenceRef)
>         -> Result<EvidenceVerificationResult, Box<dyn Error>>;
> }
>
> pub trait PolicyEvaluator: Send + Sync {
>     fn evaluate(&self, attestation: &Value, policy: &Value)
>         -> Result<PolicyDecision, Box<dyn Error>>;
> }
> ```
> Store adapters on `Agent` as `Vec<Box<dyn EvidenceAdapter>>` behind feature flag, paralleling the `key_store: Option<Box<dyn KeyStore>>` pattern.
>
> For binding-core, expose: `create_attestation(&self, ...)`, `verify_attestation(&self, ...)`, `evaluate_attestation_policy(&self, ...)` — all taking/returning JSON strings, consistent with existing binding-core pattern.

> **[REVIEW NOTE — Rust Arch]** Recommended feature flags:
> ```toml
> attestation = []                                    # Zero-dependency: types + traits + A2A adapter
> attestation-jwt = ["attestation", "dep:jsonwebtoken"]  # JWT adapter
> attestation-tlsnotary = ["attestation"]             # Future/experimental
> attestation-policy = ["attestation"]                 # Policy engine
> attestation-policy-rego = ["attestation-policy", "dep:regorus"]  # Advanced
> attestation-tests = ["attestation"]                  # Test gating
> ```
> Base `attestation` feature should be zero-dependency since A2A is already in the default build.

## Release N+2 (Adapter Expansion + Policy Hardening)

1. Add email and JWT adapters.
2. Add transform receipts with deterministic derivation hashing.
3. Add policy packs:
- Baseline trust policy
- Compliance profile examples (for regulated workflows)
4. Add richer verification reports for auditing and machine ingestion.
5. Add migration helpers:
- lift existing signed artifacts into attestation documents without re-signing source payloads.

> **[REVIEW NOTE — Product]** Move to N+2: `evaluate_attestation_policy`, MCP attestation tools, `jacs attest evaluate` CLI (from N+1).
>
> Add to N+2: Schema refinement based on N+1 feedback. Sigstore bundle verification adapter. EAT/JWT evidence adapter with IANA claim alignment. Attestation revocation mechanism (`attestation-revocation` document type).

## Backward Compatibility and Migration

Compatibility guarantees:

1. Existing JACS documents remain valid and verifiable.
2. Existing APIs remain supported.
3. Existing trust stores and key resolution behavior remain supported.

Migration strategy:

1. Opt-in feature flags for adapter/attestation APIs.
2. No forced schema migration for old documents.
3. Optional "attestation envelope" generation around existing artifacts.

## Security and Reliability Considerations

1. Replay and temporal checks
- Continue mandatory timestamp/nonce checks for signatures.
- Add attestation-level freshness checks for external evidence.

> **[REVIEW NOTE — Security: MEDIUM]** Replay protection gaps:
> - The nonce cache is process-local (`static SEEN_NONCES`, moka cache, 200K entries). In distributed deployments, the same nonce can be replayed against different instances.
> - Cache eviction attack: 200,001 unique nonces evict a legitimate one, enabling replay.
> - Attestation-level replay is distinct from payload-level replay.
>
> **Recommendations:**
> - Add `attestation.nonce` field separate from payload nonce
> - Provide a `NonceStore` trait for pluggable external stores (Redis, database)
> - Attestation-level `iat` skew should default to enabled (300s), distinct from document-level default of 0
> - Make nonce cache capacity configurable

2. Evidence integrity
- Every evidence object must carry a stable hash.
- Referenced evidence must include immutable digest binding.

3. Policy determinism
- Policy evaluation must produce deterministic decision trace payloads.
- Version policies and include policy ID in decision docs.

4. Fail-closed behavior
- Missing required evidence -> deny (not warn-only) when policy requires it.
- Unresolvable keys under strict policy -> deny.

> **[REVIEW NOTE — Security: LOW]** For attestation verification, the default trust level should be `verified` or `strict`, never `open`. If `open` is retained for attestations, produce a prominent warning in the decision trace.

> **[REVIEW NOTE — Security: MEDIUM]** Missing: attestation revocation mechanism. Unlike versioned documents, attestations may need explicit revocation (fraudulent evidence discovered, key compromised, retroactive policy change). Define an `attestation-revocation` document type that references the revoked attestation by ID and hash. Verifiers must check for revocations.

> **[REVIEW NOTE — Security: HIGH]** Missing: transparency log / append-only audit trail. Both SCITT and Sigstore depend on transparency services providing cryptographic receipts proving a claim was registered at a specific time. Without this:
> - Attesters can silently revoke/replace attestations
> - No third-party auditability of attestation history
> - "Evidence of absence" queries impossible
>
> **Recommendation:** Add an optional transparency log design. At minimum, define an `attestation-receipt` document type with Merkle inclusion proofs or sequence numbers. Consider whether JACS's existing version chain (`jacsVersion` lineage) can serve as a lightweight append-only structure.

> **[REVIEW NOTE — Security: MEDIUM]** Missing: privacy considerations for embedded evidence. JWT tokens may contain PII. TLSNotary proofs may reveal session content. Email evidence may contain private correspondence.
>
> **Recommendations:**
> - Define redaction rules per evidence type
> - Support selective disclosure (reference by hash without embedding)
> - For JWT evidence, include only `iss`, `sub`, `aud`, `iat`, `exp` by default
> - Add `sensitivity` classification to evidence objects (`public`, `restricted`, `confidential`)

> **[REVIEW NOTE — Security: LOW]** JSON canonicalization. JSON serialization is not deterministic (key ordering, whitespace). Specify a canonicalization algorithm (JCS / RFC 8785) for all hash computations over JSON content. Document whether evidence hashes are over raw bytes or canonical JSON.

## Digest Compatibility Rule

Adding attestation digest sets does **not** replace existing top-level JACS hashing semantics.

- `jacsSha256` remains required and continues to represent the canonical hash of the full JACS document envelope.
- New attestation `digests` fields are additive and scoped to attestation internals (`subject`, `evidence`, `derivation`).
- Verifiers MUST continue validating `jacsSha256` first, then validate attestation-level digest sets.

## Example End-to-End Flow (Practical)

1. Agent A signs a task artifact (existing JACS behavior).
2. Adapter normalizes artifact + parent signatures into an attestation document.
3. Agent B verifies cryptographic chain and adds transform receipt attestation for processing step.
4. Policy evaluator checks:
- signer trust level
- required evidence kinds
- quorum of approvals if needed
5. System emits `attestation-policy-decision` document with allow/deny + reasons.

Result: recipient gets not only signed data, but machine-checkable reasons for trust.

> **[REVIEW NOTE — DevEx]** This flow is the right concept but needs a concrete code example showing each step. Also add a simpler flow first (just create + verify, no policy evaluation) for the getting-started path.

## Success Metrics

1. Adoption
- % of A2A workflows producing attestations
- # of adapters used per deployment

2. Verification quality
- % of decisions with full decision trace
- reduction in "unknown trust reason" incidents

3. Operational fit
- p95 verify latency under policy-enabled flows
- offline verification success rate when evidence is local

> **[REVIEW NOTE — Product]** Most of these metrics are not measurable without telemetry. Replace/supplement with:
>
> | Metric | Target | Measurable? |
> |---|---|---|
> | Time-to-first-attestation | < 5 minutes from existing JACS integration | Yes (user testing) |
> | p95 verify latency (local evidence) | < 50ms | Yes (benchmarks) |
> | p95 verify latency (remote evidence) | < 500ms | Yes (benchmarks) |
> | Offline verification success rate | 100% when evidence is local | Yes |
> | Cross-language parity lag | < 14 days after Rust API ships | Yes |
> | Schema stability post-N+1 | 0 breaking changes | Yes |
> | # GitHub issues/discussions mentioning attestation | Directional | Yes |

## Open Questions

1. Schema granularity: single attestation schema vs profile-specific schemas?
2. Embedded vs referenced evidence defaults by size and sensitivity?
3. Policy language format: JSON DSL vs Rego-style external engine?
4. Should transform receipts require deterministic function identity hash at v1?

> **[REVIEW NOTE — All Reviewers]** Resolution recommendations:
>
> | Question | Blocking? | Recommendation |
> |---|---|---|
> | 1. Single vs profile-specific schemas? | **No** | Single schema for v1. Split later if warranted. Premature schema proliferation is worse than a slightly general schema. |
> | 2. Embedded vs referenced defaults? | **No** | Default to referenced (hash + URI). Embed under 64KB automatically (mirrors existing `jacsFiles` pattern). Document tradeoffs. |
> | 3. Policy language format? | **Blocking for N+2**, not N+1 | Simple JSON predicate DSL first (`{"requiredEvidenceKinds": ["a2a"], "minimumClaims": 1}`). Zero external deps. Rego as optional feature flag (`attestation-policy-rego`) in v2. |
> | 4. Deterministic function identity hash? | **Blocking for N+1** | Yes, require a content-addressable `transform` identifier (hash of code/binary). Do NOT require deterministic function *execution* hashing (that implies reproducible builds — much harder problem). |

## Documentation Needs

> **[REVIEW NOTE — DevEx]** Missing documentation not mentioned in the plan:
>
> 1. **Concept explainer**: "What is an attestation and when do I need one?" — Most important doc, not in the release plan.
> 2. **Decision tree**: "Should I use sign_message or create_attestation?" — Add to existing decision-tree.md.
> 3. **Tutorial**: "Add attestations to an existing JACS workflow" — Step by step from quickstart agent.
> 4. **Policy authoring guide**: "How to write an attestation policy" — blocked on question 3 resolution.
> 5. **Error catalog**: What does each verification field mean when it fails? What should the developer do?
> 6. **Adapter development guide**: "How to write a custom adapter" — target audience will want custom adapters.
> 7. **Comparison table**: "JACS attestations vs in-toto vs cosign vs SCITT" — positions JACS and reduces learning friction.

## Standards Interoperability

> **[REVIEW NOTE — Web Research]** Critical interop actions:
>
> 1. **in-toto / DSSE** (HIGH priority, N+1): Define a JACS-specific in-toto predicate type URI. Implement DSSE export. This connects JACS to the entire SLSA/Sigstore/GitHub/npm attestation ecosystem. Risk of isolation without this is HIGH.
>
> 2. **Sigstore model signing** (MEDIUM priority, N+2): Sigstore now signs ML models via OMS v1.0 (adopted by NVIDIA NGC, Google Kaggle). Add a Sigstore bundle verification adapter so JACS agents can verify upstream model provenance.
>
> 3. **EAT / IETF RATS** (MEDIUM priority, N+1): Align claim names with IANA-registered EAT claims where possible (`ueid`, `security-level`). This connects JACS to hardware attestation (TEE/TPM) workflows.
>
> 4. **NIST AI Agent Standards** (URGENT): Submit response to CAISI RFI (due March 9, 2026) and NCCoE concept paper (due April 2, 2026). JACS is one of the most complete implementations of what NIST is defining. Not participating risks becoming a niche tool.
>
> **As-of caveat (2026-03-03):** deadline dates above are planning inputs and can drift. Verify current calls/deadlines directly from official NIST channels before action.
>
> Reference links:
> - NIST AI Security Institute: https://www.nist.gov/aisi
> - NCCoE: https://www.nccoe.nist.gov/
>
> 5. **C2PA** (LOW priority, N+2+): Content credentials for AI-generated media. Only relevant if JACS agents produce/process media content.

## Summary

This plan does not replace JACS. It extends JACS.

- JACS remains the canonical document/signature substrate.
- Universal adapter capability is introduced as an additive attestation layer.
- The outcome is better cross-boundary trust decisions with explicit, portable evidence.

> **[REVIEW NOTE — Overall Assessment]**
>
> **Security (16 findings: 5 HIGH, 8 MEDIUM, 3 LOW):** The architecture is sound but under-specified on evidence lifecycle, hash agility, transparency, and policy isolation. Top priorities: algorithm-agile digest sets, evidence freshness binding, signed policy documents, optional transparency log.
>
> **Rust Architecture:** Good fit with existing codebase. `JACSDocument` and `SimpleAgent` work without modification. Key additions: `AttestationTraits`, `EvidenceAdapter`, `PolicyEvaluator` traits. Feature flags for adapter isolation. Two-tier verification (local vs full) to manage latency.
>
> **Developer Experience:** The plan is 90% architecture and 10% developer experience. The underlying design is sound, but it needs: hello-world examples, unified verify path (simple boolean still works), progressive disclosure, resolved naming confusion (sign vs attest, verify vs evaluate), and concrete transform receipt examples. 12 new concepts vs current 4 — manage the learning curve.
>
> **Product:** Right next step for JACS. N+1 scope needs trimming (cut policy engine, MCP tools). Add user stories, competitive positioning, measurable success metrics with targets. Market timing is good — no dominant AI agent attestation standard exists. **Act urgently on NIST AI Agent Standards engagement.**
>
> **Web Research:** JACS has a unique multi-capability combination no other framework matches. Critical interop: in-toto/DSSE export (HIGH), EAT claim alignment (MEDIUM), Sigstore verification (MEDIUM). NIST engagement is the most time-sensitive action.
