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

## Problem Statement

In multi-agent systems, verification failures are often not cryptographic failures. They are evidence and context failures:

- A receiver cannot reconstruct why a result is trustworthy.
- Provenance chains exist but do not encode enough policy-relevant context.
- Cross-system artifacts (A2A, email, JWT/OIDC claims, TLSNotary outputs) are hard to normalize.

Goal: make JACS a portable attestation fabric while preserving current JACS ergonomics.

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

## Layer 2: Adapter Runtime (new, additive)
- Adapter modules normalize external proof/evidence formats into canonical attestation claims.
- Initial adapters:
  - A2A wrapped artifacts (already close)
  - Email signature documents
  - JWT/OIDC token claims (header + claims + issuer metadata)
  - TLSNotary/PCD-style evidence bundles (as opaque evidence + verifier metadata)

## Layer 3: Policy Engine Hooks (new, additive)
- Evaluate attestations under explicit policy documents.
- Return machine-readable decision records:
  - allowed/denied
  - reasons
  - which evidence/claims satisfied which rule

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

Notes:
- `content` structure can evolve under schema versioning.
- Evidence may be embedded or referenced.
- Derivation block is key for "proof-carrying transformation," not just static signatures.

## Attestation Verification Output (Proposed)

Verification should return:

- `crypto_valid`: signature/hash validity
- `evidence_valid`: per-evidence verification result
- `chain_valid`: parent/derivation chain status
- `policy_allowed`: final decision
- `decision_trace`: rule-level explanation

This avoids today's binary "valid/invalid only" limitation for policy-heavy workflows.

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

## Release N+2 (Adapter Expansion + Policy Hardening)

1. Add email and JWT adapters.
2. Add transform receipts with deterministic derivation hashing.
3. Add policy packs:
- Baseline trust policy
- Compliance profile examples (for regulated workflows)
4. Add richer verification reports for auditing and machine ingestion.
5. Add migration helpers:
- lift existing signed artifacts into attestation documents without re-signing source payloads.

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

2. Evidence integrity
- Every evidence object must carry a stable hash.
- Referenced evidence must include immutable digest binding.

3. Policy determinism
- Policy evaluation must produce deterministic decision trace payloads.
- Version policies and include policy ID in decision docs.

4. Fail-closed behavior
- Missing required evidence -> deny (not warn-only) when policy requires it.
- Unresolvable keys under strict policy -> deny.

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

## Open Questions

1. Schema granularity: single attestation schema vs profile-specific schemas?
2. Embedded vs referenced evidence defaults by size and sensitivity?
3. Policy language format: JSON DSL vs Rego-style external engine?
4. Should transform receipts require deterministic function identity hash at v1?

## Summary

This plan does not replace JACS. It extends JACS.

- JACS remains the canonical document/signature substrate.
- Universal adapter capability is introduced as an additive attestation layer.
- The outcome is better cross-boundary trust decisions with explicit, portable evidence.
