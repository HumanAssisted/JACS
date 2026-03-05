# ATTESTATION_A2A_RESOLUTION

Last updated: 2026-03-05  
Status: PROPOSED  
Scope: JACS core, binding-core, jacspy, jacsnpm, docs/jacsbook

## Purpose

Resolve redundancy and confusion between:

1. JACS agent identity/signing model
2. A2A interoperability model
3. Attestation evidence model

This document is a combined PRD/TRD focused on:

- DRY architecture (single-source trust/verification behavior)
- Better developer experience (one obvious path, consistent outputs, predictable docs)

## Executive Summary

Current behavior is functionally strong but conceptually overlapping:

- "Agent" is used for both identity and protocol roles.
- A2A chain-of-custody and attestation derivation both represent provenance history.
- Trust semantics differ across A2A policy checks and attestation verification.
- Verification status fidelity in core is flattened in wrappers.
- Similar APIs are exposed in multiple layers, creating "which one should I use?" friction.

### Resolution Direction

1. Keep all three concepts, but enforce strict layer boundaries.
2. Promote one canonical developer path per use case.
3. Consolidate trust + verification policy logic into core/binding-core contracts.
4. Keep convenience APIs, but document them as aliases/shorthands, not separate models.
5. Normalize result schemas across Python/Node so status and trust are explicit, not inferred.

## Problem Statement

## Observed Confusions

1. **Agent term overload**
- Core identity definition: [concepts.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/getting-started/concepts.md:7)
- A2A framing: [README.md](/Users/jonathan.hendler/personal/JACS/README.md:168)
- Integration layering statement: [what-is-jacs.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/getting-started/what-is-jacs.md:131)

2. **Provenance model overlap**
- A2A parent signature chain: [a2a.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/integrations/a2a.md:11)
- Attestation derivation chain: [attestation.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/getting-started/attestation.md:35)

3. **Trust semantics split**
- A2A policy = admission control: [a2a.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/integrations/a2a.md:88)
- Attestation verification = evidence/claim validation: [attestation.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/getting-started/attestation.md:16)

4. **API surface duplication**
- Python A2A helpers duplicated at client + integration + adapter layers:
  - [client.py](/Users/jonathan.hendler/personal/JACS/jacspy/python/jacs/client.py:711)
  - [client.py](/Users/jonathan.hendler/personal/JACS/jacspy/python/jacs/client.py:735)
  - [base.py](/Users/jonathan.hendler/personal/JACS/jacspy/python/jacs/adapters/base.py:172)
- Node equivalents:
  - [client.ts](/Users/jonathan.hendler/personal/JACS/jacsnpm/client.ts:953)
  - [client.ts](/Users/jonathan.hendler/personal/JACS/jacsnpm/client.ts:964)

5. **Status fidelity mismatch**
- Core exposes `VerificationStatus` with `Verified`, `SelfSigned`, `Unverified`, `Invalid`:
  - [provenance.rs](/Users/jonathan.hendler/personal/JACS/jacs/src/a2a/provenance.rs:23)
- Wrappers often reduce this to boolean-valid flows:
  - [a2a.py](/Users/jonathan.hendler/personal/JACS/jacspy/python/jacs/a2a.py:737)
  - [a2a.ts](/Users/jonathan.hendler/personal/JACS/jacsnpm/a2a.ts:757)

6. **Alias sprawl**
- `wrap_a2a_artifact` vs `sign_artifact` aliases are present across layers:
  - [simple.rs](/Users/jonathan.hendler/personal/JACS/jacs/src/simple.rs:2929)
  - [binding-core lib.rs](/Users/jonathan.hendler/personal/JACS/binding-core/src/lib.rs:1173)

## Impact

- New users struggle to choose APIs.
- Existing users misinterpret verification outcomes (`unverified` vs `invalid`).
- Wrapper maintenance repeats policy logic.
- Docs must repeatedly explain the same distinctions.

## Goals (PRD)

1. Define one explicit trust/provenance mental model for JACS.
2. Make "one obvious path" clear for common tasks:
- Sign/verify only
- A2A exchange
- Attestation evidence
3. Remove duplicated policy logic across wrappers.
4. Preserve backward compatibility while reducing conceptual redundancy.
5. Achieve consistent verification/trust output schemas across Python/Node.

## Non-Goals

1. Replacing A2A protocol with a JACS-specific transport.
2. Removing attestation or A2A features.
3. Breaking existing API calls in one release.
4. Introducing blockchain/DID dependencies into this resolution.

## Product Requirements (PRD)

## PR-1: Canonical Layer Model

Publish and enforce this model across README + jacsbook:

1. **Layer A: Identity + Integrity (JACS Core)**
- `agent`, `sign_message`, `verify`
- "Who signed what"

2. **Layer B: Exchange + Discovery (A2A Integration)**
- agent card, discovery, wrapped artifact exchange, trust policy admission
- "How artifacts move across boundaries"

3. **Layer C: Trust Context (Attestation)**
- claims/evidence/derivation/DSSE
- "Why the artifact should be trusted"

Requirement:
- Each API and doc page must map to exactly one primary layer.

## PR-2: One Obvious Entry Path Per Use Case

Standardized guidance:

1. Sign/verify only: `JacsClient.sign_message` + `verify` or standalone verify.
2. A2A exchange: `client.get_a2a()` / `getA2A()` as canonical entry.
3. Attestation: `create_attestation` / `verify_attestation`.

Convenience methods remain, but docs mark them as aliases/shorthands.

## PR-3: Trust Language Unification

Standard terms:

- **Crypto status**: verified/self_signed/unverified/invalid
- **Policy status**: allowed/blocked/not_assessed
- **Attestation status**: local_valid/full_valid + evidence/chain detail

Requirement:
- No docs should use "trusted" to mean cryptographic validity alone.

## PR-4: Verification Result Contract

All wrappers must return:

1. Crypto status (enum/string)
2. Boolean compatibility field (`valid`) for legacy behavior
3. Policy/trust assessment block when requested
4. Parent-chain verification detail

No synthetic trust derivation from artifact type alone.

## PR-5: Documentation IA Cleanup

Add a single decision page that directs users to:

1. Sign
2. A2A
3. Attestation
4. A2A + Attestation combined

Deprecate duplicated explanatory text across pages by linking to the canonical "Trust Layers" page.

## Technical Requirements (TRD)

## TR-1: Single Verification Source of Truth

Use core/binding-core verification outputs as authoritative.

### Current
- Core returns detailed `VerificationStatus`:
  - [provenance.rs](/Users/jonathan.hendler/personal/JACS/jacs/src/a2a/provenance.rs:23)
- Wrappers sometimes recompute validity via `verify_response` and local logic.

### Target

1. Wrapper A2A verification must consume canonical verification JSON from:
- `verify_a2a_artifact` in binding-core:
  - [binding-core lib.rs](/Users/jonathan.hendler/personal/JACS/binding-core/src/lib.rs:1186)
2. Do not derive status with wrapper-local heuristics.
3. Preserve fields:
- `status`
- `valid`
- signer metadata
- parent verification results

## TR-2: Single Trust Policy Evaluator

### Current
- Python and Node each implement policy checks locally:
  - [a2a_discovery.py](/Users/jonathan.hendler/personal/JACS/jacspy/python/jacs/a2a_discovery.py:272)
  - [a2a.ts](/Users/jonathan.hendler/personal/JACS/jacsnpm/a2a.ts:511)

### Target

1. Prefer binding-core `assess_a2a_agent` everywhere:
- [binding-core lib.rs](/Users/jonathan.hendler/personal/JACS/binding-core/src/lib.rs:1210)
2. Policy decision input must be an actual Agent Card (or explicitly absent).
3. If no Agent Card is provided, return `policy_status = not_assessed`; do not fabricate card-derived trust.

## TR-3: Result Schema Normalization

Introduce a cross-language schema for A2A verification:

```json
{
  "status": "Verified|SelfSigned|Unverified|Invalid",
  "valid": true,
  "signerId": "uuid",
  "signerVersion": "uuid",
  "artifactType": "a2a-task",
  "timestamp": "RFC3339",
  "originalArtifact": {},
  "parentSignaturesValid": true,
  "parentVerificationResults": [],
  "trust": {
    "policy": "open|verified|strict|null",
    "status": "allowed|blocked|not_assessed",
    "reason": "string"
  }
}
```

Compatibility:
- Keep existing `valid` behavior.
- Add normalized fields; deprecate shape divergences with warnings.

## TR-4: API Surface DRY Policy

### Keep

1. High-level convenience aliases in `JacsClient`.
2. Integration-specific class (`JACSA2AIntegration`).

### Enforce

1. Canonical docs mention only one primary API per action.
2. Alias methods explicitly tagged "convenience alias."
3. No feature logic divergence between alias and canonical path.

## TR-5: A2A vs Attestation Composition Contract

Define formal composition:

1. A2A wrapped artifact may be used as attestation evidence.
2. A2A chain-of-custody remains transport provenance.
3. Attestation derivation remains trust-claim provenance.
4. Bridging rule:
- If both exist, A2A chain provides movement lineage; attestation derivation provides claim lineage.

Implementation note:
- Reuse existing A2A attestation adapter:
  - [attestation/adapters/a2a.rs](/Users/jonathan.hendler/personal/JACS/jacs/src/attestation/adapters/a2a.rs:1)
- Improve docs and output mapping; avoid claiming they are interchangeable.

## Proposed Documentation Changes

## New Pages

1. `jacs/docs/jacsbook/src/getting-started/trust-layers.md`
- Canonical layer model
- Terminology glossary
- Quick decision flow

2. `jacs/docs/jacsbook/src/guides/a2a-attestation-composition.md`
- How to use both in one workflow
- Examples for chain-of-custody + evidence

## Updated Pages

1. [README.md](/Users/jonathan.hendler/personal/JACS/README.md)
- Replace repeated boundary text with link to canonical layer page.

2. [integrations/a2a.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/integrations/a2a.md)
- Tighten A2A scope to exchange/discovery/trust policy.
- Add explicit "not attestation" section.

3. [getting-started/attestation.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/getting-started/attestation.md)
- Add explicit "not transport trust policy" section.

4. [guides/sign-vs-attest.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/guides/sign-vs-attest.md)
- Add branch for "cross-agent exchange" pointing to A2A.

5. [getting-started/decision-tree.md](/Users/jonathan.hendler/personal/JACS/jacs/docs/jacsbook/src/getting-started/decision-tree.md)
- Add combined path guidance: A2A + attestation.

## API and Code Changes (Planned)

## Core / binding-core

1. Expose policy-aware verify through binding-core:
- Add `verify_a2a_artifact_with_policy(wrapped_json, card_json, policy)` delegating to core policy verify.
2. Keep `verify_a2a_artifact` for crypto-only verify.
3. Ensure stable serialization names for status fields.

## Python (jacspy)

1. `JACSA2AIntegration.verify_wrapped_artifact(...)` should use binding-core verify output instead of direct boolean-only local verify.
2. `assess_remote_agent` should prefer binding-core trust assessment.
3. Remove synthetic-card trust inference from artifact type.
4. Keep current method names; add deprecation warnings only if output keys change.

## Node (jacsnpm)

1. `verifyWrappedArtifact(...)` should consume canonical core status.
2. `assessRemoteAgent(...)` should use binding-core trust logic.
3. Do not auto-set `jacsRegistered` purely from successful signature.
4. Keep existing method names; normalize output fields.

## DRY Rule Enforcement

All policy logic must exist in one place (core/binding-core).  
Wrappers should orchestrate I/O and type conversion only.

## Backward Compatibility

## Compatibility Principles

1. No hard removals in first release.
2. Additive response fields first; legacy fields preserved.
3. Deprecation notices for non-canonical aliases.
4. Minimum two minor releases before alias removal.

## Alias Policy

1. `sign_artifact` remains canonical.
2. `wrap_*` methods stay as deprecated aliases.
3. Docs stop using deprecated names immediately after rollout.

## Migration Plan

## Phase 0: Baseline and Contracts

Status: NOT_DONE

1. Define normalized verification/trust result schema in docs + tests.
2. Add contract tests for Python/Node wrappers against same fixtures.

Exit criteria:
- Contract tests fail before implementation and pass after.

## Phase 1: Core and Binding Consolidation

Status: NOT_DONE

1. Add binding-core policy-aware verify API.
2. Ensure serialized fields are stable and documented.
3. Add fixtures for:
- self-signed
- foreign verified
- foreign unverified (missing key)
- invalid signature
- trust blocked by policy

Exit criteria:
- `cargo test -p jacs`
- `cargo test -p binding-core`

## Phase 2: Wrapper Alignment

Status: NOT_DONE

1. Update jacspy A2A verify + trust to consume canonical outputs.
2. Update jacsnpm A2A verify + trust similarly.
3. Preserve legacy fields + add normalized fields.

Exit criteria:
- Python A2A tests pass:
  - `jacspy/tests/test_a2a*.py`
  - `jacspy/tests/test_client_a2a.py`
- Node A2A tests pass:
  - `jacsnpm/test/a2a*.test.js`
  - `jacsnpm/test/client-a2a.test.js`

## Phase 3: Docs and DevEx Simplification

Status: NOT_DONE

1. Publish Trust Layers page.
2. Update README + A2A + Attestation + decision tree.
3. Remove repeated boundary explanations in favor of canonical cross-links.

Exit criteria:
- All docs examples compile/run in CI snippets.
- No contradictory definition of trust states across docs.

## Phase 4: Deprecation Messaging

Status: NOT_DONE

1. Mark deprecated aliases in API docs with explicit timeline.
2. Emit runtime warnings where safe.

Exit criteria:
- Clear migration notes in changelog + migration guide.

## Test Strategy

## Contract Tests (Required)

For both Python and Node:

1. Given same wrapped artifact fixture:
- status must match core (`Verified/SelfSigned/Unverified/Invalid`)
- `valid` must match status-derived expected value
2. Given same Agent Card + policy:
- trust decision must match core assessment
3. Parent chain verification must match.

## Regression Tests

1. Existing A2A behavior remains functional.
2. Existing attestation behavior remains functional.
3. Cross-language A2A interop still passes.

## Documentation Tests

1. Decision-tree examples resolve to real APIs.
2. No page claims A2A trust policy validates attestation evidence freshness.
3. No page conflates `unverified` with `invalid`.

## Success Metrics

1. Reduce docs duplication:
- At least 30% reduction in repeated boundary explanations across README + A2A + attestation pages.

2. Improve API clarity:
- One canonical method shown per common task in docs (aliases moved to reference sections).

3. Improve correctness perception:
- Zero known cases where missing-key verification is interpreted as invalid signature in wrapper outputs.

4. Lower support burden:
- Fewer "which API should I use?" issues/PR comments for A2A vs attestation topics.

## Risks and Mitigations

1. **Risk:** Consumers depend on current output field names.
- Mitigation: additive fields first, deprecate later, maintain `valid`.

2. **Risk:** Trust assessment requires remote Agent Card availability.
- Mitigation: explicit `not_assessed` status and reason when card unavailable.

3. **Risk:** Wrapper refactors diverge again over time.
- Mitigation: shared contract tests + policy logic centralized in binding-core.

4. **Risk:** Docs drift from implementation.
- Mitigation: doc snippet tests and release checklist item for Trust Layers consistency.

## Open Decisions

1. Should policy-aware verify require Agent Card input always, or allow optional lookup by signer ID?
2. Should normalized status strings be enum-cased (`Verified`) or lowercase (`verified`) at wrapper layer?
3. Should deprecated alias warnings be opt-out via env var to avoid noisy production logs?

## Definition of Done

This initiative is complete only when all are true:

1. Canonical layer model published and referenced by README + key guides.
2. Wrapper A2A verify/trust outputs are contract-consistent and status-rich.
3. Trust policy logic is centralized (no divergent wrapper-local logic).
4. Alias/canonical API guidance is explicit, with migration notes.
5. Core + binding + wrapper A2A/attestation test suites pass.
