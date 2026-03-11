# W3C AI Agent Protocol Notes

**Date:** March 2026
**Audience:** Public / standards-facing

## Purpose

This note captures a public-facing JACS position on the W3C CG AI Agent Protocol work.

The short version:

- JACS is aligned with the W3C effort's goals.
- JACS is not a drop-in implementation of the current draft.
- JACS already implements several security and provenance features the draft needs.
- The right path is interoperability and contribution, not a rewrite of JACS around a still-moving draft.

## What JACS Can Credibly Say Today

JACS can say all of the following without overstating conformance:

1. JACS already provides cryptographic agent identity, signed artifacts, offline verification, trust policy, replay hardening, audit trails, and evidence-backed attestations.
2. JACS already integrates with A2A and MCP, which makes it useful at real agent boundaries today.
3. JACS does not yet natively implement the current W3C draft's `did:wba` identity model, JSON-LD agent descriptions, `.well-known/agent-descriptions` discovery pattern, or DID-based authorization header format.
4. JACS can help the W3C work by contributing practical implementation guidance for provenance, attestation, offline verification, trust policy, and multi-party authorization.

## Public Message

Suggested short public statement:

> JACS is aligned with the W3C AI Agent Protocol effort, but it is not yet an implementation of the current draft. JACS already ships strong cryptographic identity, signed artifacts, offline verification, trust policies, and attestations. We see JACS as a practical provenance and trust layer that can interoperate with emerging W3C discovery and identity mechanisms such as `did:wba` and agent descriptions.

Suggested longer public statement:

> JACS supports many of the security goals the W3C AI Agent Protocol is trying to standardize: authentic agent identity, verifiable communication, human oversight records, and interoperable agent metadata. Today, JACS implements those capabilities through JACS agent documents, trust stores, DNS-backed verification, A2A Agent Cards, MCP tooling, signed artifacts, and structured attestations. That means JACS is directionally aligned, but it should not be described as implementing the current W3C draft as written.  
>
> The most useful role for JACS is to help ground the W3C work in deployable security primitives: offline verification, provenance carried with artifacts, evidence-backed attestations, replay resistance, and multi-party authorization. We expect the right engineering path to be a compatibility layer that lets JACS emit W3C-facing identity and discovery formats without replacing the JACS trust and provenance model that already works.

## What JACS Already Offers That Is Relevant

- Cryptographic agent identity and signed agent documents
- Signed artifacts and messages with integrity protection
- Offline verification
- Replay defenses and signature freshness checks
- Trust-store and policy-based admission
- Human, human-org, hybrid, and AI agent types
- Service metadata, contact metadata, and privacy-policy fields
- A2A discovery and signed Agent Cards
- MCP tooling for identity, trust, audit, and artifact operations
- Structured attestation with claims, evidence references, derivation chains, and DSSE export
- Quorum-based multi-agent agreement flows

## Where JACS Does Not Yet Match The Draft

- No native `did:wba` issuance, resolution, or DID document toolchain in core
- No native W3C JSON-LD agent description exporter
- No `.well-known/agent-descriptions` endpoint generator
- No DID-based authorization header format
- Current HTTP adapters mostly verify signed request bodies, not a W3C-style auth header
- Current auth helper signs only `jacs_id:timestamp`, which is weaker than a fuller request-binding proof

## What JACS Should Offer To The W3C Discussion

JACS should contribute a few concrete positions:

1. Identity/discovery and provenance should be separate layers.
   `did:wba` can identify and route an agent; JACS can carry signed provenance on the artifacts themselves.

2. Offline verification should remain a first-class property.
   The draft should not force every meaningful trust decision to depend on online resolution.

3. Attestation needs to be structured and machine-readable.
   Signed identity alone is not enough for higher-trust workflows.

4. Trust policy belongs above raw cryptographic verification.
   "Valid signature" and "allowed actor" are different questions.

5. Human oversight should include durable records.
   Human review, approval, or delegation should produce verifiable artifacts, not just UI state.

6. Multi-party authorization is worth standardizing.
   Some agent actions should require M-of-N approval, not just a single signer.

## Messaging Guardrails

Do say:

- "Aligned with the goals"
- "Can interoperate with"
- "Can help implement or inform"
- "Already ships provenance and attestation primitives"
- "Not yet a full implementation of the current W3C draft"

Do not say:

- "JACS is the W3C AI Agent Protocol"
- "JACS already supports `did:wba` natively"
- "JACS already emits W3C agent descriptions"
- "JACS is wire-compatible with the current draft"

## Recommended Position

The best public position is:

- JACS should support the W3C draft where it stabilizes.
- JACS should not throw away its existing identity, provenance, attestation, and trust model to chase early draft churn.
- JACS should present itself as an implementation partner and security reference point, not as a competing total replacement.
