# JACS Trust Layers

JACS organizes trust into three distinct layers. Each layer has a clear scope and its own vocabulary. Understanding which layer you need prevents confusion between identity, transport policy, and evidentiary trust.

## The Three Layers

### Layer A: Identity + Integrity (JACS Core)

**Scope:** Who signed what, and has it been tampered with?

**APIs:** `sign_message()`, `verify()`, `verify_standalone()`

This is the foundation. Every JACS document carries a cryptographic signature that proves which agent created it and that the content hasn't changed. Layer A answers: *"Is this signature valid?"*

**Crypto status values:** `Verified` · `SelfSigned` · `Unverified` · `Invalid`

- **Verified**: Signature is valid and signer's key was resolved from a trusted source.
- **SelfSigned**: Signature is valid but signer is the same as verifier (no third-party trust).
- **Unverified**: Signature could not be checked because the signer's key was not available.
- **Invalid**: Signature check failed — the content was tampered with or the wrong key was used.

### Layer B: Exchange + Discovery (A2A Integration)

**Scope:** Is this agent allowed to communicate with me?

**APIs:** `sign_artifact()`, `verify_wrapped_artifact()`, `assess_remote_agent()`, `discover_agent()`

Layer B handles cross-boundary exchange between agents using the A2A protocol. It adds trust *policy* on top of Layer A's cryptographic status. Layer B answers: *"Should I accept artifacts from this agent?"*

**Policy status values:** `allowed` · `blocked` · `not_assessed`

Trust policies (`open`, `verified`, `strict`) control admission:

| Policy | Requirement |
|--------|------------|
| `open` | Accept all agents |
| `verified` | Agent must have the `urn:jacs:provenance-v1` extension |
| `strict` | Agent must be in the local trust store |

See [A2A Interoperability](../integrations/a2a.md) for full details.

### Layer C: Trust Context (Attestation)

**Scope:** Why should this data be trusted?

**APIs:** `create_attestation()`, `verify_attestation()`, `lift_to_attestation()`, `export_attestation_dsse()`

Layer C records the *reasoning* behind trust: claims, evidence, derivation chains, and assurance levels. Layer C answers: *"What evidence supports this data?"*

**Attestation status values:** `local_valid` · `full_valid`

- **local_valid**: Signature and hash are correct; claims are structurally valid.
- **full_valid**: All of the above, plus evidence digests verified and derivation chain intact.

See [What Is an Attestation?](attestation.md) for full details.

## Terminology Glossary

| Term | Layer | Meaning |
|------|-------|---------|
| Crypto status | A | Outcome of signature verification: `Verified`, `SelfSigned`, `Unverified`, `Invalid` |
| Policy status | B | Outcome of trust policy check: `allowed`, `blocked`, `not_assessed` |
| Attestation status | C | Outcome of attestation verification: `local_valid`, `full_valid` |
| Verified | A | Signature is valid and signer key was resolved |
| SelfSigned | A | Signature is valid but signer is the verifier |
| Unverified | A | Key not available — cannot check signature |
| Invalid | A | Signature check failed |
| Allowed | B | Agent passes the configured trust policy |
| Blocked | B | Agent does not pass the trust policy |
| Not assessed | B | No agent card provided — trust not evaluated |

## Quick Decision Flow

**"Which layer do I need?"**

1. **I just need to prove data hasn't been tampered with** → Layer A. Use `sign_message()` and `verify()`.
2. **I need to exchange signed data with other agents** → Layer B. Use `sign_artifact()` and A2A discovery. See the [A2A Quickstart](../guides/a2a-quickstart.md).
3. **I need to record WHY data should be trusted** → Layer C. Use `create_attestation()`. See the [Attestation Tutorial](../guides/attestation-tutorial.md).
4. **I need both exchange AND trust evidence** → Layer B + C. See [A2A + Attestation Composition](../guides/a2a-attestation-composition.md).

## Common Misconceptions

- **"Unverified" does not mean "Invalid."** Unverified means the signer's key wasn't available. Invalid means the signature check actively failed. These have very different security implications.
- **A2A trust policy is not attestation verification.** A2A policy (Layer B) answers "should I talk to this agent?" Attestation (Layer C) answers "why should I trust this data?" They compose but are not interchangeable.
- **"Trusted" is not the same as "Verified."** In JACS, "trusted" refers to trust store membership (Layer B). "Verified" refers to cryptographic signature validation (Layer A).
