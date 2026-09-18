# JACS Attestation vs. Other Standards

JACS occupies a unique position as an agent-layer attestation framework.
This page compares JACS with related standards and explains when to use
them together.

## Comparison Table

| Feature | JACS | in-toto / SLSA | Sigstore / cosign | SCITT | IETF RATS / EAT |
|---------|------|----------------|-------------------|-------|-----------------|
| **Primary domain** | AI agent runtime | Build provenance | Artifact signing | Transparency logs | Hardware/platform attestation |
| **Identity model** | Decentralized (key pairs) | Build system certs | Keyless (OIDC) | Issuer certs | Platform certs |
| **Agent-native** | Yes | No | No | No | Partial |
| **Offline verification** | Yes | Yes (with keys) | No (requires Rekor) | No (requires log) | Depends |
| **Multi-agent quorum** | Yes (M-of-N) | No | No | No | No |
| **Evidence normalization** | Yes (A2A, email, JWT, custom) | No | No | No | Partial (EAT claims) |
| **Transform receipts** | Yes (derivation chains) | Yes (build steps) | No | No | No |
| **Probabilistic claims** | Yes (confidence + assurance) | No | No | No | No |
| **Post-quantum** | Yes (ML-DSA-87) | No | No | No | Depends |
| **Central infrastructure** | Not required | Not required | Required (Fulcio + Rekor) | Required (transparency log) | Depends |
| **Schema format** | JSON Schema + JCS | in-toto layout | Sigstore bundle | SCITT receipt | CBOR/COSE |

## JACS vs. in-toto / SLSA

**Domain difference:** in-toto and SLSA focus on build provenance -- proving
that a software artifact was built by a specific builder from specific source
code. JACS focuses on runtime agent actions -- proving that a specific agent
performed a specific action with specific evidence.

**Interoperability:** JACS exports attestations as DSSE (Dead Simple Signing
Envelope) documents, the same format used by in-toto v1.0+. This means:

- A JACS attestation can include an in-toto predicate type URI
- SLSA verifiers can validate the DSSE envelope structure
- JACS and in-toto attestations can coexist in the same verification pipeline

**When to use both:** If your workflow includes both software builds (use
SLSA/in-toto for build provenance) and AI agent actions (use JACS for
runtime attestation), you can link them via derivation chains.

## JACS vs. Sigstore / cosign

**Domain difference:** Sigstore provides signing infrastructure (Fulcio CA,
Rekor transparency log) and cosign is a tool for signing container images
and artifacts. JACS provides its own signing with decentralized identity.

**Key difference:** Sigstore's keyless signing relies on centralized OIDC
identity providers and a public transparency log. JACS uses self-managed
key pairs and does not require any centralized infrastructure.

**When to use both:** Sigstore for container image signing in CI/CD
pipelines. JACS for AI agent action signing at runtime. A planned
Sigstore bundle verification adapter (N+2) would let JACS attestations
reference Sigstore signatures as evidence.

## JACS vs. SCITT

**Most overlap.** SCITT (Supply Chain Integrity, Transparency and Trust)
defines a centralized transparency service for recording signed statements
about artifacts.

**Key difference:** SCITT requires a transparency log (centralized notary).
JACS is fully decentralized and offline-capable. JACS verification works
without contacting any server.

**Complementary use:** JACS signs and attests. SCITT logs. An organization
could use JACS to create signed attestations and then submit them to a
SCITT transparency log for auditability, getting the benefits of both
decentralized creation and centralized discoverability.

## JACS vs. IETF RATS / EAT

**Layer difference:** RATS (Remote ATtestation procedureS) and EAT
(Entity Attestation Token) focus on hardware and platform attestation --
proving that a device or execution environment is in a known-good state.
JACS fills the software agent layer above hardware.

**Alignment opportunity:** JACS claim names could align with IANA-registered
EAT claim types where they overlap. A JACS attestation could reference a
RATS attestation result as evidence, creating a trust chain from hardware
to agent.

**IETF drafts of interest:**
- `draft-huang-rats-agentic-eat-cap-attest-00` -- Capability attestation
  for agents, directly aligned with JACS claims model
- `draft-messous-eat-ai-00` -- EAT profile for AI agents
- `draft-jiang-seat-dynamic-attestation-00` -- Dynamic attestation for
  runtime assertions

## JACS vs. CSA Agentic Trust Framework

The Cloud Security Alliance's Agentic Trust Framework defines progressive
trust levels that map directly to JACS's trust model:

| CSA Level | JACS Equivalent | Verification |
|-----------|----------------|--------------|
| None | No JACS | No signing |
| Basic | Open | Valid signature accepted |
| Standard | Verified | Trust store + DNS verification |
| Enhanced | Strict | Attestation-level evidence required |

## When to Use JACS

Use JACS when you need:

- **Agent identity** that works without PKI/CA infrastructure
- **Non-repudiable action logging** for AI agent workflows
- **Multi-agent authorization** with quorum (M-of-N approval)
- **Offline verification** without centralized services
- **Evidence-backed trust** that goes beyond simple signing
- **Post-quantum readiness** for long-lived agent identities

## When to Use JACS Alongside Other Tools

| Scenario | JACS + ... |
|----------|-----------|
| CI/CD pipeline with AI agents | JACS (agent actions) + SLSA (build provenance) |
| Enterprise with compliance requirements | JACS (signing) + SCITT (transparency log) |
| IoT/edge with hardware attestation | JACS (agent layer) + RATS/EAT (hardware layer) |
| Container-based agent deployment | JACS (runtime signing) + cosign (image signing) |
