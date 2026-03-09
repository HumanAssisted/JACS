# Response to NIST CAISI Request for Information: Security Considerations for Artificial Intelligence Agents

**Docket Number:** NIST-2025-0035
**Federal Register Document:** 2026-00206
**Submitted by:** HAI.AI / JACS Project
**Date:** March 2026
**Contact:** Jonathan Hendler, jonathan@hai.io, HAI.AI
**Website:** https://github.com/HumanAssisted/JACS

---

## 1. Respondent Identification

HAI.AI develops and maintains JACS (JSON Agent Communication Standard), an open-source cryptographic framework for AI agent identity, signed communication, and verifiable attestation. JACS is implemented in Rust with production bindings for Python, Node.js, and Go. The project is currently at version 0.9.2 with over 1,000 tests across 5 language targets.

JACS addresses the core challenge NIST identifies in this RFI: the need for security controls that are native to AI agent systems rather than bolted on from traditional software security. Our framework provides cryptographic agent identity, non-repudiable action signing, multi-agent agreement protocols with quorum-based authorization, and a structured attestation system for evidence-backed trust decisions.

This response draws on practical experience building and deploying these capabilities across the HAI.AI platform, where registered agents receive cryptographically verified identities and participate in evaluated conversations and benchmarks.

### What Makes JACS Different

Most AI agent security proposals describe architectures. JACS ships working code. Key differentiators:

1. **Decentralized-first:** No certificate authority, no registration server, no central identity provider required. Agents create key pairs and start signing immediately. Trust is additive — organizations can layer DNS-based verification, trust stores, and attestation policies on top of the decentralized foundation without changing the core protocol.

2. **Verification works offline:** Every JACS operation — agent creation, signing, verification, multi-agent agreement, attestation — works without network connectivity. This is a hard requirement for air-gapped environments, edge deployments, and scenarios where the verifying party has no relationship with the signing party's infrastructure.

3. **Developer experience as a security multiplier:** Security controls that are hard to adopt don't get adopted. JACS provides a `quickstart()` one-liner in Python, Node.js, and Rust CLI that creates a persistent agent with keys in under 100ms. Framework adapters for LangChain, FastAPI, CrewAI, and the Anthropic SDK allow developers to add cryptographic signing to existing agent code with 1-3 lines of change. The MCP server exposes all 33 JACS tools to any MCP client, meaning AI assistants can use JACS without any code integration at all.

4. **Post-quantum from day one:** ML-DSA-87 (NIST FIPS 204) is not a roadmap item — it ships today alongside Ed25519 and ECDSA. Agreement protocols can enforce minimum algorithm strength, ensuring that sensitive multi-agent authorizations use post-quantum signatures even if individual agents support classical algorithms.

5. **A2A protocol integration:** JACS extends Google's Agent-to-Agent protocol with cryptographic provenance. Agent Cards carry JACS extensions, artifacts are signed with chain-of-custody tracking, and trust assessment is built into the discovery flow. This bridges the gap between A2A's transport-level protocol and the cryptographic identity layer that multi-agent systems need.

---

## 2. Topic 1: Security Threats, Risks, and Vulnerabilities

### 2.1 Agent Identity Spoofing and Impersonation

The most fundamental threat to multi-agent systems is the inability to reliably distinguish one agent from another. Without cryptographic identity, any component can claim to be any agent, and downstream consumers have no mechanism to verify the claim.

**JACS's approach:** Every JACS agent generates a cryptographic key pair (Ed25519, ECDSA P-256/P-384, or post-quantum ML-DSA-87) at creation time. The public key becomes part of the agent's verifiable identity document. All actions produce signed artifacts that can be verified by any party holding the public key, without requiring a centralized authority or online verification service.

**Concrete example:** In a multi-agent financial approval workflow, Agent A signs a recommendation, Agent B signs a review, and Agent C signs the final approval. Each signature binds the action to a specific agent identity. If an attacker substitutes a forged Agent B review, the signature verification fails immediately -- the downstream agent (or any auditor) detects the forgery without contacting a central server.

### 2.2 Data Integrity Tampering in Multi-Agent Workflows

When agents pass data between each other, any intermediate component can modify the payload. Without integrity guarantees, a compromised relay can alter agent outputs, inject false data, or selectively drop information.

**JACS's approach:** Every JACS-signed document includes a SHA-256 content hash computed over the JSON Canonicalization Scheme (RFC 8785) representation of the document. The hash is included in the signed envelope, binding the content to the signature. Any modification to the document body invalidates both the hash and the signature.

### 2.3 Replay Attacks

An attacker who captures a legitimate signed message can replay it in a different context -- for example, re-submitting an approved transaction or replaying a stale authorization.

**JACS's approach:** JACS documents include unique identifiers (`jacsId`) and version counters (`jacsVersion`), along with timestamps. The combination of unique ID, version, and temporal context makes replay attacks detectable. The agreement protocol additionally uses nonce-based challenge-response to prevent replay of multi-party authorization flows.

### 2.4 Trust Boundary Violations

In systems with multiple agents of varying trustworthiness, an untrusted agent may attempt actions that should require higher trust levels. Without explicit trust boundaries, privilege escalation occurs silently.

**JACS's approach:** JACS implements a three-tier progressive trust model:
- **Open:** Accept any signed document (verify signature only)
- **Verified:** Require the signer's public key to be in a local trust store and optionally DNS-anchored
- **Strict:** Require verified identity plus policy compliance (attestation-level trust)

These trust levels are enforced at verification time, not just at the API boundary, meaning that every document carries its trust requirements with it.

### 2.5 Lack of Provenance in Agent Outputs

When an AI agent produces an output, downstream consumers currently cannot determine: what inputs the agent used, what transformation it applied, whether a human reviewed the result, or what evidence supports the output's trustworthiness.

**JACS's approach:** JACS attestations extend signed documents with structured claims, evidence references, and derivation chains. An attestation answers not just "WHO signed this?" but "WHO signed this and WHY should it be trusted?" Evidence can reference A2A protocol exchanges, email verifications, JWT tokens, or custom evidence sources, each with content-addressable digests and freshness timestamps.

---

## 3. Topic 2: Security Practices and Controls

This is where JACS has the most direct contribution. JACS implements multiple security practices that directly address the controls NIST is exploring.

### 3.1 Cryptographic Agent Identity

**What it is:** Each JACS agent is created with a cryptographic key pair. The agent document -- a signed JSON file containing the agent's identity, capabilities, and public key -- serves as a verifiable credential.

**Implementation details:**
- **Algorithms:** Ed25519 (via ring), ECDSA P-256/P-384 (via ring), and ML-DSA-87 post-quantum signatures (via the `pqcrypto` crate, NIST FIPS 204)
- **Key management:** Private keys are encrypted at rest using AES-256-GCM with PBKDF2 key derivation (600,000 iterations per OWASP 2024 recommendations)
- **Key rotation:** Agents can rotate keys while maintaining identity continuity through signed rotation records
- **Decentralized:** No certificate authority, no PKI infrastructure, no central identity registry required. Agents can verify each other directly.

**Why this matters for NIST's standardization effort:** Cryptographic agent identity should be a foundational requirement, not an optional feature. Without it, all higher-level security controls (authorization, audit, non-repudiation) rest on unverifiable claims.

### 3.2 Non-Repudiable Action Signing

**What it is:** Every agent action (document creation, message signing, agreement participation) produces a cryptographically signed artifact. The signature binds the action to the agent's identity and the specific content.

**Implementation details:**
- Documents are signed using the agent's private key over a canonical JSON representation (JCS, RFC 8785)
- Each signed document includes: agent signature, content hash (SHA-256), unique document ID, version, timestamp, and schema reference
- Signatures can be verified offline without any network connectivity
- Cross-language interoperability: documents signed in Rust can be verified in Python, Node.js, or Go (validated by 35+ cross-language tests)

**Performance:** Signing and verification complete in under 1ms for Ed25519 (benchmarked). ML-DSA-87 (the default algorithm) adds approximately 2-3ms for signing — fast enough for real-time agent workflows.

### 3.3 Multi-Agent Agreement with Quorum Authorization

**What it is:** JACS provides a protocol for multi-agent authorization where M-of-N agents must sign before an action is authorized. This implements least-privilege and separation-of-duty controls natively in the agent system.

**Implementation details:**
- `AgreementOptions` struct supports: timeout (ISO 8601 duration), quorum (M-of-N), required algorithms, and minimum cryptographic strength
- Quorum failure is a hard error -- partial signing does not produce a valid agreement
- Each party's signature is independently verifiable
- Tampered signatures or bodies are detected by any verifying party

**Concrete example:** A 3-agent approval chain where 2-of-3 must sign before a financial transaction proceeds. If Agent 2's signature is tampered with after signing, verification fails. If only 1-of-3 signs before the timeout, the agreement fails with a clear quorum-not-met error.

### 3.4 Signed Attestation for Verifiable Trust Decisions

**What it is:** JACS attestations extend the signing model with structured claims, evidence references, and derivation chains. An attestation answers: who attested, what they attested to, what evidence supports the attestation, and how the attested output was derived.

**Key concepts:**
- **Claims:** Named assertions with values, confidence scores (0.0-1.0), and categorical assurance levels (self-asserted, verified, independently-attested)
- **Evidence references:** Content-addressable references to external proofs (A2A exchanges, email verifications, JWT tokens, custom evidence) with freshness timestamps
- **Derivation chains:** Transform receipts that prove what inputs an agent consumed, what function it applied, and what output it produced -- with depth-limited chain verification (default: 10)
- **Two-tier verification:** Local tier (crypto + hash, <1ms) for hot-path validation; Full tier (crypto + evidence + derivation chain) for audit

**Schema:** Single JSON schema (`attestation.schema.json`) validated against all attestation documents. Uses `jacsType` field to distinguish profiles (attestation, attestation-transform-receipt, attestation-policy-decision).

### 3.5 Auditing and Immutable Document History

**What it is:** JACS documents are versioned and signed. Each version references the prior version, creating an append-only history that any auditor can traverse.

**Implementation details:**
- Documents have `jacsId` (stable identity) and `jacsVersion` (monotonic version counter)
- Editable documents (`jacsLevel: "editable"`) produce new signed versions; raw documents (`jacsLevel: "raw"`) are immutable after creation
- Storage backends support SQLite (default), DuckDB, Redb, SurrealDB, and Rusqlite -- all maintaining the same versioned document semantics
- The complete history is cryptographically linked: each version's hash includes the prior version reference

### 3.6 Trust Store and DNS-Based Key Distribution

**What it is:** Agents maintain a local trust store of public keys they have explicitly chosen to trust. Keys can also be published and retrieved via DNS TXT records, enabling decentralized key distribution without a central authority.

**Implementation details:**
- Trust/untrust operations are explicit agent actions
- DNS-based key lookup uses DNSSEC-validated TXT records
- No trust-on-first-use (TOFU) by default in verified/strict modes
- Trust decisions are auditable (logged as structured tracing events)

### 3.7 Post-Quantum Cryptographic Readiness

**What it is:** JACS supports ML-DSA-87 (NIST FIPS 204) for post-quantum digital signatures alongside classical Ed25519 and ECDSA algorithms.

**Why this matters now:** Agent identities may be long-lived. Documents signed today may need to be verified years from now. Harvest-now-decrypt-later attacks mean that quantum-vulnerable signatures on agent identity documents are a present-day risk, not a future concern.

**Implementation:** The `pq2025` algorithm in JACS uses ML-DSA-87, the strongest parameter set in NIST's finalized ML-DSA standard. It is the **default algorithm** for all new agents — post-quantum is opt-out, not opt-in. Key generation, signing, and verification all use this algorithm. Post-quantum keys are managed with the same PBKDF2/AES-256-GCM protection as classical keys.

### 3.8 Feature-Flagged Incremental Adoption

**What it is:** JACS uses Cargo feature flags to allow incremental adoption. Organizations can start with basic signing (`default` features), add attestation (`attestation` feature), add specific storage backends (`duckdb-storage`, `redb-storage`, etc.), and add specific evidence adapters -- all without requiring a monolithic deployment.

This approach aligns with NIST's emphasis on practical, deployable security controls that can be adopted incrementally.

### 3.9 Developer Experience as a Security Practice

**What it is:** Security controls that are difficult to adopt do not get adopted. JACS treats developer experience as a first-class security concern — the fastest path for a developer should also be the secure path.

**Implementation details:**
- **One-line quickstart:** `JacsClient.quickstart()` (Python/Node.js) or `jacs quickstart` (CLI) creates a persistent agent with post-quantum keys, encrypted private key, and a signed agent document — in under 100ms, with zero configuration
- **Framework adapters:** Drop-in integrations for LangChain, FastAPI, CrewAI, and the Anthropic SDK add cryptographic signing to existing agent code with 1-3 lines of change. A LangChain tool call becomes a signed tool call by adding a single decorator.
- **MCP server:** All 33 JACS tools are available through the Model Context Protocol. An AI assistant can sign documents, verify artifacts, manage trust stores, and create attestations through standard MCP tool calls — no library integration required.
- **A2A integration:** Every JACS agent is automatically an A2A agent. `client.export_agent_card()` produces a standards-compliant Agent Card with JACS provenance extensions. Discovery, trust assessment, and signed artifact exchange are built into the A2A module.
- **Instance-based multi-agent API:** `JacsClient` supports multiple concurrent agent instances in the same process. Each instance manages its own keys, trust store, and signing context. This enables realistic multi-agent testing and development without separate processes or containers.

**Why this matters for NIST's standardization effort:** The gap between "specified" and "deployed" is almost always a developer experience gap. Standards that require complex setup, configuration ceremonies, or specialized infrastructure face slow adoption. JACS demonstrates that strong cryptographic controls can be made accessible without sacrificing security properties.

### 3.10 A2A Protocol Integration with Cryptographic Provenance

**What it is:** JACS extends Google's Agent-to-Agent (A2A) protocol with cryptographic document provenance, bridging A2A's transport-level protocol with the identity and integrity guarantees that multi-agent systems require.

**Implementation details:**
- **Agent Card extensions:** JACS agents declare the `urn:jacs:provenance-v1` extension in their Agent Card, enabling JACS-aware agents to discover each other through standard A2A discovery
- **Well-known endpoints:** JACS serves 5 endpoints for A2A discovery: agent card, JWK set, JACS agent descriptor, public key, and extension descriptor
- **Artifact signing with chain of custody:** A2A artifacts (tasks, messages) are signed with JACS provenance. Parent signatures enable chain-of-custody tracking across multi-agent workflows.
- **Trust assessment:** JACS provides three trust policies for A2A interactions — open (any agent), verified (JACS extension required), and strict (trust store required) — enabling progressive trust enforcement
- **Evidence adapter:** A2A protocol exchanges are normalized into JACS attestation evidence, enabling cryptographic proof chains that span A2A interactions

---

## 4. Topic 3: Evaluation and Assessment

### 4.1 Structured Verification APIs

JACS verification returns structured results, not just boolean pass/fail. The `AttestationVerificationResult` includes:

```
{
  "valid": boolean,           // Overall result
  "crypto": {
    "signature_valid": boolean,  // Signature matches content
    "hash_valid": boolean,       // Hash matches content
    "signer_id": string,         // Who signed
    "algorithm": string          // What algorithm was used
  },
  "evidence": [{               // Per-evidence verification (full tier)
    "kind": string,
    "digest_valid": boolean,
    "freshness_valid": boolean,
    "detail": string
  }],
  "chain": {                   // Derivation chain (full tier)
    "valid": boolean,
    "depth": number,
    "max_depth": number,
    "links": [...]
  },
  "errors": [string]           // Human-readable error messages
}
```

This structured output enables automated security evaluation: monitoring systems can watch for `signature_valid: false` events, compliance systems can enforce minimum `assurance_level` requirements, and audit systems can traverse `chain` links to reconstruct the full provenance of an agent output.

### 4.2 Cross-Language Test Suites

JACS validates interoperability through cross-language test suites:
- **Rust core:** 570+ tests (lib + integration + attestation + 4 storage backends)
- **Python bindings:** 265+ tests
- **Node.js bindings:** 283+ tests
- **Go bindings:** 111+ tests
- **Cross-language:** 35+ dedicated tests that sign in one language and verify in another

Total: over 1,200 tests across all targets.

These test suites serve as both quality assurance and specification-by-example. Any organization implementing the JACS protocol can use these tests to verify conformance.

### 4.3 Observability and Structured Logging

JACS emits structured `tracing` events for all security-relevant operations (sign, verify, agreement lifecycle, attestation create/verify). These events include OpenTelemetry-compatible span attributes, enabling integration with existing observability infrastructure.

**Example structured event:**
```
jacs::attestation::create event=attestation_created jacs_id=... jacs_type=attestation subject_type=Agent claims_count=3 evidence_count=1 has_derivation=false
```

### 4.4 Benchmarking

JACS includes benchmarks for:
- Sign/verify performance across all algorithms (Ed25519, ECDSA, ML-DSA-87)
- N-party agreement signing (2, 5, 10, 25 parties)
- Concurrent signing (10, 50, 100 concurrent operations)

These benchmarks provide concrete performance data for deployment planning and security assessment.

---

## 5. Topic 4: Deployment Environment Constraints

### 5.1 Offline Verification

JACS is designed for fully offline operation. No centralized infrastructure is required for:
- Agent creation and key generation
- Document signing
- Document verification (given the signer's public key)
- Multi-agent agreement execution
- Attestation creation and local-tier verification

This is critical for air-gapped environments, edge deployments, and scenarios where network connectivity is unreliable or untrusted.

### 5.2 Feature-Flagged Capabilities

JACS capabilities are modular through Cargo feature flags:
- `default`: Basic signing and verification
- `attestation`: Attestation creation and verification
- `duckdb-storage`, `redb-storage`, `surrealdb-storage`, `rusqlite-storage`: Storage backend choices
- No feature requires all other features -- organizations deploy only what they need

### 5.3 Agreement Protocols with Quorum

Multi-agent authorization via quorum provides a deployment-level control for constraining agent actions. An organization can require that sensitive operations need M-of-N agent approval, with configurable timeouts and algorithm requirements. This directly addresses NIST's interest in "constraining and monitoring an agent's access in its deployment environment."

### 5.4 MCP Integration

JACS provides a Model Context Protocol (MCP) server with 33 tools for signing, verification, trust management, A2A artifact operations, and attestation (including DSSE export). This allows any MCP-compatible client (including AI assistants and development tools) to use JACS signing and verification as native tool calls, without requiring direct library integration.

### 5.5 Cross-Platform Support

JACS builds and runs on:
- macOS (arm64, x86_64)
- Linux (x86_64, arm64)
- Windows (x86_64)

Prebuilt CLI binaries are available for all platforms via GitHub releases.

---

## 6. Recommendations for NIST

Based on our experience building and deploying cryptographic security controls for AI agent systems, we recommend the following priorities for NIST standardization:

### 6.1 Cryptographic Identity Should Be Mandatory

Any standard for AI agent security should require cryptographic identity for agents that take consequential actions. Without it, all other security controls (authorization, audit, non-repudiation) are built on unverifiable claims. The identity mechanism should:
- Support multiple cryptographic algorithms (classical and post-quantum)
- Not require centralized infrastructure
- Enable offline verification
- Support key rotation without identity loss

### 6.2 Agent Actions Should Produce Non-Repudiable Records

Every consequential agent action should produce a signed artifact that:
- Binds the action to a specific agent identity
- Includes a content integrity hash
- Is verifiable without contacting the signing agent or any central authority
- Can be audited at any point in the future

### 6.3 Multi-Agent Authorization Should Support Quorum

When multiple agents collaborate on a decision, the standard should support M-of-N quorum-based authorization with:
- Configurable quorum thresholds
- Timeout mechanisms
- Algorithm and strength requirements
- Clear failure semantics (partial signing is not authorization)

### 6.4 Standards Should Support Offline and Decentralized Verification

Requiring online verification services creates single points of failure and trust. Security standards should ensure that:
- Verification can occur without network connectivity
- No centralized notary or transparency service is required for basic verification
- Centralized services (when used) are additive, not required

### 6.5 Post-Quantum Readiness Should Be Addressed Now

Agent identity documents and signed artifacts may be long-lived. Standards should:
- Require support for NIST-standardized post-quantum algorithms (ML-DSA, ML-KEM)
- Encourage algorithm agility (support for multiple algorithms simultaneously)
- Address the transition period where both classical and post-quantum signatures may be needed

### 6.6 Attestation Should Be Structured and Machine-Readable

Trust decisions should be based on structured, machine-readable evidence rather than opaque assertions. Standards should define:
- A schema for attestation claims (what the agent claims about its output)
- A mechanism for evidence references (what supports the claims)
- A derivation chain format (how the output was produced from inputs)
- Two-tier verification (fast local check for hot paths, thorough check for audits)

### 6.7 Standards Should Prioritize Developer Adoption

Security standards that are difficult to implement face slow adoption regardless of their technical merit. Standards for AI agent security should:
- Define a "fast path" that provides strong defaults with minimal configuration (JACS demonstrates this: post-quantum signing is the default, not an opt-in)
- Specify integration points with existing frameworks (MCP, A2A, LangChain, FastAPI) rather than requiring bespoke infrastructure
- Support incremental adoption — organizations should be able to start with basic signing and add attestation, quorum authorization, and trust store management as their requirements mature
- Provide cross-language interoperability guarantees, since agent systems are inherently polyglot

### 6.8 A2A Protocol Interoperability Should Be a First-Class Concern

As agent-to-agent communication protocols mature (Google A2A, Anthropic MCP), security standards should ensure that cryptographic identity and signing work natively within these protocols, not as an afterthought. Standards should define:
- How agent identity credentials are expressed in Agent Cards and discovery protocols
- How signed artifacts flow through A2A message exchanges with chain-of-custody tracking
- Progressive trust policies that allow agents to enforce different security levels based on the sensitivity of the interaction

---

## 7. References

1. **JACS Open Source Repository:** https://github.com/HumanAssisted/JACS
2. **JACS Documentation:** https://docs.hai.ai (jacsbook)
3. **HAI.AI Platform:** https://hai.ai
4. **NIST FIPS 204 (ML-DSA):** https://csrc.nist.gov/pubs/fips/204/final
5. **RFC 8785 (JSON Canonicalization Scheme):** https://tools.ietf.org/html/rfc8785
6. **in-toto Specification:** https://in-toto.io
7. **DSSE (Dead Simple Signing Envelope):** https://github.com/secure-systems-lab/dsse
8. **SLSA (Supply-chain Levels for Software Artifacts):** https://slsa.dev
9. **IETF RATS (Remote ATtestation procedureS):** https://datatracker.ietf.org/wg/rats/about/
10. **OWASP PBKDF2 Recommendations (2024):** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

*This response represents the views of the HAI.AI / JACS project team and is based on practical experience developing and deploying cryptographic security controls for AI agent systems. All capabilities described are implemented and tested in the JACS codebase (v0.9.2, Apache 2.0 OR MIT license, 1,200+ tests across 5 language targets).*
