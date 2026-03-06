# Response to NCCoE Concept Paper: Accelerating the Adoption of Software and AI Agent Identity and Authorization

**Submitted by:** HAI.AI / JACS Project
**Contact:** Jonathan Hendler, HAI.AI
**Submission:** AI-Identity@nist.gov
**Date:** March 2026
**Website:** https://github.com/HumanAssisted/JACS

---

## Executive Summary

JACS (JSON Agent Communication Standard) is an open-source cryptographic framework that directly addresses the core challenge posed by the NCCoE concept paper: how to securely identify and authorize AI agents operating across systems and data environments. JACS provides decentralized agent identity, non-repudiable action signing, multi-agent quorum authorization, and structured attestation -- all implemented in Rust with production bindings for Python, Node.js, and Go.

We propose JACS as a technology partner for the NCCoE demonstration project, with a specific scenario: a multi-agent financial approval workflow demonstrating cryptographic identity, signed attestations with evidence chains, quorum-based authorization, and a verifiable audit trail.

---

## 1. Use Cases for AI Agent Identity and Authorization

### 1.1 Multi-Agent Workflow with Cryptographic Provenance

**Scenario:** A financial institution uses three AI agents in sequence for trade approval: Risk Analysis (Agent A), Compliance Check (Agent B), and Final Approval (Agent C). Each agent must prove its identity, sign its output, and the final approval requires at least 2-of-3 agent signatures.

**How JACS addresses this:**
- Each agent is created with a unique cryptographic key pair (Ed25519, ECDSA, or post-quantum ML-DSA-87)
- Each agent's signed output includes a content-integrity hash (SHA-256 over JSON Canonicalization Scheme / RFC 8785)
- The approval step uses JACS's multi-agent agreement protocol with configurable quorum (M-of-N), timeout, and algorithm strength requirements
- The complete chain from input to approval is cryptographically linked and auditable

**Concrete capability:** JACS's `AgreementOptions` supports `quorum: {required: 2, total: 3}`, `timeout: "PT5M"` (5-minute window), and `required_algorithms: ["ring-Ed25519"]`. Partial signing (1-of-3) does not produce a valid authorization.

### 1.2 Cross-Organization Agent Trust Without Centralized Authority

**Scenario:** Organization A's procurement agent needs to interact with Organization B's supplier agent. Neither organization wants to depend on a shared identity provider or certificate authority.

**How JACS addresses this:**
- Each agent's public key is published via DNS TXT records (DNSSEC-validated)
- Agents discover each other's identities through standard DNS lookups
- Trust is established through explicit trust-store operations, not automatic trust-on-first-use
- All cross-organization interactions produce signed artifacts verifiable by either party offline

### 1.3 Audit-Ready Agent Action Logging with Non-Repudiation

**Scenario:** A compliance team needs to reconstruct what an AI agent did, when, and why -- six months after the fact.

**How JACS addresses this:**
- Every agent action produces a signed document with unique ID, version, timestamp, and content hash
- JACS attestations extend this with structured claims, evidence references, and derivation chains
- Verification is offline-capable: an auditor can verify any signed document using only the signer's public key
- Two-tier verification: local tier (crypto-only, <1ms) for real-time monitoring; full tier (evidence + chain) for compliance audits

### 1.4 A2A Protocol Integration with Verifiable Identity

**Scenario:** AI agents communicating via Google's Agent-to-Agent (A2A) protocol need verifiable identity and signed message exchange.

**How JACS addresses this:**
- JACS provides an A2A integration module that wraps agent cards with JACS signatures
- A2A messages carry cryptographic provenance (who sent it, was it modified)
- JACS's A2A evidence adapter normalizes A2A protocol exchanges into attestation evidence
- The Model Context Protocol (MCP) server provides 13+ JACS tools accessible to any MCP client

---

## 2. Technical Challenges Addressed

### 2.1 Decentralized Agent Identity Without PKI/CA Infrastructure

Traditional identity systems rely on certificate authorities, LDAP directories, or centralized identity providers. For AI agents that may be ephemeral, cross-organizational, or edge-deployed, centralized infrastructure is a bottleneck and single point of failure.

**JACS solution:** Self-sovereign key pairs with DNS-based key distribution. Agent creation requires no server, no registration, and no approval flow. Trust is established through explicit trust-store operations and can be anchored to DNS (DNSSEC) for organizational verification.

**Implementation:** Agent creation takes under 100ms. The resulting agent document is a self-contained signed JSON file containing the public key, identity metadata, and a cryptographic signature. This document can be verified by anyone with access to the public key, without contacting any server.

### 2.2 Post-Quantum Readiness for Long-Lived Agent Identities

Agent identity documents and signed artifacts may need to be verifiable years from now. Harvest-now-decrypt-later attacks mean that quantum-vulnerable signatures are a present-day risk.

**JACS solution:** ML-DSA-87 (NIST FIPS 204) support alongside Ed25519 and ECDSA. Algorithm agility: multiple algorithms can coexist, and key rotation preserves identity continuity. Agreement protocols can specify `required_algorithms` and `minimum_strength` to enforce post-quantum usage in sensitive contexts.

### 2.3 Offline Verification in Air-Gapped or Edge Deployments

Enterprise environments frequently include air-gapped networks, edge locations, and restricted connectivity zones. Security controls that require online verification create availability risks.

**JACS solution:** All JACS operations -- agent creation, signing, verification, multi-agent agreement, attestation creation, and local-tier attestation verification -- work fully offline. No centralized service, transparency log, or online verification endpoint is required.

### 2.4 Multi-Agent Agreement with Quorum-Based Authorization

When multiple agents collaborate on a decision, the authorization model must support collective approval, not just individual authentication.

**JACS solution:** Multi-agent agreements with `AgreementOptions` including quorum (M-of-N), ISO 8601 timeout, required algorithms, and minimum cryptographic strength. Quorum failure is a hard error: partial signing does not produce authorization. Each party's signature is independently verifiable. Tampered signatures or bodies are detected by any verifying party. Tested with 2, 5, 10, and 25 party scenarios.

### 2.5 Cross-Language Interoperability

Agent systems are polyglot by nature. Security controls must work consistently across implementation languages.

**JACS solution:** Core implementation in Rust with first-class bindings for Python (PyO3), Node.js (NAPI-RS), and Go (CGo). Cross-language interoperability validated by 35+ dedicated tests that sign in one language and verify in another. Total test count across all targets: 500+.

---

## 3. Standards Alignment

### 3.1 Model Context Protocol (MCP)

**Relationship:** JACS provides an MCP server with 13+ tools for signing, verification, trust management, and attestation operations. Any MCP-compatible client can use JACS as a native tool.

**Integration value for NCCoE:** The MCP server demonstrates how cryptographic identity and signing can be added to existing AI agent workflows without code changes -- the agent calls JACS tools through the standard MCP interface.

### 3.2 OAuth 2.0 / OpenID Connect

**Relationship:** Complementary, not competing. OAuth/OIDC provides session authentication ("prove you are who you claim to be right now"). JACS provides non-repudiable action signing ("prove you performed this action, verifiable at any future time").

**Integration pattern:** OAuth authenticates an agent to an API. JACS signs the agent's actions through that API. The OAuth token proves current access; the JACS signature proves the action was taken by a specific cryptographic identity.

### 3.3 SPIFFE / SPIRE

**Relationship:** SPIFFE provides workload identity (which process is this?). JACS provides agent-action identity (which agent performed this action?). These are different layers of identity.

**Integration pattern:** SPIFFE SVIDs can serve as evidence in JACS attestations, linking workload identity to agent action identity. A JACS attestation could reference a SPIFFE SVID as proof that the signing agent was running in a specific workload context.

### 3.4 NIST SP 800-63-4 (Digital Identity Guidelines)

**Mapping to Identity Assurance Levels (IAL):**

| NIST SP 800-63-4 Level | JACS Equivalent | How |
|------------------------|----------------|-----|
| IAL1 (self-asserted) | Open trust | Valid signature from any key |
| IAL2 (evidence-based) | Verified trust | Trust store + DNS-anchored key |
| IAL3 (verified, in-person) | Strict trust | Attestation with independently-verified evidence |

**Mapping to Authenticator Assurance Levels (AAL):**

| NIST SP 800-63-4 Level | JACS Equivalent |
|------------------------|----------------|
| AAL1 (single factor) | Single key pair (Ed25519) |
| AAL2 (multi-factor) | Key pair + password-encrypted private key |
| AAL3 (hardware) | Key pair + hardware-backed key storage |

### 3.5 NIST SP 800-207 (Zero Trust Architecture)

**Alignment:** JACS implements zero-trust principles natively:
- Never trust, always verify: every document is verified before acceptance
- Least privilege: multi-agent agreement requires explicit quorum approval
- Continuous verification: attestation freshness checks prevent stale trust decisions
- Assume breach: all operations produce signed, auditable artifacts

### 3.6 in-toto / DSSE

**Relationship:** JACS exports attestations as DSSE (Dead Simple Signing Envelope) documents, the same format used by in-toto v1.0+ and SLSA. This enables interoperability with supply chain verification tooling.

---

## 4. Demonstration Project Proposal

### 4.1 Proposed Scenario: Multi-Agent Financial Approval with Cryptographic Identity

**Overview:** A working demonstration showing three AI agents completing a financial approval workflow with full cryptographic identity, signed attestations, quorum authorization, and a verifiable audit trail.

**Agents:**
1. **Risk Analyst Agent** -- Evaluates transaction risk, produces a signed risk assessment with attestation claims (risk score, data sources used, confidence level)
2. **Compliance Agent** -- Checks regulatory requirements, attests that the transaction meets applicable rules with evidence references
3. **Approval Agent** -- Reviews both assessments, initiates a 2-of-3 quorum agreement for final approval

**Workflow:**
1. Risk Analyst signs its assessment and creates an attestation with claims (`risk_score: 0.3`, `data_source: "market_feed"`, `confidence: 0.85`)
2. Compliance Agent signs its check and creates an attestation with claims (`regulation: "SOX"`, `compliant: true`) and evidence (link to regulatory database lookup)
3. Approval Agent reviews both, initiates a multi-agent agreement requiring 2-of-3 signatures with a 5-minute timeout
4. The agreement produces a single signed document with all three agent signatures
5. An auditor verifies the complete chain: all signatures, all attestations, all evidence, the quorum result

**Standards demonstrated:**
- **MCP integration:** All three agents interact with JACS through the MCP server
- **OAuth complementarity:** Agents authenticate to the workflow API via OAuth; sign actions with JACS
- **NIST SP 800-63-4 mapping:** Agent identity levels mapped to IAL/AAL
- **NIST SP 800-207 alignment:** Zero-trust verification at every step

**Deliverables:**
1. Working demonstration code (Python, with Rust core)
2. Integration guide: JACS + OAuth + MCP
3. Audit verification walkthrough
4. Performance benchmarks (signing time, verification time, agreement completion time)
5. Documentation mapping JACS concepts to NCCoE standards

### 4.2 Technology Stack

| Component | Technology |
|-----------|-----------|
| Agent identity | JACS (Rust core, v0.9.0) |
| Agent communication | MCP server + A2A protocol |
| Session auth | OAuth 2.0 (complementary) |
| Signing algorithms | Ed25519 (primary), ML-DSA-87 (post-quantum) |
| Key distribution | DNS TXT records (DNSSEC) |
| Attestation format | JACS attestation schema + DSSE export |
| Storage | SQLite (default) or DuckDB/SurrealDB |
| Languages | Rust (core), Python (demo agents), Node.js (verification dashboard) |

### 4.3 Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Integration setup | 2 weeks | JACS + OAuth + MCP demo environment |
| Scenario implementation | 4 weeks | 3-agent workflow with full signing and attestation |
| Audit verification | 2 weeks | Complete audit trail walkthrough |
| Documentation | 2 weeks | Integration guide, standards mapping, performance data |
| **Total** | **10 weeks** | Complete demonstration package |

---

## 5. About JACS

JACS (JSON Agent Communication Standard) is an open-source project maintained by HAI.AI. Key facts:

- **Version:** 0.9.0 (attestation release)
- **Language:** Rust core with Python, Node.js, and Go bindings
- **License:** Open source (MIT)
- **Tests:** 500+ across 5 language targets
- **Algorithms:** Ed25519, ECDSA P-256/P-384, ML-DSA-87
- **Standards alignment:** JCS (RFC 8785), DSSE, in-toto predicate types
- **Repository:** https://github.com/HumanAssisted/JACS

The HAI.AI platform provides a production deployment of JACS capabilities, including agent registration, verified email addresses, benchmarking, and evaluation services for AI agents.

---

*We welcome the opportunity to participate in the NCCoE demonstration project and would be glad to discuss this proposal further. Contact: AI-Identity@nist.gov or directly at jonathan@hai.ai.*
