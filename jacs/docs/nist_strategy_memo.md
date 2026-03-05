# Internal Strategy Memo: NIST AI Agent Standards Alignment

**Date:** March 2026
**For:** HAI.AI Leadership
**Re:** IETF Internet-Draft Alignment, NCCoE Opportunity, and CSA Framework

---

## 1. IETF Internet-Drafts Aligned with JACS

Several IETF Internet-Drafts from late 2025 and early 2026 directly relate to JACS capabilities. Key drafts to monitor and potentially contribute to:

### Strongly Aligned

| Draft | Working Group | JACS Relevance |
|-------|---------------|----------------|
| `draft-huang-rats-agentic-eat-cap-attest-00` | RATS | Capability attestation for agents. JACS claims model maps to EAT claims. |
| `draft-jiang-seat-dynamic-attestation-00` | RATS/new | Dynamic attestation for runtime assertions. Aligns with JACS attestation freshness model. |
| `draft-messous-eat-ai-00` | RATS | EAT profile for AI agents. JACS could implement this profile using its existing attestation schema. |
| `draft-ni-a2a-ai-agent-security-requirements-00` | Security | Security requirements for A2A. JACS already implements A2A with signed trust. |
| `draft-huang-acme-scalable-agent-enrollment-00` | ACME | Scalable agent certificate enrollment. JACS could add ACME-based key enrollment alongside its current decentralized model. |

### Complementary

| Draft | Relevance |
|-------|-----------|
| SCITT (Supply Chain Integrity, Transparency, and Trust) | JACS is decentralized, SCITT is centralized transparency. Complementary: JACS signs, SCITT logs. |
| DSSE (Dead Simple Signing Envelope) | JACS already exports to DSSE format for in-toto/SLSA interop. |

## 2. Should JACS Submit Its Own IETF I-D?

**Recommendation: Yes, target the RATS working group.**

**Rationale:**
- JACS fills a gap between hardware attestation (RATS/EAT) and software agent attestation that no current I-D fully addresses
- The JACS attestation schema (subject, claims, evidence, derivation, policy context) is a concrete implementation of concepts the RATS WG is discussing abstractly
- Having an I-D positions JACS as a reference implementation, not just a product
- The RATS WG is actively seeking agent-layer contributions (evidenced by multiple agent-related I-Ds appearing in 2025-2026)

**Proposed I-D scope:**
- Title: "Attestation Profile for AI Agent Actions and Evidence Chains"
- Content: Define the attestation schema format, claim types, evidence reference model, derivation chain verification, and two-tier verification tiers
- Reference implementation: JACS
- Target: Informational RFC initially, potentially Standards Track if WG interest is strong

**Timeline:**
- April-May 2026: Draft I-D text based on JACS v0.9.0 attestation spec
- June 2026: Submit to RATS WG mailing list for discussion
- July 2026: Present at IETF 121 (if accepted for agenda)

## 3. NCCoE Concept Paper Response (April 2, 2026)

**Priority: HIGH** -- This is the best fit for JACS of all current NIST opportunities.

The NCCoE concept paper "Accelerating the Adoption of Software and AI Agent Identity and Authorization" proposes a demonstration project exploring identity and authorization practices for AI agents. JACS should respond proposing itself as a technology partner.

**Key strengths to emphasize:**
- JACS provides the cryptographic identity layer that complements OAuth/OIDC (session auth vs. non-repudiable signing)
- JACS MCP server already integrates with the Model Context Protocol referenced in the concept paper
- JACS maps to NIST SP 800-63-4 assurance levels (open/verified/strict maps to IAL/AAL levels)
- JACS attestation aligns with in-toto/DSSE for supply chain scenarios
- JACS works offline and decentralized, addressing enterprise air-gap requirements

**Proposed demonstration scenario:**
Multi-agent financial approval workflow with 3 agents, cryptographic identity, signed attestations with evidence chains, quorum-based authorization, and a verifiable audit trail. Demonstrate end-to-end from agent creation to audit verification.

**Standards addressed:**
- MCP integration (JACS MCP server)
- OAuth 2.0 complementarity (JACS for action signing, OAuth for session auth)
- SPIFFE/SPIRE complementarity (SPIFFE for workload identity, JACS for agent-action identity)
- NIST SP 800-207 (Zero Trust) alignment (JACS implements verify-before-trust)
- NIST SP 800-63-4 assurance level mapping

## 4. CSA Agentic Trust Framework

The Cloud Security Alliance's Agentic Trust Framework defines progressive trust levels. JACS's open/verified/strict model maps directly:

| CSA Level | JACS Level | How |
|-----------|-----------|-----|
| None | (no JACS) | No signing |
| Basic | Open | Accept any valid signature |
| Standard | Verified | Require trust store + DNS verification |
| Enhanced | Strict | Require attestation-level evidence |

**Action:** Monitor CSA publications and consider submitting JACS as a reference implementation.

## 5. Timeline Summary

| Date | Action |
|------|--------|
| **March 9, 2026** | **NIST CAISI RFI submission deadline** |
| **April 2, 2026** | **NCCoE concept paper response deadline** |
| April-May 2026 | Draft IETF I-D based on attestation spec |
| June 2026 | Submit I-D to RATS WG |
| July 2026 | IETF 121 presentation (if accepted) |
| Ongoing | Monitor CSA Agentic Trust Framework |

---

*This memo is internal to HAI.AI and should not be distributed externally.*
