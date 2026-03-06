# DID Integration (No Blockchain Required)

This chapter describes an integration pattern. JACS does not currently ship a built-in DID resolver, DID method implementation, or DID document toolchain in core bindings.

You can still use JACS in DID-oriented architectures without requiring a blockchain or ledger.

## Core Position

- JACS already gives you signed, verifiable agent identity and artifact provenance
- DID is an interoperability format you can layer on top when needed
- Blockchain is optional infrastructure, not a dependency of JACS

## How Identity Maps

JACS identity primitives:

- `jacsId` (stable agent identity)
- `agentVersion` (key/version lifecycle)
- `publicKeyHash` (verification anchor)
- Optional DNS domain for public verification

Typical DID mappings:

- `did:web:agent.example.com` for web-hosted identity metadata
- `did:key:<multibase>` for direct key-based identity
- Organization-specific DID methods for internal ecosystems

## Practical Integration Pattern

1. Keep JACS as the source of truth for signing and verification.
2. Publish a DID representation that references the same public key material.
3. Verify payload signatures with JACS runtime policy (`local`, `dns`, `registry`).
4. Use DID resolution for discovery/routing metadata where useful.

This avoids duplicate trust stacks while still supporting DID-based interoperability requirements.

## Why Teams Choose This Model

- No chain operations, gas costs, or ledger finality concerns
- Works in private networks and regulated environments
- Easier migration path from existing PKI/DNS systems
- Clear separation: JACS for provenance, DID for interoperable identity documents

## Example: `did:web` + JACS DNS

- Serve DID metadata via `did:web`
- Publish JACS public key fingerprint in DNS TXT
- Accept external artifacts only when JACS verification succeeds under your trust policy

This gives human-readable identity, standards-friendly discovery, and strong cryptographic verification without blockchain dependencies.

## Where to Combine With Other Standards

- [A2A Interoperability](a2a.md): cross-organization agent discovery and artifact exchange
- [MCP Overview](mcp.md): signed tool invocation flows
- [DNS-Based Verification](../rust/dns.md): decentralized public key anchoring
- [Databases](databases.md): durable storage for signed artifacts and identity metadata
