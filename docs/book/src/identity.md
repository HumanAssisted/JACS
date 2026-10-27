# DID and A2A identity

A persistent native JACS `pq2025` key can identify an agent across DID documents,
public JWK/JWKS exports and signed Agent Cards. Current source adds direct
ML-DSA-87 public-key and JWS support; published 0.15.0 artifacts are a separate
release baseline. Start with the
[DID and post-quantum identity guide](https://github.com/HumanAssisted/JACS/blob/main/docs/identity-standards.md)
for source installation, `did:wba` exports, and trust requirements.

The [A2A quickstart](https://github.com/HumanAssisted/JACS/blob/main/A2A_QUICKSTART.md)
covers local discovery, source versus release behavior, and explicit ES256
compatibility. Legacy discovery retains its `0.4.0` model and compact JWS
representation. The separate typed A2A 1.0 API signs its bounded profile with
the native ML-DSA-87 root and standard detached signature fields. Explicit
ES256 remains available for peers that need it; the official-SDK finite report
example selects ES256. Neither surface is a general production host. The portable MCP server does not provide DID
resolution or A2A transport.

See the [checked standards research](https://github.com/HumanAssisted/JACS/blob/main/docs/research/pq-identity-standards.md)
for primary sources and independent ML-DSA verification evidence. Standardized
JOSE key representation does not imply support in every peer or a finalized
ML-DSA-87 Data Integrity cryptosuite.
