# Identity across MCP, A2A and DID

A persistent JACS identity signs documents with the same key across sessions.
New identities use ML-DSA-87 (`pq2025`); verification errors never trigger a
classical fallback. Choose the integration boundary you need:

| Goal | Start here | What JACS supplies |
| --- | --- | --- |
| Connect an agent to local signing/verification tools | [MCP client setup](mcp-quickstart.md) | A stdio server; verification-only by default |
| Publish an Agent Card or exchange A2A artifacts | [A2A how-to](a2a.md) | Native discovery and signing APIs; explicit A2A 1.0 profile |
| Export a DID document or test a DID-bound request proof | [W3C DID how-to](w3c-did.md) | `did:wba` export and JACS-specific request proofs |

MCP is the primary integration. The portable `jacs` server does not host A2A
messaging or resolve DIDs. The separate native `jacs-compat` CLI and language
libraries provide those documented exports; an application supplies its own
messaging handler and identity/authorization policy.

The [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
records published 0.15.0 packages. New direct-PQ DID/JWK and Agent Card behavior
in this checkout is **source work**. The A2A and DID how-tos therefore start with
source builds. A public key fetched alongside a signature is not an independent
trust anchor, and a valid signature is not permission to act.

See the [standards evidence](https://github.com/HumanAssisted/JACS/blob/main/docs/research/pq-identity-standards.md)
for RFC 9964, DID and A2A references. An AKP JWK represents an ML-DSA key; it does
not imply a finalized ML-DSA Data Integrity cryptosuite or universal peer support.
