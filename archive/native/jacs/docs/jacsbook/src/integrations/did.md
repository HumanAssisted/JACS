# DID integration

JACS exports `did:wba` identifiers and public DID documents using the persisted
native signing identity. It has no general-purpose DID resolver. See the
[current identity guide](https://github.com/HumanAssisted/JACS/blob/main/docs/identity-standards.md)
for source installation, ML-DSA-87 JWK exports, checked standards and release
boundaries. The extended CLI is named `jacs-compat`:

```sh
jacs-compat w3c did --origin https://agent.example.com
jacs-compat w3c did-document --origin https://agent.example.com
```

These commands load the existing native agent configuration. The DID is
`did:wba:<host>:agent:<jacsId>` and its document is hosted at
`/agent/<jacsId>/did.json`. The domain comes from configured `jacs_agent_domain`
or an explicit `--origin`; publish under an origin you control. The exporter
does not prove that control or deploy the document.

Current source represents the native `pq2025` root as a `JsonWebKey` verification
method with an RFC 9964 ML-DSA-87 AKP `publicKeyJwk`. DID v1 and Controlled
Identifiers v1 contexts describe that representation. Exporting a different
format does not rotate the key or create another root identity. A valid
signature must still be tied to independently trusted identity evidence and
application authorization. No blockchain is required.

Generic `did:web` and `did:key` mappings are possible integration designs;
they are not implemented exporters in this library.

## ES256 compatibility entries


When the agent has an ES256 compatibility key **and** a valid
native-root-signed compatibility key binding granting the `did` scope,
generated DID documents (`jacs-compat w3c did-document`) include two
verification-method entries for that key:

- a `JsonWebKey` entry (`publicKeyJwk`) for JOSE consumers, and
- a `Multikey` entry (`publicKeyMultibase`) — the form `ecdsa-jcs-2019`
  Data Integrity proofs reference.

If the compatibility key is absent or the binding is missing, invalid, or
lacks the `did` scope, the DID document is still exported — it simply
omits the ES256 entries. The ES256 entries prove possession of the
compatibility key only; native-root trust comes from the binding
(`jacs-compat agent export-compat-binding`) — see the
[Security Model](../advanced/security.md#compatibility-key-binding-p2).

## JACS-Specific Request Proofs

The request-proof helpers (`jacs_w3c_sign_request` and
`jacs_w3c_verify_request` in the compiled MCP inventory, backed by the Rust
`w3c::auth` module) use an experimental JACS-specific JSON format:
`type: "JacsW3cRequestProof"`, `scheme: "DIDWba"`. This label does not make the
JSON object an ANP HTTP Message Signatures request or demonstrate interoperability
with an ANP peer. Existing helper names and fields describe the current JACS
contract; an ANP wire adapter is a separate integration.

The proof signs canonical request fields, including method, target, claimed
creation time, nonce and an optional body digest. Verification checks the supplied
DID document and signing key, timestamp policy and nonce use. To bind verification
to the request actually received, provide its expected method and URL and its
body; inspecting only the proof's own method and URL does not establish that
match. A supplied DID document is not, by itself, trusted identity evidence or
permission to act. Apply trusted resolution and current authorization policy at
the receiving application boundary.

## Where to Combine With Other Standards

- [A2A Interoperability](a2a.md): cross-organization agent discovery and artifact exchange
- [MCP Overview](mcp.md): signed tool invocation flows
- [DNS-Based Verification](../rust/dns.md): decentralized public key anchoring
- [Storage Backends](../advanced/storage.md): durable storage for signed artifacts and identity metadata
