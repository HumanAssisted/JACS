# A2A Interoperability

The default discovery adapters retain the legacy A2A `0.4.0` card shape.
The separate typed `jacs::a2a::v1` API uses the A2A 1.0 shape for a bounded
JSON-RPC profile; see the
[current source quickstart](https://github.com/HumanAssisted/JACS/blob/main/A2A_QUICKSTART.md)
and the [v1 example](#opt-in-a2a-10-peer-example) below.

{{#include ../_snippets/node-registry-status.md}}

Use A2A when your agent needs to be discoverable and verifiable by another service, team, or organization. This is the cross-boundary story; MCP is the inside-the-app story.

## What JACS Adds To A2A

- **Agent Cards** with JACS provenance metadata
- **Signed artifacts** such as `a2a-task` or `a2a-message`
- **Trust policy** for deciding whether another agent is acceptable
- **Chain of custody** via parent signatures

## The Core Flow

### 1. Export An Agent Card

Python:

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")
card = client.export_agent_card()
```

Node.js:

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});

const card = client.exportAgentCard();
```

### 2. Serve Discovery Documents

Python and Node provide discovery-only server helpers. These mounts publish
well-known documents; they do not implement A2A message/task handling or the
legacy optional `/jacs/sign` and `/jacs/verify` host endpoint examples in the
extension descriptor. A host application must implement and authorize any
callable interface separately. Discovery does not grant remote signing access.

Quick demo server:

```python
from jacs.a2a import JACSA2AIntegration

JACSA2AIntegration.quickstart(
    name="my-agent",
    domain="my-agent.example.com",
).serve(port=8080)
```

Production FastAPI mounting:

```python
from jacs.a2a_server import create_a2a_app, jacs_a2a_routes

app = create_a2a_app(client, title="My A2A Agent")
# or:
# app.include_router(jacs_a2a_routes(client))
```

Node.js has two discovery helpers:

- `client.getA2A().listen(port)` for a minimal demo server
- `jacsA2AMiddleware(client, options)` for mounting discovery routes in an existing Express app

```typescript
import express from 'express';
import { jacsA2AMiddleware } from '@hai.ai/jacs/a2a-server';

const app = express();
app.use(jacsA2AMiddleware(client));
app.listen(3000);
```

The local listening port does not rewrite the signed public interface URL.
Configure the advertised domain before generating the signed card and provide
the host service that interface describes. A reachable discovery route alone
does not prove that message/task operations exist.

### 3. Sign And Verify Artifacts

Python:

```python
signed = client.sign_artifact({"artifactId": "a-1", "operation": "classify"}, "artifact")
result = client.get_a2a().verify_wrapped_artifact(signed)
assert result["valid"]
```

Node.js:

```typescript
const signed = await client.signArtifact(
  { artifactId: 'a-1', operation: 'classify' },
  'artifact',
);

const result = await client.verifyArtifact(signed);
console.log(result.valid);
```

Both SDKs require the canonical native A2A verifier for an affirmative result.
The generic `verify_response()` / `verifyResponse()` document API is not an A2A
fallback: even a literal success boolean yields an invalid result with blank
signer, version, type, timestamp, and payload provenance, and cannot elevate
trust. This prevents parsed attacker-controlled wrapper fields from being
presented as authenticated A2A evidence.

The Node signing wrapper also validates the native return contract before
releasing it: the document must carry complete portable-v2 signature metadata,
its payload and type must match the request, and its ordered parent chain must
exactly match the caller's input. If no parents were requested, only an absent
or empty returned chain is accepted. This prevents a malformed native result
from injecting, dropping, reordering, or changing chain-of-custody evidence.

## Trust Policies

Trust policy answers a different question from cryptographic verification.

- **Trust policy**: should this remote agent be admitted?
- **Artifact verification**: is this specific signed payload valid?

The current policy meanings are:

{{#include ../_snippets/a2a-trust-policies.md}}

`verified` means the card signature and a durable same-origin key pin verified.
It proves origin/key continuity, not that the self-asserted `jacsId` is a
real-world or explicitly trusted identity. `strict` is the identity-bound mode.

### Python

```python
a2a = client.get_a2a()
assessment = a2a.assess_remote_agent(remote_card_json, policy="strict")

if assessment["allowed"]:
    result = a2a.verify_wrapped_artifact(artifact, assess_trust=True)
```

### Node.js

```typescript
const a2a = client.getA2A();
const assessment = a2a.assessRemoteAgent(remoteCardJson);

if (assessment.allowed) {
  const result = await a2a.verifyWrappedArtifact(signedArtifact);
}
```

## Bootstrap Patterns

Use the trust store when you want explicit admission:

- Export the agent document with `share_agent()` / `shareAgent()`
- Exchange the public key with `share_public_key()` / `getPublicKey()`
- Add the remote agent with `trust_agent_with_key()` / `trustAgentWithKey()`

This is the cleanest path into `strict` policy.

## Native post-quantum discovery

Current source defaults to the persisted native ML-DSA-87 root for
`generate_well_known_documents`. It publishes that root's RFC 9964 AKP JWK and
five discovery documents, with no delegated-key binding. The card's JWS signs
canonical card bytes and its `metadata.jacsRootKid` identifies the root's JWK
thumbprint. Loading or exporting does not create another signing key. The
legacy card wire shape remains unchanged.

## Explicit ES256 compatibility

Agent cards can also be exported with an ES256 signature from the agent's
compatibility key (`export_a2a_agent_card` in the Rust core and bindings,
feature `a2a`). This is a card-typed exporter, not a generic JWS API:

- The JWS protected header is pinned to `{"alg": "ES256", "typ": "JOSE",
  "kid": "<compat-key kid>"}` — `typ` is `JOSE`, not `JWT`.
- The export is gated by the `a2a-agent-card` scope of the native-root-signed
  compatibility key binding (an identity scope, granted by default).
- The card's `metadata` carries `jacsCompatKid`,
  `jacsCompatBindingHash`, and the fixed same-origin
  `jacsCompatBindingPath` (`/.well-known/jacs-compat-binding.json`).

A stock JOSE verifier can check the ES256 signature against the agent's
compatibility JWKS (`jacs-compat agent export-jwks`), but that proves possession of the
compatibility key only. Tracing the card to the agent's native root requires
verifying the native-root-signed compatibility key binding
(`jacs-compat agent export-compat-binding`). Calling native
`generate_well_known_documents` with explicit `ES256` publishes the binding at
the fixed path and reuses the same persisted ES256 key
across calls and restarts. An obsolete explicit `ring-Ed25519` discovery-key
choice is rejected rather than silently ignored — see the
[Security Model](../advanced/security.md#compatibility-key-binding-p2).

Under `strict`, the verifier checks the trusted native root signature, expected
`jacsId` and `jacsVersion`, binding content hash, compatibility `kid` and JWK,
the `a2a-agent-card` scope, expiry, and a signed `issuedAt` no more than seven
days old or five minutes in the future. This absolute freshness check applies
on first contact; local discovery generation refreshes an authentic binding at
six days while preserving its scopes and explicit expiry. A self-advertised
JWKS key by itself can never establish the claimed JACS identity.

## Current Runtime Differences

- **Python and Node.js**: the FastAPI and Express routers serve five native
  discovery documents by default, including the signed card and JWKS. Explicit
  ES256 adds a compatibility binding. They are discovery-only; `serve()` and `listen()` are convenience
  hosts, not complete A2A task/message services.
- The mounted routers refresh their complete snapshots lazily at six days from
  local generation (direct root) or signed binding issuance (ES256). HTTP freshness ends at renewal or earlier explicit expiry;
  separate fetches can still straddle replacement. Verify the related documents
  together and refetch on a mismatch. See [Serve Your Agent Card](../guides/a2a-serve.md).

## Example Paths In This Repo

- `jacspy/tests/test_a2a_server.py`
- `jacsnpm/src/a2a-server.js`
- `jacsnpm/examples/a2a-agent-example.js`
- `jacs/tests/a2a_cross_language_tests.rs`


## Opt-in A2A 1.0 peer example

Current source's typed `jacs::a2a::v1::export_agent_card` signs directly with the
loaded ML-DSA-87 root. It uses the A2A 1.0 `supportedInterfaces` model and
standard detached `signatures[].protected` / `signature` fields, with typed
protobuf presence handling and RFC 8785 canonicalization. Its
`verify_root_card` verifies the signature, exact trusted root and expected
identity/version for the supported profile. See the
[source library guide](https://github.com/HumanAssisted/JACS/blob/main/docs/identity-standards.md#library-entry-points).

`export_agent_card_es256` is the explicit compatibility alternative. The
pinned official-SDK example below selects this ES256 path; it does not prove
that the peer implements ML-DSA-87. `verify_card_binding` remains the
compatibility binding check, and its caller must additionally verify the JWS.


Public Node and Python discovery APIs accept explicit A2A 1.0 options with
caller-provided skills, input/output modes and a messaging URL. Without those
options, language discovery remains the legacy `0.4.0` format. See the
[current public API examples](https://github.com/HumanAssisted/JACS/blob/main/A2A_QUICKSTART.md#a2a-10-from-nodejs-or-python).

The [current official SDK smokes](https://github.com/HumanAssisted/JACS/blob/main/archive/native/examples/a2a_v1_sdk/README.md)
exercise those public APIs with stock JavaScript SDK **1.3.0** (direct ML-DSA-87,
Node 24.7+) and stock Python SDK **1.3.0** (explicit ES256 compatibility,
Python 3.11+). Each uses actual SDK discovery, signature verification and a
finite JSON-RPC report exchange. SDK version and wire version are different
numbers. The Python backend does not provide ML-DSA verification.

The broader retained native-fixture/Python vector harness also uses the exact
`a2a-sdk==1.3.0` registry package and hashed transitive dependencies. From the
repository root, with Python 3.11+ and uv installed:

```sh
uv venv --python python3 /tmp/jacs-a2a-peer-env
uv pip sync --python /tmp/jacs-a2a-peer-env/bin/python archive/native/examples/a2a_v1_peer_requirements.txt
cargo build --locked --manifest-path archive/native/Cargo.toml -p jacs \
  --no-default-features --features a2a --example a2a_v1_peer --target-dir target/a2a-v1-example
/tmp/jacs-a2a-peer-env/bin/python archive/native/examples/a2a_v1_peer.py \
  --native-bin target/a2a-v1-example/debug/examples/a2a_v1_peer
```

A disposable native helper creates an encrypted signing identity, a card,
its native-root-signed compatibility binding, and a pre-signed synthetic report.
It removes its private workspace before a separate recipient starts. A finite
loopback host serves the card and a real SDK JSON-RPC interface. The official
client follows that returned interface and receives the report as raw
`application/json` artifact bytes. The recipient checks exact bytes, uses the
native public-key-only verifier for the document, and separately validates the
native binding against an explicitly supplied trusted root before the official
SDK verifies the ES256 card signature. No email or external network is used.

The new profile puts native identity and binding references in
`urn:jacs:provenance-v1` extension parameters, using the current card's standard
signature fields. It preserves explicitly supplied optional false booleans and
omits absent optional fields and ordinary proto defaults. Required strings and
arrays must be nonempty. It rejects caller-supplied binding parameters,
duplicate extension URIs, unsupported capability claims, non-object extension
parameter roots, and empty/null or unsafe numeric extension values instead of silently changing them. Production
interface URLs require HTTPS; explicit loopback HTTP is permitted for this
example. The caller must implement every declared skill; the example implements one report skill.

This deliberately bounded profile records a pinned-peer limitation: its
canonicalizer removes explicit optional empty strings, although the protocol's
presence rules preserve them. The peer is not patched. Unsupported values are
rejected by the new typed boundary, and the example does not claim general A2A
conformance. It tests independent SDK card/JWS handling and message transport;
native document and root-binding verification still use JACS. The existing
legacy Strict discovery parser is not a v1 parser, and this stateless bridge
does not establish rollback history. Key attribution, human approval, current
contact authority and Agreement-policy acceptance remain separate decisions.

Historical verification on September 15, 2026 used macOS arm64, Rust 1.98.1, Python
3.14.7, SDK 1.1.4 at commit `2d4d3048b245d2af854bad804f0e722ea9febc08`,
and the reviewed Rustls 0.23.45 lock. The native profile
regression and existing legacy discovery/restart regression passed. The actual
peer verified three card vectors and received all 1,201 report bytes unchanged;
14 peer/native refusals and seven typed-profile refusals passed, along with
private-workspace and host cleanup. This is selected-feature (`a2a`, without
default features) example evidence, not an all-platform or general-conformance
certification.
