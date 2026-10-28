# A2A + Attestation: Using Both Together

A2A artifact signatures cover an exchanged payload and its linked parent artifacts. Attestations record claims, evidence and derivation. Neither mechanism proves that a claim is true or that a human reviewed it.

## Create distinct identities

Different names alone do not create different agents: `quickstart` loads an existing config. Use distinct paths:

```python
from jacs.client import JacsClient

scanner = JacsClient.quickstart(
    name="scanner", domain="scanner.example.com", config_path="scanner/jacs.config.json"
)
reviewer = JacsClient.quickstart(
    name="reviewer", domain="reviewer.example.com", config_path="reviewer/jacs.config.json"
)
```

The Node equivalent is `JacsClient.quickstart({name, domain, configPath})` with a separate `configPath` for each agent. Preserve each identity's encrypted keys and host password source.

## Configure verification before exchanging artifacts

Independently authenticate the sender's agent document and public key. [Trust-store enrollment](../advanced/trust-store.md) records admission evidence, but it is not sufficient by itself to configure artifact verification: the native A2A artifact verifier resolves foreign keys from its configured local public-key cache or registry. The OS/XDG trust-store key cache is a separate location. Provision the appropriate resolver with the authenticated key and test rejection of a wrong key before enabling the exchange.

The following is an application workflow, not a complete cross-agent program:

1. The scanner signs its result with `sign_artifact(result, "result")` and sends the full envelope.
2. The reviewer resolves the authenticated scanner key, verifies the artifact and required parent signatures, then applies admission policy. Fetching a key beside a payload is not independent authentication.
3. After performing its own checks, the reviewer creates an attestation about the exact artifact bytes, with explicit digest conventions and supporting evidence. A claim such as `reviewed=true` remains the reviewer's signed assertion.
4. The reviewer may sign an A2A artifact referencing that attestation. The receiver verifies the exchanged envelope and separately evaluates the attestation's signature, evidence and claim policy.

A `create_chain_of_custody` summary collects metadata; it does not verify signatures or establish ordering. Attestation full verification likewise has specific evidence/resolver limits; it is not automatic cross-agent trust evaluation.

Continue with [artifact exchange](a2a-exchange.md), the [attestation tutorial](attestation-tutorial.md), and the [cross-language A2A tests](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs/tests/a2a_cross_language_tests.rs).
