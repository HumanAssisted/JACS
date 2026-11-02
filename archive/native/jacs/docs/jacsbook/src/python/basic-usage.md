# Python Basic Usage

Use `JacsClient` for independent agents, or [`jacs.simple`](simple-api.md)
for one process-wide session.

## Sign and verify

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")
signed = client.sign_message({"event": "tool-result", "answer": 42})
result = client.verify(signed.raw)
if not result.valid:
    raise ValueError(result.errors)
print(result.signer_id, signed.payload)
```

Quickstart loads an existing config or creates encrypted keys with `pq2025`.
See [password bootstrap](../getting-started/quick-start.md#native-password-bootstrap)
for preserving access across process restarts. To load explicitly:

```python
client = JacsClient(config_path="./jacs.config.json", strict=True)
```

With `strict=True`, verification failures raise `VerificationError`; with
strict mode disabled, inspect `result.valid` and `result.errors`.
Configuration and signing errors still raise.

Verification authenticates bytes under the resolved key. Separately require
the expected signer, trusted identity binding, allowed action and freshness
before executing an operation.

## Save and exchange signed JSON

```python
from pathlib import Path

Path("signed.json").write_text(signed.raw, encoding="utf-8")
received = Path("signed.json").read_text(encoding="utf-8")
result = client.verify(received)
if not result.valid:
    raise ValueError(result.errors)
```

Send the complete `signed.raw`, including signature and metadata. To verify
another agent, configure its public key under your trust policy. A key embedded
in a submission or fetched from a URL is not an identity endorsement.

## Files and public identity

```python
signed_file = client.sign_file("report.pdf", embed=True)
assert client.verify(signed_file.raw).valid
agent_json = client.export_agent()
public_key_pem = client.get_public_key()
```

The file must already exist. Embedding carries its bytes; `embed=False`
records a reference/hash. Apply an external-file verification policy when
receiving referenced files. Share public identity material through an
authenticated channel.

## Independent agents

```python
alice = JacsClient.quickstart(
    name="alice", domain="alice.example.com", config_path="./alice/jacs.config.json"
)
bob = JacsClient.quickstart(
    name="bob", domain="bob.example.com", config_path="./bob/jacs.config.json"
)
```

For short-lived tests, `JacsClient.ephemeral()` keeps its identity in memory.
Do not assume separate ephemeral agents can resolve one another's public keys.

## Agreements and integrations

Legacy `create_agreement()`, `sign_agreement()` and `check_agreement()`
inspect sidecar evidence; inspection cannot establish application consent.
Agreement v2 is available on `jacs.simple` and native `SimpleAgent`; its
`valid` and `policyAccepted` remain false even when
`mathematicalChecksValid` is true.

See [MCP](mcp.md), [Framework Adapters](adapters.md), and the
[API reference](api.md) for direct native calls.
