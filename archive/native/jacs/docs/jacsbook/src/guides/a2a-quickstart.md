# A2A Quickstart

Start with the [A2A how-to](https://humanassisted.github.io/JACS/a2a.html) for source installation, local discovery, A2A 1.0 export and a real official-SDK message exchange. Current source adds capabilities beyond the published 0.15.0 baseline; see the [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md).

| Guide | Task |
|-------|------|
| [Serve](a2a-serve.md) | Publish signed Agent Cards and public discovery documents |
| [Discover and trust](a2a-discover.md) | Assess a remote legacy card against an explicit policy |
| [Exchange](a2a-exchange.md) | Sign artifacts and verify their linked parent signatures |

## Cards, keys and handlers

Default native discovery exports the legacy `0.4.0` card format. Explicit A2A `1.0` options produce typed cards with detached signatures; the [interoperability reference](../integrations/a2a.md) describes the supported profile and official SDK tests. SDK version numbers and wire protocol versions are separate.

The persisted ML-DSA-87 root signs discovery by default: five public documents, with no compatibility binding required. Explicit ES256 uses a persisted compatibility key and adds a sixth, root-signed binding document. Agent creation may generate that optional key; loading or exporting does not mint an unrelated signer.

The discovery servers do not implement message/task handlers. The host must implement and authorize the advertised service. A2A already defines card signatures; JACS adds native-root attribution, signed artifact envelopes and explicit verification policies.

## Sign an artifact

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")
signed = client.sign_artifact({"result": "ready"}, "result")
```

The wire payload is `signed["a2aArtifact"]`; `jacsType` is `a2a-result` here. Extracting the payload discards its signed envelope, so a recipient must verify before relying on provenance.

## Troubleshooting

- **Valid signature, rejected policy:** independently enroll the full native agent document and public key before using `strict`. A self-advertised card cannot enroll itself.
- **No agent loaded:** create/load a client before signing or discovery assessment. Different local agents need different `config_path`/`configPath` values.
- **Missing skills:** provide skills before generating signed discovery. Post-signing overrides are rejected.
- **Missing signer key:** native key resolution defaults to `local,registry`; set `JACS_KEY_RESOLUTION=local` for offline lookup. DNS checks fingerprints, not key bytes. Obtaining a key is separate from trusting it.
- **Python installation:** published 0.15.0 wheels support Python 3.10–3.14; current source requires 3.11–3.14. The `a2a-server` extra adds FastAPI and uvicorn.

Continue with [trust-store enrollment](../advanced/trust-store.md) and [the A2A reference](../integrations/a2a.md).
