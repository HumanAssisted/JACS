# Python API Reference

| API | Use |
| --- | --- |
| `jacs.client.JacsClient` | Independent clients with Python result types |
| `jacs.simple` | One process-wide session |
| `jacs.JacsAgent` / `jacs.SimpleAgent` | Distinct direct native APIs |

Start with [Basic Usage](basic-usage.md). Native arguments accepting `None`
are not necessarily optional at the call site.

## JacsClient

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")
signed = client.sign_message({"message": "hello"})
assert client.verify(signed.raw).valid
```

| Method | Result |
| --- | --- |
| `JacsClient(config_path=None, algorithm=None, strict=None)` | Client; loads only when a path is supplied |
| `JacsClient.quickstart(name, domain, description=None, algorithm=None, config_path=None, strict=None)` | Persistent client |
| `JacsClient.ephemeral(algorithm=None, strict=None)` | In-memory client |
| `sign_message(data)` | `SignedDocument` |
| `sign_file(path, embed=False)` | `SignedDocument` |
| `verify(document)` / `verify_self()` | `VerificationResult` |
| `verify_by_id(doc_id)` | Verification of stored `uuid:version` |
| `export_agent()` / `get_public_key()` | Agent JSON / public PEM string |
| `update_agent(data)` | Updated JSON; supply the complete agent document |
| `update_document(doc_id, data, attachments=None, embed=False)` | Updated document; supply its full `id:version` key and complete replacement |
| `reset()` | Clear the client session |

The constructor's `algorithm` argument does not create an agent; select an
algorithm through a factory. New agents default to `pq2025`.
`verify()` accepts JSON, a dict or `SignedDocument`; strict mode raises on
verification failures, otherwise inspect `valid` and `errors`.

See the [client source](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacspy/python/jacs/client.py)
for trust-store, attestation, media and A2A helpers.

## Result types

| Type | Common attributes |
| --- | --- |
| `AgentInfo` | `agent_id`, `version`, `algorithm`, `config_path`, key paths |
| `SignedDocument` | `document_id`, `version`, `signer_id`, `payload`, `raw_json` |
| `VerificationResult` | `valid`, `signer_id`, `timestamp`, `errors` |

`raw` aliases `raw_json`, `agent_id` aliases `signer_id`, and
`timestamp` aliases `signed_at` on `SignedDocument`.
Signer timestamps are claims; verification does not grant permission to act.

## Low-level JacsAgent

Every argument below without a default must be supplied, even when its value is
`None`. Native operation errors normally raise `RuntimeError`; Python
argument conversion can raise `TypeError`.

```python
import json
from jacs import JacsAgent

agent = JacsAgent()
agent.load("./jacs.config.json")
document = agent.create_document(
    json.dumps({"jacsDocument": {"type": "message", "content": {"answer": 42}}}),
    None,   # custom_schema
    None,   # outputfilename
    True,   # no_save
    None,   # attachments
    None,   # embed
)
assert agent.verify_document(document)
assert agent.verify_agent(None)
```

| Native method | Return |
| --- | --- |
| `load(config_path)` | JSON string |
| `create_document(document_string, custom_schema, outputfilename, no_save, attachments, embed)` | Signed JSON string |
| `verify_document(document_string)` | Boolean |
| `verify_signature(document_string, signature_field)` | Boolean; `None` selects default field |
| `verify_agent(agentfile)` | Boolean; `None` selects loaded agent |
| `update_document(document_key, new_document_string, attachments, embed)` | Updated JSON string |
| `update_agent(new_agent_string)` | Updated agent JSON string |
| `export_agent()` / `get_public_key_pem()` | Agent JSON / public PEM string |
| `create_agreement(document_string, agentids, question, context, agreement_fieldname)` | Agreement JSON |
| `sign_agreement(document_string, agreement_fieldname)` | Countersigned JSON |
| `check_agreement(document_string, agreement_fieldname)` | Inspection report JSON |

`create_document.attachments` accepts an optional string through the native
attachment parser; `update_document.attachments` accepts an optional list of
paths. Use `sign_file()` for the common single-file workflow.

Document updates require the original to be available in the agent's document
store. Parse the complete document, derive `jacsId:jacsVersion`, modify its
application fields, and submit the complete replacement. `no_save` controls
file export; it does not mean the document is absent from the in-memory store.

Legacy agreement parameters are exactly `agentids` and
`agreement_fieldname` on `JacsAgent`. `JacsClient.create_agreement()` uses
`agent_ids` and `field_name` instead. Inspection reports include
`verified_signature_count`, `pending`, and `mathematical_checks_valid`;
`complete` and `policy_accepted` remain false. Never infer consent from them.

### Configuration helper

`jacs.create_config()` returns configuration JSON and does not create keys.
All nine arguments are required, though each accepts `None`:

```text
create_config(jacs_use_security, jacs_data_directory, jacs_key_directory,
              jacs_agent_private_key_filename, jacs_agent_public_key_filename,
              jacs_agent_key_algorithm, jacs_private_key_password,
              jacs_agent_id_and_version, jacs_default_storage)
```

Prefer `JacsClient.quickstart()` for setup. Keep passwords in host secret
handling rather than examples, logs or persisted config.

## Native SimpleAgent

`SimpleAgent` provides instance-based Agreement v2, request authentication,
signed events and public human-approval verification. See the
[simplified API guide](simple-api.md) and
[native binding source](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacspy/src/lib.rs).
Do not assume methods on one native class exist on the other.

See [MCP](mcp.md), [Framework Adapters](adapters.md), and
[Python examples](../examples/python.md).
