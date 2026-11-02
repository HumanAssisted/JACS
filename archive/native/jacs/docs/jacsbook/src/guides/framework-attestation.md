# Framework Adapter Attestations

Python adapters accept `attest=True` to produce an attestation about their
output. A signed claim records what its issuer asserted; it does not prove a
human reviewed the output or that an action is authorized.

Install the corresponding [framework extra](../python/adapters.md). These
examples require a native build with attestation support.

## LangChain and LangGraph

Wrap a LangChain tool instance:

```python
from langchain_core.tools import tool
from jacs.client import JacsClient
from jacs.adapters.langchain import signed_tool

client = JacsClient.ephemeral()

@tool
def lookup_customer(customer_id: str) -> str:
    """Return the customer status."""
    return "active"

attested_lookup = signed_tool(lookup_customer, client=client, attest=True)
```

For LangGraph, `with_jacs_signing([lookup_customer], client=client, attest=True)`
constructs a `ToolNode`. `jacs_wrap_tool_call(client=client, attest=True)`
returns a `(request, execute)` hook for a tool node; it is not a decorator for
an ordinary Python function. For LangChain agents use
`jacs_signing_middleware(client=client, attest=True)`.

## FastAPI

```python
from fastapi import FastAPI
from jacs.client import JacsClient
from jacs.adapters.fastapi import JacsMiddleware

client = JacsClient.quickstart(name="api", domain="api.example.com")
app = FastAPI()
app.add_middleware(JacsMiddleware, client=client, attest=True)
```

For an individual route, use `@jacs_route(client=client, attest=True)`.
These constructors do not accept `claims` or `default_claims`.
Request verification only checks signed POST JSON bodies; unsigned requests
still pass through, including in strict mode. See
[FastAPI verification limits](../python/adapters.md#fastapi--starlette).

## Anthropic tools

```python
from jacs.client import JacsClient
from jacs.adapters.anthropic import signed_tool

client = JacsClient.ephemeral()

@signed_tool(client=client, attest=True)
def search_database(query: str) -> str:
    return "Found 3 results"

attestation_json = search_database("example")
```

`JacsToolHook(client=client, attest=True)` is an async post-tool hook accepting
an input dictionary containing `tool_response`. It does not register or wrap a
list of tool schemas.

## Custom claims and verification

Use `JacsClient.create_attestation(subject=..., claims=..., evidence=...)`
when you need explicit claims and evidence. The lower-level
`BaseJacsAdapter` also accepts `default_claims`, and its
`sign_output(data, extra_claims=...)` adds per-output claims. Framework wrappers
do not expose all of those arguments.

`client.verify_attestation(attestation_json)` returns `valid`, `crypto`,
`evidence`, `chain` and `errors`; it does not return a top-level `claims`
list. The attestation must already be available in this agent's document store.
Read the [attestation tutorial](attestation-tutorial.md) for exact result keys
and full-verification limits.

Signing and attestation failures raise by default, even when strict mode is off.
The explicit compatibility options `allow_unsigned_output=True` and
`allow_plain_signature_fallback=True` respectively permit unsigned output or
dropping attestation claims. `strict=True` disables those fallbacks.
