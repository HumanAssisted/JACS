# Testing JACS Integrations

Test real signing and verification at the boundary where your application accepts
data. Keep cryptographic validity, identity trust, authorization and replay policy
as separate assertions.

## A real Python fixture

An empty config does not create an agent or keys. Use an ephemeral agent for
isolated tests:

```python
import json
import pytest
from jacs.client import JacsClient

@pytest.fixture
def client():
    return JacsClient.ephemeral()

def test_signed_result_and_tamper_rejection(client):
    signed = client.sign_message({"answer": 42})
    assert client.verify(signed.raw).valid

    tampered = json.loads(signed.raw)
    tampered["content"] = {"answer": 43}
    assert not client.verify(tampered).valid

def test_invalid_json_is_rejected(client):
    assert not client.verify("not JSON").valid
```

Install `jacs` and `pytest`, save this as `test_signing.py`, then run:

```bash
python -m pytest -q test_signing.py
```

New ephemeral agents default to `pq2025`. For persistent-agent tests use
`JacsClient.quickstart(name=..., domain=..., config_path=...)` in a private
temporary directory with a test-only password supplied through host secret
handling. An existing config must refer to a real agent and keys. Do not rely on
undocumented `JACS_TEST_MODE` or `JACS_TEST_CONFIG` switches.

## Test the trust boundary

Cover valid signatures, changed payloads and metadata, malformed input, wrong
keys, unexpected signer IDs, and missing signatures. For multiple agents,
explicitly provision trusted public keys; creating two agents does not
automatically enroll one in the other's trust store.

A passing signature test does not prove authorization. Test denied actions,
revoked or expired trust, and mismatched purpose/audience separately. Legacy
agreement inspection deliberately leaves consent-policy acceptance false;
never write a test that grants permission merely because a signature count or
claimed agreement status looks complete.

For request authentication, mutate method, URL/query, exact body bytes and
audience independently. For replay protection, test duplicate delivery,
expiry, cache/store failure and concurrent attempts against the same shared
store. A process-local cache does not establish protection across workers.

## Test framework behavior explicitly

Python FastAPI middleware checks signed POST JSON bodies. Unsigned or non-JSON
requests and other methods can pass through even with `strict=True`; test your
separate authentication requirement. Test signing failure, verification failure
and any explicitly enabled fallback without returning unmarked trusted data.

MCP tests should start the actual chosen server, negotiate a session, list tools,
call a tool and inspect its returned payload. The portable `jacs mcp` starts
verify-only by default. Python's signed local HTTP wrapper requires both peers
to use JACS wrappers and trust policy; a normal MCP client is not a substitute
in that transport test. Test unexpected peers and response correlation failures.

Await asynchronous Node APIs such as `load()` and `createDocument()`.
See the maintained [Python tests](https://github.com/HumanAssisted/JACS/tree/main/archive/native/jacspy/tests),
[Node tests](https://github.com/HumanAssisted/JACS/tree/main/archive/native/jacsnpm/tests)
and [Go tests](https://github.com/HumanAssisted/JACS/tree/main/archive/native/jacsgo)
for executable fixtures.

## Mocks and release validation

Mocks help test application error handling, but cannot establish canonicalization,
signature interoperability or key-resolution behavior. Retain real negative
tests and cross-language fixtures. Test the installed package in a clean
consumer separately from the source checkout; published artifacts may differ
from later source fixes.

For repository changes, use the root contributor instructions and
[native development guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md)
for current commands. Select focused tests first, then the required workspace
and release gates. Keep trust stores, configuration, environment and filesystem
state isolated; never use a production private key in tests.

See [security](security.md), [trust store](trust-store.md), and
[custom evidence adapters](../guides/custom-adapters.md).
