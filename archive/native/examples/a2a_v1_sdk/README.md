# Current official A2A SDK interoperability

These executable checks use the public JACS Node/Python discovery APIs to export
A2A 1.0 cards with caller-provided skills, input/output modes and an actually
served messaging URL. Each starts a real official SDK JSON-RPC server and uses
an official SDK client to discover the card, verify its signature, request a
report and compare the returned artifact bytes.

| Peer | Pinned SDK | Card signing | Runtime |
| --- | --- | --- | --- |
| JavaScript | `@a2a-js/sdk` 1.3.0, `jose` 6.2.13 | Native ML-DSA-87 root; stock SDK verification | Node 24.7+ with ML-DSA WebCrypto (tested on 24.19.0) |
| Python | `a2a-sdk` 1.3.0 | Explicit ES256 compatibility key, bound to the native ML-DSA-87 root | Python 3.11+ (tested on 3.12.14) |

The JavaScript fixture pins Express **5.3.0** for its local HTTP server. The
lockfile retains the local `@hai.ai/jacs` package reference; install with scripts
disabled as shown below.

The Python SDK's PyJWT signing backend does not provide ML-DSA verification.
Selecting ES256 for that peer is explicit; the identity's native root remains
post-quantum. No SDK verification callback is replaced with a custom signature
algorithm. JACS separately checks the ES256 delegation binding against trusted
native identity evidence.

From the repository root, build this checkout's bindings first (Rust, npm,
Python/maturin and the native platform dependencies are required):

```sh
make build-jacsnpm
make build-jacspy
npm ci --ignore-scripts --prefix archive/native/examples/a2a_v1_sdk
npm test --prefix archive/native/examples/a2a_v1_sdk
```

The local npm dependency uses `archive/native/jacsnpm`, including the native
library produced by its build. For a separately staged source package, set
`JACS_NODE_PACKAGE` to its absolute package directory; the same public `client`
and `a2a-server` exports are exercised.

For Python, install the locked SDK and the freshly built JACS wheel into an
isolated environment, then build the helper that independently checks native
root/binding and document signatures:

```sh
uv venv --python python3 /tmp/jacs-a2a-sdk-env
uv pip sync --python /tmp/jacs-a2a-sdk-env/bin/python archive/native/examples/a2a_v1_peer_requirements.txt
uv pip install --python /tmp/jacs-a2a-sdk-env/bin/python target/native-bindings/artifacts/python/jacs-0.15.0-*.whl
cargo build --locked --manifest-path archive/native/Cargo.toml -p jacs \
  --no-default-features --features a2a --example a2a_v1_peer --target-dir target/a2a-v1-example
/tmp/jacs-a2a-sdk-env/bin/python archive/native/examples/a2a_v1_sdk_python.py \
  --native-bin target/a2a-v1-example/debug/examples/a2a_v1_peer
```

The broader retained Python vector harness uses the same current SDK lock:

```sh
/tmp/jacs-a2a-sdk-env/bin/python archive/native/examples/a2a_v1_peer.py \
  --native-bin target/a2a-v1-example/debug/examples/a2a_v1_peer
```

The JavaScript example resolves and verifies the card before selecting a
transport; a tampered card advertising an extended-card endpoint is rejected
without contacting that endpoint.

Fixtures use generated passwords and disposable identities. They pass only
public documents and separately captured trust evidence to the peer after
removing private files. Negative cases reject modified cards/signatures and
untrusted roots. The local server implements one finite report request; this
is a reproducible integration example, not a complete production agent host.
Default JACS discovery remains the legacy `0.4.0` profile unless `protocolVersion`
is explicitly `1.0`. Signature validity does not grant application authority.
