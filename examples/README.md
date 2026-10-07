# JACS examples

Start with [MCP use cases](../USECASES.md) and the
[client connection guide](../docs/mcp-quickstart.md). Direct-library examples
remain available in the native workspace:

| Example | Source |
|---|---|
| Portable Rust sign/verify | [Portable quickstart](../jacs-core/examples/portable_quickstart.rs) |
| Node direct library | [Node quickstart](../archive/native/jacsnpm/examples/quickstart.js) |
| Python direct library | [Python quickstart](../archive/native/jacspy/examples/quickstart.py) |
| A2A trust policies | [Python](../archive/native/examples/a2a_trust_demo.py), [TypeScript](../archive/native/examples/a2a_trust_demo.ts) |
| Agreement v2 | [Three-party Python example](../archive/native/examples/agreement_v2_three_party.py) |
| Email signing and verification | [Rust](../archive/native/jacs/examples/email_signing.rs), [MCP/MIME flow](../archive/native/examples/mcp_mime_demo.py) |
| Attestations | [Python](../archive/native/examples/attestation_hello_world.py), [Node](../archive/native/examples/attestation_hello_world.js) |
| Framework integration | [Node LangChain](../archive/native/jacsnpm/examples/langchain/README.md), [Python adapters](../archive/native/jacs/docs/jacsbook/src/python/adapters.md) |

These links restore discoverability without duplicating the maintained source.
Some examples predate the native workspace move, use explicit classical
algorithms for compatibility, or expect generated local fixtures. Use the
[current installation guide](../docs/libraries.md), translate extended CLI
commands to `jacs-compat`, and generate fresh test identities in temporary
directories. New-agent examples should default to `pq2025`; never fall back
after a crypto error.

The release checks cover installed consumers and selected compatibility
flows. They do not establish that every example above currently runs. The
[restoration audit](../docs/repository-restoration-audit.md) tracks the remaining
work to repair examples and restore their CI coverage without restoring
removed private key fixtures.
