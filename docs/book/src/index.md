# Start with MCP

JACS signs structured data and verifies it using explicit public evidence.
MCP is the primary integration. Install the portable CLI and start its stdio
server:

```sh
cargo install jacs-cli --locked
jacs mcp
```

The default profile exposes `jacs_verify_document`. Verification checks integrity
under the supplied public key; identity, consent, trust and permission remain
application decisions. Diagnostics go to stderr and stdout carries only MCP.

Explicit local signing provides create, sign, verify, rotate, re-encrypt and
encrypted import/export operations for one selected vault. New identities use
`pq2025` (ML-DSA-87), without automatic classical fallback. Passwords belong in
the host's prompt or designated environment variable, never in MCP parameters.

See the [complete MCP contract and configuration guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-mcp/README.md)
and [CLI commands](https://github.com/HumanAssisted/JACS/blob/main/jacs-cli/README.md).
The [native MCP profiles](native-mcp.md) provide separate agreement and media
capabilities for existing integrations.
