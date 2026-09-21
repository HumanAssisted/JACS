# JACS use cases

Start with MCP when an agent or tool host needs local signing and verification.
Rust, Node.js, Python, Go, browser and mobile libraries remain available for
embedding the same primitives in an application. Choose the integration by its
actual capabilities and the authority the host is prepared to grant.

## Verify an artifact before using it

Use the default `jacs mcp` server to check signed JSON received from another
agent, tool or service. It needs no signing identity or private key.

1. The host selects the expected signer's public key and algorithm from its
   trusted state, independently of the received document.
2. Call `jacs_verify_document` with the signed JSON and that public evidence.
3. Parse the JSON text in the MCP result and require `valid: true`. A successful
   JSON-RPC response alone is insufficient.
4. Apply the application's identity, freshness, revocation and authorization
   policy before acting on the verified content.

This is useful for agent handoffs, signed tool outputs, stored memories,
configuration and audit records. It verifies integrity under the chosen key;
the application decides whether to trust and use the result.

## Sign agent output with one selected identity

Use portable `local-sign` to sign JSON before it leaves an agent or service.
The host selects one encrypted vault and supplies its password outside the
tool request. The process can create, sign, verify, rotate, re-encrypt and
import/export encrypted material within that vault.

The grant applies to the process. Applications that need human approval for
each signature must enforce it in their own host flow. New identities use
`pq2025` (ML-DSA-87), and an error never triggers an algorithm downgrade.

See the [MCP configuration guide](https://github.com/HumanAssisted/JACS/blob/main/docs/mcp-quickstart.md)
and [portable tool contract](https://github.com/HumanAssisted/JACS/blob/main/jacs-mcp/README.md).

## Record agreements and review text or images

The separate `jacs-compat mcp` server's extended `local-sign` profile provides
document signing and Agreement v2 operations. An explicit content directory
also enables text/image signing, verification and signature extraction.

Use these for signed agreement transcripts, reviewed documents and media
provenance. The host selects the agent and content directory; a tool cannot
choose arbitrary key storage or filesystem roots. The exact 1/9/14-tool
profiles are documented in the [extended MCP guide](https://github.com/HumanAssisted/JACS/blob/main/docs/native-mcp.md).

## Embed JACS in a service or application

Direct libraries retain capabilities beyond the portable MCP tool set:

| Use case | Starting point |
|---|---|
| JSON signing, verification and encrypted identity lifecycle | Portable Rust core, native Rust, Node.js, Python, Go, browser or mobile; select the relevant [library guide](https://github.com/HumanAssisted/JACS/blob/main/docs/libraries.md) |
| Request-bound HTTP authentication and signed response/event envelopes | Native Rust and Node/Python/Go instance APIs |
| A2A discovery and signed artifact exchange | [A2A quickstart](https://github.com/HumanAssisted/JACS/blob/main/A2A_QUICKSTART.md); language wrappers and extended CLI have their own feature rules |
| MIME email signatures and PNG logo embedding | Native Rust [email guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs/docs/jacsbook/src/guides/email-signing.md) and HAI SDK email integration |
| Attestations, trust policies, W3C interoperability and framework adapters | [Native integration reference](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs/docs/jacsbook/src/SUMMARY.md); availability depends on the package and enabled features |
| Durable signed-document storage | `jacs-duckdb`, `jacs-redb`, `jacs-postgresql`, `jacs-surrealdb` |

The compiled native MCP inventory has 42 names. Only the selected runtime
profile's authorized subset is callable; installing a library does not expose
all of its APIs as MCP tools. See the [example index](https://github.com/HumanAssisted/JACS/blob/main/examples/README.md)
for retained examples and their validation limits.
