# Extended CLI and MCP profiles

The primary entry point is `jacs mcp`, from `cargo install jacs-cli`.
Both JACS command-line programs are written in Rust. The focused `jacs` binary
provides portable signing, verification, encrypted keys and MCP. The extended
`jacs-compat` binary provides the broader integration commands, including
agreements, A2A, text/media, attestations and trust operations:

```sh
cargo install jacs-cli-compat --locked
jacs-compat mcp
```

| Rust package | Executable | CLI scope |
|---|---|---|
| `jacs-cli` | `jacs` | Portable document/key operations and focused MCP |
| `jacs-cli-compat` | `jacs-compat` | Extended integration commands and its separately scoped MCP server |

The 0.15 package split isolates the portable dependency graph from the broader
integration dependencies. It does not make either program a different
language, and it does not deprecate the direct libraries. Email signing is
available through the Rust library; there is no dedicated email CLI command.

From this checkout, `make build-jacs-compat` builds that binary and
`make mcp-compat` starts it without writing Make output to protocol stdout.
It uses the separate `archive/native` workspace; the portable dependency graph
is unchanged.

| Server/profile | Runtime tools | Required host configuration |
|---|---|---|
| Portable `jacs mcp`, default | 1: document verification | Explicit public evidence in each request |
| Portable `jacs mcp --profile local-sign` | 7: portable vault lifecycle and document operations | One selected encrypted vault and host-held passwords |
| Extended `jacs-compat mcp`, default | 1: document verification | Explicit public evidence in each request |
| Extended `local-sign` | 9: document sign/verify plus seven agreement-v2 operations | Existing signed local config, matching unlocked key, offline process |
| Extended `local-sign` with a content directory | 14: the nine above plus five text/image tools | Explicit `JACS_MCP_BASE_DIR`, confined separately from config/key storage |

The extended CLI compiles the full tool families, but runtime authorization
restricts the advertised and callable subset. To select an existing local agent:

```sh
jacs-compat mcp --profile local-sign --config /path/to/jacs.config.json
```

For local text/image signing, verification and extraction:

```sh
JACS_MCP_BASE_DIR=/path/to/content \
  jacs-compat mcp --profile local-sign --config /path/to/jacs.config.json
```

Use the existing password prompt or designated password environment variable.
Keep network capability flags unset. File arguments are relative to the selected
content directory; config and key directories cannot be used as content roots.
The selected process can sign as this agent; it does not provide per-call human
approval. Ordinary HAI photo policy remains an application decision.

The 42-name native contract is a compiled inventory. A2A, attestation, trust
administration, W3C signing and key administration are not all enabled by
`local-sign`. `trust-admin` and `legacy-core` still refuse startup because the
capability/status/approval broker they require is absent. Preparing a broader
profile means implementing that authority boundary and testing advertisement,
dispatch, revocation and expiry together. Adding names to an allowlist would
bypass that requirement.

See the [extended MCP protocol and authorization details](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-mcp/README.md).
`make test-jacs-mcp-compat` exercises the native profiles and contract with
`full-tools`; `make test-jacs-mcp` tests the portable server.
