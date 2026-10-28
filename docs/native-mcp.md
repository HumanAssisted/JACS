# Extended CLI and MCP profiles

The primary entry point is `jacs mcp`, from `cargo install jacs-cli`.
The extended `jacs-compat` binary adds native integration commands for
agreements, A2A, text/media, attestations and trust:

```sh
cargo install jacs-cli-compat --locked
jacs-compat mcp
```

| Rust package | Executable | CLI scope |
|---|---|---|
| `jacs-cli` | `jacs` | Portable document/key operations and focused MCP |
| `jacs-cli-compat` | `jacs-compat` | Extended integration commands and its separately scoped MCP server |

Email signing is Rust-library only; there is no dedicated email CLI command.

From this checkout, `make build-jacs-compat` builds that binary and
`make mcp-compat` starts it without writing Make output to protocol stdout.
These commands select the separate native workspace.

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

Supply the host password through the configured environment, protected password
file or keychain. The MCP signing process does not prompt interactively.
Keep network capability flags unset. File arguments are relative to the selected
content directory; config and key directories cannot be used as content roots.
The selected process can sign as this agent; it does not provide per-call human
approval. Ordinary HAI photo policy remains an application decision.

Only the selected profile's tools are callable. The 42-name compiled contract
includes unavailable tools; `trust-admin` and `legacy-core` refuse startup.

See the [extended MCP protocol and authorization details](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-mcp/README.md).
`make test-jacs-mcp-compat` exercises the native profiles and contract with
`full-tools`; `make test-jacs-mcp` tests the portable server.
