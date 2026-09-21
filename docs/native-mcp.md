# Native MCP profiles

The primary entry point is `jacs mcp`, from `cargo install jacs-cli`.
Existing agreement and media integrations can use the separate native binary:

```sh
cargo install jacs-cli-compat --locked
jacs-compat mcp
```

From this checkout, `make build-jacs-compat` builds that binary and
`make mcp-compat` starts it without writing Make output to protocol stdout.
It uses the separate `archive/native` workspace; the portable dependency graph
is unchanged.

| Server/profile | Runtime tools | Required host configuration |
|---|---|---|
| Portable `jacs mcp`, default | 1: document verification | Explicit public evidence in each request |
| Portable `jacs mcp --profile local-sign` | 7: portable vault lifecycle and document operations | One selected encrypted vault and host-held passwords |
| Native `jacs-compat mcp`, default | 1: document verification | Explicit public evidence in each request |
| Native `local-sign` | 9: document sign/verify plus seven agreement-v2 operations | Existing signed local config, matching unlocked key, offline process |
| Native `local-sign` with a content directory | 14: the nine above plus five text/image tools | Explicit `JACS_MCP_BASE_DIR`, confined separately from config/key storage |

The native CLI compiles the full tool families, but runtime authorization
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

See the [native protocol and authorization details](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-mcp/README.md).
`make test-jacs-mcp-compat` exercises the native profiles and contract with
`full-tools`; `make test-jacs-mcp` tests the portable server.
