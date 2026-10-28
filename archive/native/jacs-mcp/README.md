# JACS native MCP server (`jacs-mcp-compat`)

MCP server for JACS verification and explicitly configured local agent signing.

Uses **stdio transport only**. Verification needs no signing identity or key
setup. An explicitly supplied `--config` or `JACS_CONFIG` is loaded public-only
in the default `verify-only` profile; private keys are never unlocked there.
Local JSON/Agreement signing requires an existing signed agent config; it needs
no server, extra policy file, or new key format.

The checked-in contract snapshot for downstream adapters lives at [`contract/jacs-mcp-contract.json`](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-mcp/contract/jacs-mcp-contract.json).

## Quick start

```bash
cargo install jacs-cli-compat --locked
jacs-compat mcp
```

```json
{
  "mcpServers": {
    "jacs": { "command": "jacs-compat", "args": ["mcp"] }
  }
}
```

For the portable `jacs` executable, use the
[primary MCP guide](https://humanassisted.github.io/JACS/mcp-quickstart.html).

## Protocol compatibility

The server uses [RMCP 3.3.0](https://github.com/modelcontextprotocol/rust-sdk/releases/tag/rmcp-v3.3.0)
with MCP revision `2026-07-28`; legacy `2025-11-25` clients retain their
initialization flow. `tools/list` reports the process's authorized inventory.
Transport is stdio only, with no HTTP, SSE or OAuth listener. See the
[upgrade evidence](https://github.com/HumanAssisted/JACS/blob/main/docs/RMCP_3_UPGRADE_SPIKE.md)
for protocol details.

## What can it do?

The default `verify-only` profile exposes only explicit-key document integrity
verification. The only profile names are `verify-only`,
`local-sign`, `trust-admin`, and compatibility-only `legacy-core`. An explicit
flag wins over the environment and unknown values fail startup. A privileged
profile name alone does not authorize signing. `local-sign` additionally loads
and verifies the operator-selected config and freezes that identity/key for the
process. `trust-admin` and `legacy-core` remain unavailable.

### Explicit local signing

After `jacs-compat init`, start with your existing config and normal keychain/password
source (never send a password as tool input):

```bash
jacs-compat mcp --profile local-sign --config ./jacs.config.json
```

`JACS_CONFIG` can supply the same path instead of `--config`. There is no
implicit config discovery, new-key fallback, or second grant file. The selected
config must be signed and use filesystem storage. Ambient identity/path
overrides are ignored; the password source is resolved at startup.

The closed local inventory is `jacs_sign_document`, `jacs_verify_document`, and
the compiled Agreement-v2 create/apply/sign/verify/detect-conflict/merge/resolve
tools. `jacs_sign_document` always puts the caller's JSON inside `content` of an
ordinary JACS document: even supplied `jacsType`, `$schema`, or signature fields
stay data. The optional MIME label is recorded as `contentType`. Signing and
Agreement tool arguments are limited to 1 MiB. Documents are returned and persisted under
`<config directory>/documents/`; normal encrypted keys and public-key storage
remain on disk. Agreement inspection may read configured local public keys,
but network opt-ins must be off for this local process.

Local signing lets the MCP client sign **as this agent**. It does not prove
human approval, truth, identity, consent-policy acceptance or permission to
publish. `jacsVisibility` and `_jacs_meta` are advisory labels. Verification
checks integrity under the supplied key; the application supplies trust,
freshness, revocation and authorization policy.

Protect the host, config, keys and storage: these tool restrictions do not
sandbox a malicious local owner. Diagnostics go to stderr; stdout is MCP
JSON-RPC only. Startup, verification failures and scope denials emit the
`mcp_local_signing_authorized`, `mcp_verification_failed`,
`mcp_local_signing_denied` and `mcp_tool_scope_denied` events without secrets or
document bodies. A rejected call leaves the process available.

Clients must inspect each response layer. A tool outside the active inventory
returns JSON-RPC `-32602`. Invalid tool arguments return an MCP tool result with
`isError: true`. A dispatched tool can return `isError: false` while its JACS
operation fails. Current handlers return JSON in an MCP `content` item with
`type: "text"`; parse that item's `text` to obtain the per-tool payload. Do not
treat the JSON-RPC `result` or a client-rendered structured view as the JACS
payload itself, and do not assume every tool has a `valid` field.

| Tool | Fields in the parsed JACS payload | Meaning |
|------|----------------------------------|---------|
| `jacs_sign_document` | `success`, `signed_document`, optional `error` | Signing completed and returned a signed JSON string; this is agent-key provenance, not human approval. |
| `jacs_verify_document` | `success`, `valid`, optional `error` | Execution and supplied-key document integrity, respectively; neither establishes identity or authority. |
| Agreement-v2 create/apply/sign/merge/resolve tools | `success`, `agreement`, optional `error` | A document operation completed; its output is not a policy verdict. |
| `jacs_verify_agreement_v2` | `success`, `valid`, `result`, optional `error` | `success` means inspection executed. `valid` stays **false**. Mathematical coverage is `result.cryptographicResult` (`"valid"` or `"invalid"`) and the per-proof entries in `result.partyProofs`. |
| `jacs_detect_agreement_v2_branch_conflict` | `success`, `result`, optional `error` | Branch analysis, not consent or authorization. |
| `jacs_verify_text` | `success`, `status`, `signatures[].status`, optional `error` | Inspect each signature's status. Permissive missing-signature inspection can succeed without a signature. |
| `jacs_verify_image` | `success`, `status`, optional `error` | `status: "valid"` reports image-signature verification; there is no generic top-level `valid` boolean. |

In this table, `result.cryptographicResult` is relative to the **parsed text
payload**, not the JSON-RPC envelope. The Agreement-v2 coverage report has
`overallScope: "consent_signatures_only"` and explicitly unauthenticated role,
quorum, lineage and notary bindings. It does not return a top-level
`mathematicalChecksValid` or a policy-acceptance decision. A mathematically valid
proof, status label or signature count cannot authorize an action. Other tools
retain their own result types; extraction success, for example, is not
verification. Neither transport completion nor signature integrity is an
authorization decision.

To also work with local text and images, explicitly select an existing content
directory at startup:

```bash
JACS_MCP_BASE_DIR=/path/to/content jacs-compat mcp --profile local-sign --config ./jacs.config.json
```

This adds exactly five existing tools: `jacs_sign_text`, `jacs_verify_text`,
`jacs_sign_image`, `jacs_verify_image`, and `jacs_extract_media_signature`.
The same loaded agent signs JSON, Agreements, text and images; media calls do
not reload config or decrypt another key. Without `JACS_MCP_BASE_DIR`, the
nine-tool JSON/Agreement surface stays unchanged (when Agreement tools are
compiled). Setting a content root never expands a verification-only process.

Raw/key APIs, registration, trust administration, key rotation, W3C request signing,
A2A and attestation tools likewise are not enabled by `local-sign`. Their
ordinary CLI/SDK capabilities are unchanged.

The [compiled contract](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-mcp/contract/jacs-mcp-contract.json)
contains all tool names and parameter schemas, including tools unavailable in
current profiles. Use `tools/list` to discover the authorized runtime surface.
CLI and binding DID/A2A exports have separate
[identity and release boundaries](https://github.com/HumanAssisted/JACS/blob/main/docs/identity-standards.md).

## Configuration

Optional:

- `RUST_LOG` - Logging level, default `info,rmcp=warn`
- `JACS_MCP_PROFILE` - one exact closed profile name; defaults to
  `verify-only` and is used only when `--profile` is absent
- `JACS_CONFIG` - existing signed config for local signing; `--config` wins

Local file settings are captured when the authorized signer starts; changing
the environment afterward cannot broaden them:

- `JACS_MCP_BASE_DIR` - Explicit existing directory for the five local file
  tools; absent means no file tools, not a working-directory grant
- `JACS_MCP_OVERWRITE_OK=1` - Explicitly allow file tools to overwrite an
  existing distinct output (disabled by default)
- `JACS_MCP_ALLOW_KEY_DIR=true` - Allow a caller-selected public-key directory
  inside the content root for verification (disabled by default). A valid
  signature using these supplied keys is integrity evidence, not identity or
  application authorization

These retained admin settings do not add tools or grant authority:

- `JACS_MCP_ALLOW_REGISTRATION` - retained handler setting; does not authorize registration
- `JACS_MCP_ALLOW_UNTRUST` - retained handler setting; does not authorize trust administration

### File path policy

File-tool arguments are relative paths beneath `JACS_MCP_BASE_DIR`. Absolute
paths, `.`/`..` traversal, NULs, and symlinks are rejected (including symlinked
ancestors). Hard-linked content files are refused on Unix. The selected
config, encrypted-key directory, agent-data directory, document store and
trust store are excluded even when they sit below the content root.
Case-equivalent reserved names are also refused before a protected backup or
document directory exists.

Signing text or choosing the same image input/output path is an explicit
in-place write. A distinct existing output is refused unless the operator
opts in with `JACS_MCP_OVERWRITE_OK=1`; the caller's `refuse_overwrite:false`
cannot grant that permission. Existing atomic file writes and sibling `.bak`
behavior are retained: text backups are on by default (`no_backup:true` opts
out); in-place/replaced image outputs keep backups. **Backups contain the
original plaintext content**, use owner-only permissions by default, and may
be refreshed on subsequent writes. Backup paths receive the same containment
and protected-material checks before signing. Protect the content directory
and backups as you would the original files.

File startup logs `mcp_local_files_authorized` with the selected directory and
captured options. Rejections are returned as `PATH_POLICY_BLOCKED` in the
existing tool error envelope; scope denials also emit
`mcp_local_signing_denied` at WARN. No extra daemon or file-policy service is
required. These checks constrain MCP requests; they do not isolate a process
from a malicious local host owner changing filesystem state concurrently.

## MIME attachment example

From the repository root, run this POSIX/Python 3.10+ demo with a source-matched
compatibility binary:

```bash
python3 archive/native/examples/mcp_mime_demo.py --jacs-bin /absolute/path/to/source-built/jacs-compat --json
```

It signs a report through local MCP, attaches the exact signed bytes to MIME,
and verifies them in a separate keyless process using an independently supplied
public key. It tests tampering and rejection paths without sending email. The
attachment does not authenticate mail headers, prove human approval or accept
agreement policy. See the [harness](https://github.com/HumanAssisted/JACS/blob/main/archive/native/examples/mcp_mime_demo.py)
for test/provenance details, or the [email API example](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs/examples/email_signing.rs)
for signing the email itself.
