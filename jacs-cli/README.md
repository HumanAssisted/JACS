# JACS CLI

`jacs` is a thin command line over `jacs-core` and the encrypted-file vault shared
with `jacs-mcp`. New agents and key rotations default to `pq2025` (ML-DSA-87).
Explicit `--algorithm ed25519` or `--algorithm es256` supports compatible systems;
rotation cannot downgrade an existing post-quantum identity.

```sh
cargo install jacs-cli
mkdir -m 700 .jacs
jacs create --output .jacs/agent.json > public-identity.json
printf '%s' '{"message":"hello"}' | jacs sign --agent .jacs/agent.json --input - > signed.json
jacs verify --public-identity public-identity.json --input signed.json
```

Passwords are entered through a terminal, with confirmation when creating or
rewrapping keys. Automation can supply `JACS_PRIVATE_KEY_PASSWORD` and, when
rotating or rewrapping, `JACS_NEW_PRIVATE_KEY_PASSWORD` through its secret manager.
Passwords are never command arguments or MCP tool inputs. Use a strong generated
password or passphrase; an encrypted envelope does not make a weak password safe.

| Command | Purpose |
| --- | --- |
| `create --output FILE` | Create and encrypt an agent; stdout contains public identity metadata. |
| `sign --agent FILE --input FILE\|- [--output FILE]` | Unlock for one operation, sign JSON, then clear the signer. |
| `verify --public-identity FILE --input FILE\|-` | Verify against a separately trusted public key and agent ID. |
| `verify --agent FILE --input FILE\|-` | Verify using the bundle's public identity without unlocking. |
| `rotate --agent FILE --output NEWFILE [--algorithm ALG]` | Create a new key and identity version with a proof signed by the old key. |
| `reencrypt --agent FILE --output NEWFILE` | Change the wrapping password; preserve key and identity. |
| `export --agent FILE --output TRANSFERFILE` | Rewrap for transfer under a different password. |
| `import --input TRANSFERFILE --output LOCALFILE` | Authenticate and rewrap under the receiving device's password. |
| `mcp [--profile verify-only]` | Start the public verification MCP tools over stdio. |
| `mcp --profile local-sign --agent FILE` | Unlock the explicitly selected vault for the focused local tools. |

Files holding encrypted agents must live in an existing private directory
(`0700` on Unix); vault files use `0600`. Commands create new destination files
and refuse to overwrite existing identities. Material is the same encrypted
`AgentMaterial` JSON used by browser and mobile bindings. Private keys are never
written or printed in plaintext. A transfer must use a separately shared strong
secret, and its public identity must be compared with a trusted registration or
out-of-band public key before treating the imported identity as someone else's.
Self-signature validation alone does not establish who owns an identity.

The native file vault currently requires Unix owner-only permissions. On Windows
and other platforms where this adapter cannot establish the required file ACL,
private-file operations fail closed. Public-key verification and the verify-only
MCP profile remain available. Browser and mobile secure storage use their own
platform adapters rather than this filesystem vault.

Sign and verify accept JSON up to 4 MiB and reject duplicate member names and
unsafe integer values. Successful verification reports `{"valid":true,...}`;
invalid signatures or identity mismatches report `valid:false` and exit nonzero.
Other failures exit nonzero and report sanitized diagnostics on stderr. Help and
version output are text; operation results are JSON. `RUST_LOG` (or `LOG_LEVEL`)
controls structured stderr logging without contaminating signed JSON or MCP frames.

`mcp` defaults to verification only. In `local-sign`, rotation and re-encryption
use the destination password supplied at startup through
`JACS_NEW_PRIVATE_KEY_PASSWORD`; it is unavailable to tools. The server can only
modify its explicitly configured vault. It has no HTTP transport or remote key
lookup.

The extended Rust CLI is a separate package: `cargo install jacs-cli-compat`
provides the `jacs-compat` executable for agreements, A2A, text/media,
attestations and trust-related commands. Both CLIs are Rust programs; the
split keeps integration dependencies outside the portable workspace. See the
[CLI and MCP profile guide](../docs/native-mcp.md) for their actual scope.
