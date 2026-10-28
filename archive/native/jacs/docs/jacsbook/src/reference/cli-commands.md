# CLI Command Reference

This page provides a comprehensive reference for all JACS command-line interface commands. For a workflow-oriented tutorial, see [CLI Tutorial](../rust/cli.md). For practical scripting examples, see [CLI Examples](../examples/cli.md).

## Global Commands

### `jacs-compat --version`
Prints version and build information for the JACS installation.

```bash
jacs-compat --version
```

### `jacs-compat quickstart`
Create a persistent agent with keys on disk and optionally sign data -- no manual setup needed. If `./jacs.config.json` already exists, loads it; otherwise creates a new agent. Agent, keys, and config are saved to `./jacs_data`, `./jacs_keys`, and `./jacs.config.json`. Password is required: set `JACS_PRIVATE_KEY_PASSWORD` (recommended) or `JACS_PASSWORD_FILE` (CLI file bootstrap). Set exactly one explicit source; if both are set, CLI exits with an error. This is the fastest way to start using JACS.

```bash
# Print agent info (ID, algorithm)
jacs-compat quickstart --name my-agent --domain my-agent.example.com

# Sign JSON from stdin
echo '{"action":"approve"}' | jacs-compat quickstart --name my-agent --domain my-agent.example.com --sign

# Sign a file
jacs-compat quickstart --name my-agent --domain my-agent.example.com --sign --file mydata.json
```

**Options:**
- `--name <name>` - Agent name used for first-time quickstart creation (required)
- `--domain <domain>` - Agent domain used for DNS/public-key verification workflows (required)
- `--algorithm <algo>` - Signing algorithm: `pq2025` (default) or `ed25519`; the legacy input alias `ring-Ed25519` is also accepted and the canonical Ed25519 wire label remains `ring-Ed25519`
- `--sign` - Sign input (from stdin or `--file`) instead of printing info
- `--file <path>` - Read JSON input from file instead of stdin (requires `--sign`)

### `jacs-compat verify`
Verify a signed JACS document. No agent or config file required -- the CLI creates an ephemeral verifier if needed.

```bash
# Verify a local file
jacs-compat verify signed-document.json

# JSON output (for scripting)
jacs-compat verify signed-document.json --json

# Verify a remote document
jacs-compat verify --remote https://example.com/signed-doc.json

# Specify a directory of public keys
jacs-compat verify signed-document.json --key-dir ./trusted-keys/
```

**Options:**
- `<file>` - Path to the signed JACS JSON file (positional, required unless `--remote` is used)
- `--remote <url>` - Fetch document from URL before verifying
- `--json` - Output result as JSON (`{"valid": true, "signerId": "...", "timestamp": "..."}`)
- `--key-dir <dir>` - Directory containing public keys for verification

**Exit codes:** `0` for valid, `1` for invalid or error.

**Output (text):**
```
Status:    VALID
Signer:    550e8400-e29b-41d4-a716-446655440000
Signed at: 2026-02-10T12:00:00Z
```

**Output (JSON):**
```json
{
  "valid": true,
  "signerId": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-10T12:00:00Z"
}
```

If `./jacs.config.json` and agent keys exist in the current directory, the CLI uses them automatically. Otherwise it creates a temporary ephemeral verifier internally.

See the [Verification Guide](../getting-started/verification.md) for Python, Node.js, and DNS verification workflows.

### `jacs-compat keychain`

Manage private key passwords in the OS keychain (macOS Keychain or Linux Secret Service via D-Bus). This allows JACS to retrieve your private key password without environment variables or password files.

> Requires the `keychain` feature (enabled by default in `jacs-cli-compat`).
> Set `JACS_KEYCHAIN_BACKEND=disabled` to skip keychain lookups in CI/headless environments.

Every keychain command requires `--agent-id` so that each agent's password is stored separately. This prevents collisions when multiple agents coexist on the same machine.

```bash
# Store a password interactively (prompts for input)
jacs-compat keychain set --agent-id <AGENT_UUID>

# Retrieve the stored password (prints to stdout, for piping)
export JACS_PRIVATE_KEY_PASSWORD=$(jacs-compat keychain get --agent-id <AGENT_UUID>)

# Remove the stored password
jacs-compat keychain delete --agent-id <AGENT_UUID>

# Check keychain availability and whether a password is stored
jacs-compat keychain status --agent-id <AGENT_UUID>
```

| Subcommand | Description |
|------------|-------------|
| `jacs-compat keychain set --agent-id <ID>` | Store a password for an agent (prompts interactively) |
| `jacs-compat keychain get --agent-id <ID>` | Print stored password to stdout |
| `jacs-compat keychain delete --agent-id <ID>` | Remove stored password from OS keychain |
| `jacs-compat keychain status --agent-id <ID>` | Check keychain availability and storage state |

**Output conventions:** Human-friendly messages go to stderr; machine-friendly data goes to stdout. This means `jacs-compat keychain get` output can be safely piped or captured in a variable.

**Password resolution order:** When JACS needs the private key password, it checks sources in this order:
1. `JACS_PRIVATE_KEY_PASSWORD` environment variable (highest priority)
2. `JACS_PASSWORD_FILE` / legacy `.jacs_password` file
3. OS keychain keyed by agent ID (if `keychain` feature is enabled and not disabled)

### `jacs-compat init`
Initialize JACS by creating both configuration and agent (with cryptographic keys). Use this for persistent agent setup. New agents get the selected native root (`pq2025` by default) plus an ES256 ecosystem compatibility key; pass `--no-compat-key` to skip the compatibility key (minimal/air-gapped agents).

```bash
jacs-compat init
jacs-compat init --no-compat-key
```

### `jacs-compat --help`
Print help information for JACS commands.

```bash
jacs-compat [COMMAND] --help
```

## Configuration Commands

### `jacs-compat config`
Work with JACS configuration settings.

```bash
jacs-compat config [SUBCOMMAND]
```

*Note: Specific subcommands for config are not detailed in the current help output.*

## Agent Commands

### `jacs-compat agent`
Work with JACS agents - the cryptographic identities that sign and verify documents.

```bash
jacs-compat agent [SUBCOMMAND]
```

### `jacs-compat agent add-compat-key`
Add the ES256 `ecosystem_signing` compatibility key to an existing agent (explicit migration — loading never creates key material). New agents mint this key at creation unless `--no-compat-key` was used. Errors if the key already exists.

```bash
jacs-compat agent add-compat-key [--config ./jacs.config.json]
```

### `jacs-compat agent issue-compat-binding`
Issue (or re-issue) the native-root-signed compatibility key binding. Content scopes (`ap2-mandate`, `agreement-vc`) are never auto-issued — grant them here explicitly. This is also the re-issue path after `agent rotate-keys` (a binding signed by a previous root no longer authorizes exports). The same grant is available from language bindings as `issue_compat_binding_json(scopes_json, expires_at)` (scopes as a JSON array, e.g. `["jwks","did","ap2-mandate"]`), so Python/Node/Go callers can enable content exports without shelling out to the CLI.

```bash
# default: identity scopes only (jwks,did,a2a-agent-card,w3c-agent-identity)
jacs-compat agent issue-compat-binding

# grant a content scope explicitly
jacs-compat agent issue-compat-binding --scopes jwks,did,a2a-agent-card,w3c-agent-identity,ap2-mandate

# optional expiry (RFC 3339)
jacs-compat agent issue-compat-binding --expires-at 2027-01-01T00:00:00Z
```

## Agreement VC Export

### `jacs-compat agreement-v2 export-vc`
Export an Agreement-v2 document as a W3C Verifiable Credential with an `ecdsa-jcs-2019` Data Integrity proof (W3C vc-di-ecdsa, Multikey verification method). Requires the `agreement-vc` binding scope. The native agreement is unchanged; incoming VC verification is out of scope.

```bash
jacs-compat agreement-v2 export-vc --agreement agreement.json   # file path
cat agreement.json | jacs-compat agreement-v2 export-vc --agreement -  # stdin
```

## AP2 Commands

### `jacs-compat ap2 export-mandate`
Export the AP2 merchant-authorization mandate for a UCP checkout as a detached ES256 JWS (UCP AP2-Mandates extension, rev 2026-01-23). Requires the `ap2-mandate` binding scope. Input is validated against the named ap2-mandate schema; user-side AP2 Checkout Mandates (SD-JWT-VC) are out of scope. See [AP2 Mandate Export](../integrations/ap2.md).

```bash
jacs-compat ap2 export-mandate --input checkout.json          # file path
jacs-compat ap2 export-mandate --input '{"id":"c1", ... }'    # inline JSON
cat checkout.json | jacs-compat ap2 export-mandate --input -  # stdin
```

## Document Commands

The `jacs-compat document` command provides comprehensive document management capabilities.

### `jacs-compat document create`
Create a new JACS document, either by embedding or parsing a document with optional file attachments.

**Usage:**
```bash
jacs-compat document create [OPTIONS]
```

**Options:**
- `-a <agent-file>` - Path to the agent file. If not specified, uses config `jacs_agent_id_and_version`
- `-f <filename>` - Path to input file. Must be JSON format
- `-o, --output <output>` - Output filename for the created document (cannot be combined with `--directory`)
- `-d <directory>` - Path to directory of files. Files should end with `.json`
- `-v, --verbose` - Enable verbose output
- `--json` - Emit a machine-readable result containing each document key and saved path
- `-n, --no-save` - Instead of saving files, print to stdout
- `-s, --schema <schema>` - Path to JSON schema file to use for validation
- `--attach <attach>` - Path to file or directory for file attachments
- `-e, --embed <embed>` - Embed documents or keep them external [possible values: true, false]
- `-h, --help` - Print help information

**Examples:**
```bash
# Create document from JSON file
jacs-compat document create -f my-document.json
# Prints: Saved signed document: <actual path>

# Create document with embedded attachment
jacs-compat document create -f document.json --attach ./image.jpg --embed true

# Create document with referenced attachment
jacs-compat document create -f document.json --attach ./data.csv --embed false

# Create from directory of JSON files
jacs-compat document create -d ./documents/

# Create with custom schema validation
jacs-compat document create -f document.json -s custom-schema.json

# Print to stdout instead of saving
jacs-compat document create -f document.json --no-save
```

### `jacs-compat document update`
Create a new version of an existing document. Requires both the original JACS file and the modified JACS metadata.

**Usage:**
```bash
jacs-compat document update [OPTIONS]
```

**Options:**
- `-a <agent-file>` - Path to the agent file
- `-f <filename>` - Path to original document file
- `-n <new-file>` - Path to new/modified document file
- `-o <output>` - Output filename for updated document
- `-v, --verbose` - Enable verbose output
- `-n, --no-save` - Print to stdout instead of saving
- `-s, --schema <schema>` - Path to JSON schema file for validation
- `--attach <attach>` - Path to file or directory for additional attachments
- `-e, --embed <embed>` - Embed new attachments or keep them external
- `-h, --help` - Print help information

**Example:**
```bash
# Update document with new version
jacs-compat document update -f original.json -n modified.json -o updated.json

# Update and add new attachments
jacs-compat document update -f original.json -n modified.json --attach ./new-file.pdf --embed false
```

### `jacs-compat document verify`
Verify a document's hash, signatures, and schema compliance.

**Usage:**
```bash
jacs-compat document verify [OPTIONS]
```

**Options:**
- `-a <agent-file>` - Path to the agent file
- `-f <filename>` - Path to input file. Must be JSON format
- `-d <directory>` - Path to directory of files. Files should end with `.json`
- `-v, --verbose` - Enable verbose output
- `-s, --schema <schema>` - Path to JSON schema file to use for validation
- `-h, --help` - Print help information

**Examples:**
```bash
# Verify single document
jacs-compat document verify -f signed-document.json

# Verify all documents in directory
jacs-compat document verify -d ./documents/

# Verify with custom schema
jacs-compat document verify -f document.json -s custom-schema.json
```

**Verification Process:**
1. **Hash verification** - Confirms document integrity
2. **Signature verification** - Validates cryptographic signatures
3. **Schema validation** - Ensures document structure compliance
4. **File integrity** - Checks SHA256 checksums of attached files

### `jacs-compat document extract`
Extract embedded file contents from documents back to the filesystem.

**Usage:**
```bash
jacs-compat document extract [OPTIONS]
```

**Options:**
- `-a <agent-file>` - Path to the agent file
- `-f <filename>` - Path to input file containing embedded files
- `-d <directory>` - Path to directory of files to process
- `-s, --schema <schema>` - Path to JSON schema file for validation
- `-h, --help` - Print help information

**Examples:**
```bash
# Extract embedded files from single document
jacs-compat document extract -f document-with-embedded-files.json

# Extract from all documents in directory
jacs-compat document extract -d ./documents/
```

**Extract Process:**
1. Reads embedded file contents from document
2. Decodes base64-encoded data
3. Writes files to their original paths
4. Creates backup of existing files (with timestamp)

### Agreement Commands

The `jacs-compat agreement-v2` commands inspect native compatibility agreement
documents; mathematical validity is separate from application policy acceptance.
The `jacs-compat document *-agreement` commands below inspect legacy sidecar
signatures without authenticating their participant or quorum policy. New
portable consent uses
[Agreement v3](https://docs.rs/jacs-core/latest/jacs_core/agreements/v3/index.html).

#### `jacs-compat document check-agreement`
Given a document, provide a list of agents that should sign the document.

**Usage:**
```bash
jacs-compat document check-agreement [OPTIONS]
```

#### `jacs-compat document create-agreement`
Create an agreement structure for a document that requires multiple agent signatures.

**Usage:**
```bash
jacs-compat document create-agreement [OPTIONS]
```

#### `jacs-compat document sign-agreement`
Sign the agreement section of a document with the current agent's cryptographic signature.

**Usage:**
```bash
jacs-compat document sign-agreement [OPTIONS]
```

### `jacs-compat agreement-v2`

Standalone Agreement v2 documents provide compatibility inspection, not consent-policy acceptance. Each is a self-contained, cryptographically signed `jacsType: "agreement"` artifact — terms, parties, signature policy (quorum, required roles), an optional transcript, links, controllers, and owners — with its own content hash and version chain. Running `jacs-compat agreement-v2` with no subcommand prints help and exits non-zero.

Typical order: **create → sign → verify**. Use `apply` to evolve an agreement via a typed mutation; use the branch commands when two agents diverge from the same prior version.

#### `jacs-compat agreement-v2 create`
Create a standalone agreement v2 document from a `CreateAgreementV2` JSON input.

```bash
jacs-compat agreement-v2 create --input <CreateAgreementV2 JSON | path | ->
```

#### `jacs-compat agreement-v2 sign`
Add this agent's signature as a `signer`, `witness`, or `notary`.

```bash
jacs-compat agreement-v2 sign --agreement <JSON | path | -> [--role signer|witness|notary]
```

`--role` defaults to `signer`.

#### `jacs-compat agreement-v2 verify`
Recompute the agreement and transcript hashes and re-check quorum, roles, status, and every signature. Exits non-zero when the agreement is invalid.

```bash
jacs-compat agreement-v2 verify --agreement <JSON | path | ->
```

#### `jacs-compat agreement-v2 apply`
Apply a typed mutation (`appendTranscript`, `updateTerms`, `setStatus`, `addLink`, `setParties`, `setPolicy`, `setOwners`) and emit a successor version. Mutation fields are camelCase.

```bash
jacs-compat agreement-v2 apply --agreement <JSON | path | -> --mutation <mutation JSON | path>
```

#### `jacs-compat agreement-v2 detect-conflict`
Report whether two successor versions of `--base` are transcript-only (auto-mergeable) or conflict on consent-scope fields.

```bash
jacs-compat agreement-v2 detect-conflict --base <common ancestor> --left <branch> --right <branch>
```

#### `jacs-compat agreement-v2 merge-transcript`
Auto-merge two transcript-only branches of `--base` into one successor version.

```bash
jacs-compat agreement-v2 merge-transcript --base <common ancestor> --left <branch> --right <branch>
```

#### `jacs-compat agreement-v2 resolve-conflict`
Resolve a consent-scope conflict by rebasing an explicit mutation onto `--previous`; the divergent `--side-branch` is recorded as a link on the result.

```bash
jacs-compat agreement-v2 resolve-conflict \
  --base <common ancestor> \
  --previous <branch you keep> \
  --side-branch <divergent branch> \
  --mutation <resolving mutation JSON | path>
```

`--side-branch` replaces the older `--side` flag; `--side` still works as a hidden alias for backward compatibility.

## Provenance Commands

The provenance commands sign and verify content **in place** — text files keep a YAML-bodied signature block at the end of the file, images carry the signature in a metadata chunk. See the [Inline Text Signatures](../guides/inline-text-signing.md) and [Image and Media Signatures](../guides/media-signing.md) guides for the full feature set.

### `jacs-compat sign-text`

Append a YAML-bodied JACS signature block to the end of a markdown or text file. The file content (everything before the first signature block) is preserved byte-for-byte.

**Usage:**
```bash
jacs-compat sign-text <file>
```

The command refuses (hard error) to sign input that contains a column-zero `-----BEGIN JACS SIGNATURE-----` line outside a valid block — see the inline-text-signing guide for documented workarounds.

### `jacs-compat verify-text`

Verify all signature blocks in a text file. Permissive by default — missing signatures are exit code `2`, not a thrown error. Per-signer status is printed to stdout.

**Usage:**
```bash
jacs-compat verify-text <file> [--strict] [--key-dir <dir>]
```

Options:
- `--strict` — treat missing signature as exit `1` (instead of `2`); stderr: `no JACS signature found`.
- `--key-dir <dir>` — directory of `<signer_id>.public.pem` files used in addition to the local trust store.

### `jacs-compat sign-image`

Embed a JACS signature inside a PNG, JPEG, or WebP image. The signature lives in a metadata chunk (PNG iTXt / JPEG APP11 / WebP XMP).

**Usage:**
```bash
jacs-compat sign-image <input> --out <output> [--robust] [--refuse-overwrite]
```

Options:
- `--out <path>` — output file (required).
- `--robust` — opt-in LSB embedding fallback for PNG/JPEG (off by default; WebP deferred).
- `--refuse-overwrite` — exit non-zero if the input already carries a JACS signature (default is overwrite).

### `jacs-compat verify-image`

Verify the embedded signature on an image. Same permissive / strict model as `verify-text`.

**Usage:**
```bash
jacs-compat verify-image <file> [--strict] [--key-dir <dir>]
```

### `jacs-compat extract-media-signature`

Extract the embedded signature payload without verifying it.

**Usage:**
```bash
jacs-compat extract-media-signature <file> [--raw-payload]
```

Options:
- `--raw-payload` — emit the base64url wire form instead of decoded JSON.

## Common Patterns

### Basic Document Lifecycle
```bash
# 1. Initialize JACS
jacs-compat init

# 2. Create document with attachments
jacs-compat document create -f document.json --attach ./files/ --embed true

# 3. Verify document integrity
jacs-compat document verify -f created-document.json

# 4. Update document if needed
jacs-compat document update -f original.json -n modified.json

# 5. Extract embedded files when needed
jacs-compat document extract -f document.json
```

### Working with Attachments
```bash
# Embed small files for portability
jacs-compat document create -f doc.json --attach ./small-image.png --embed true

# Reference large files to save space
jacs-compat document create -f doc.json --attach ./large-video.mp4 --embed false

# Attach multiple files from directory
jacs-compat document create -f doc.json --attach ./attachments/ --embed false
```

### Schema Validation Workflow
```bash
# Create with schema validation
jacs-compat document create -f document.json -s schema.json

# Verify against specific schema
jacs-compat document verify -f document.json -s schema.json
```

## Global Options

Most commands support these common options:

- `-h, --help` - Show help information
- `-v, --verbose` - Enable verbose output for debugging

## Exit Codes

See [CLI exit codes](errors.md#cli-exit-codes). Inspect the command's result
fields as well as process status; Agreement v2 inspection never grants policy
acceptance.

## Environment Variables

- `JACS_CONFIG` - Override default configuration file location
- `JACS_DATA_DIRECTORY` - Override default data directory location

## File Formats

### Input Files
- **JSON documents** - Must be valid JSON format
- **Schema files** - JSON Schema format (draft-07 compatible)
- **Agent files** - JACS agent format with cryptographic keys
- **Attachments** - Any file type (automatically detected MIME type)

### Output Files
- **JACS documents** - JSON format with JACS metadata, signatures, and checksums
- **Extracted files** - Original format of embedded attachments
