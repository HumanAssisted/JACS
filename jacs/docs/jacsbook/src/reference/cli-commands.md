# CLI Command Reference

This page provides a comprehensive reference for all JACS command-line interface commands.

## Global Commands

### `jacs version`
Prints version and build information for the JACS installation.

```bash
jacs version
```

### `jacs quickstart`
Create a persistent agent with keys on disk and optionally sign data -- no manual setup needed. If `./jacs.config.json` already exists, loads it; otherwise creates a new agent. Agent, keys, and config are saved to `./jacs_data`, `./jacs_keys`, and `./jacs.config.json`. If `JACS_PRIVATE_KEY_PASSWORD` is not set, a secure password is auto-generated and saved to `./jacs_keys/.jacs_password`. This is the fastest way to start using JACS.

```bash
# Print agent info (ID, algorithm)
jacs quickstart

# Sign JSON from stdin
echo '{"action":"approve"}' | jacs quickstart --sign

# Sign a file
jacs quickstart --sign --file mydata.json

# Use a specific algorithm
jacs quickstart --algorithm ring-Ed25519
```

**Options:**
- `--algorithm <algo>` - Signing algorithm (default: `pq2025`). Also: `ring-Ed25519`, `RSA-PSS`
- `--sign` - Sign input (from stdin or `--file`) instead of printing info
- `--file <path>` - Read JSON input from file instead of stdin (requires `--sign`)

### `jacs verify`
Verify a signed JACS document. No agent or config file required -- the CLI creates an ephemeral verifier if needed.

```bash
# Verify a local file
jacs verify signed-document.json

# JSON output (for scripting)
jacs verify signed-document.json --json

# Verify a remote document
jacs verify --remote https://example.com/signed-doc.json

# Specify a directory of public keys
jacs verify signed-document.json --key-dir ./trusted-keys/
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

### `jacs init`
Initialize JACS by creating both configuration and agent (with cryptographic keys). Use this for persistent agent setup.

```bash
jacs init
```

### `jacs help`
Print help information for JACS commands.

```bash
jacs help [COMMAND]
```

## Configuration Commands

### `jacs config`
Work with JACS configuration settings.

```bash
jacs config [SUBCOMMAND]
```

*Note: Specific subcommands for config are not detailed in the current help output.*

## Agent Commands

### `jacs agent`
Work with JACS agents - the cryptographic identities that sign and verify documents.

```bash
jacs agent [SUBCOMMAND]
```

*Note: Specific subcommands for agent management are not detailed in the current help output.*

## Task Commands

### `jacs task`
Work with JACS agent tasks - structured workflows between agents.

```bash
jacs task [SUBCOMMAND]
```

*Note: Specific subcommands for task management are not detailed in the current help output.*

## Document Commands

The `jacs document` command provides comprehensive document management capabilities.

### `jacs document create`
Create a new JACS document, either by embedding or parsing a document with optional file attachments.

**Usage:**
```bash
jacs document create [OPTIONS]
```

**Options:**
- `-a <agent-file>` - Path to the agent file. If not specified, uses config `jacs_agent_id_and_version`
- `-f <filename>` - Path to input file. Must be JSON format
- `-o <output>` - Output filename for the created document
- `-d <directory>` - Path to directory of files. Files should end with `.json`
- `-v, --verbose` - Enable verbose output
- `-n, --no-save` - Instead of saving files, print to stdout
- `-s, --schema <schema>` - Path to JSON schema file to use for validation
- `--attach <attach>` - Path to file or directory for file attachments
- `-e, --embed <embed>` - Embed documents or keep them external [possible values: true, false]
- `-h, --help` - Print help information

**Examples:**
```bash
# Create document from JSON file
jacs document create -f my-document.json

# Create document with embedded attachment
jacs document create -f document.json --attach ./image.jpg --embed true

# Create document with referenced attachment
jacs document create -f document.json --attach ./data.csv --embed false

# Create from directory of JSON files
jacs document create -d ./documents/

# Create with custom schema validation
jacs document create -f document.json -s custom-schema.json

# Print to stdout instead of saving
jacs document create -f document.json --no-save
```

### `jacs document update`
Create a new version of an existing document. Requires both the original JACS file and the modified JACS metadata.

**Usage:**
```bash
jacs document update [OPTIONS]
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
jacs document update -f original.json -n modified.json -o updated.json

# Update and add new attachments
jacs document update -f original.json -n modified.json --attach ./new-file.pdf --embed false
```

### `jacs document verify`
Verify a document's hash, signatures, and schema compliance.

**Usage:**
```bash
jacs document verify [OPTIONS]
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
jacs document verify -f signed-document.json

# Verify all documents in directory
jacs document verify -d ./documents/

# Verify with custom schema
jacs document verify -f document.json -s custom-schema.json
```

**Verification Process:**
1. **Hash verification** - Confirms document integrity
2. **Signature verification** - Validates cryptographic signatures
3. **Schema validation** - Ensures document structure compliance
4. **File integrity** - Checks SHA256 checksums of attached files

### `jacs document extract`
Extract embedded file contents from documents back to the filesystem.

**Usage:**
```bash
jacs document extract [OPTIONS]
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
jacs document extract -f document-with-embedded-files.json

# Extract from all documents in directory  
jacs document extract -d ./documents/
```

**Extract Process:**
1. Reads embedded file contents from document
2. Decodes base64-encoded data
3. Writes files to their original paths
4. Creates backup of existing files (with timestamp)

### Agreement Commands

JACS provides specialized commands for managing multi-agent agreements.

#### `jacs document check-agreement`
Given a document, provide a list of agents that should sign the document.

**Usage:**
```bash
jacs document check-agreement [OPTIONS]
```

#### `jacs document create-agreement`
Create an agreement structure for a document that requires multiple agent signatures.

**Usage:**
```bash
jacs document create-agreement [OPTIONS]
```

#### `jacs document sign-agreement`
Sign the agreement section of a document with the current agent's cryptographic signature.

**Usage:**
```bash
jacs document sign-agreement [OPTIONS]
```

## Common Patterns

### Basic Document Lifecycle
```bash
# 1. Initialize JACS
jacs init

# 2. Create document with attachments
jacs document create -f document.json --attach ./files/ --embed true

# 3. Verify document integrity
jacs document verify -f created-document.json

# 4. Update document if needed
jacs document update -f original.json -n modified.json

# 5. Extract embedded files when needed
jacs document extract -f document.json
```

### Working with Attachments
```bash
# Embed small files for portability
jacs document create -f doc.json --attach ./small-image.png --embed true

# Reference large files to save space
jacs document create -f doc.json --attach ./large-video.mp4 --embed false

# Attach multiple files from directory
jacs document create -f doc.json --attach ./attachments/ --embed false
```

### Schema Validation Workflow
```bash
# Create with schema validation
jacs document create -f document.json -s schema.json

# Verify against specific schema
jacs document verify -f document.json -s schema.json
```

## Global Options

Most commands support these common options:

- `-h, --help` - Show help information
- `-v, --verbose` - Enable verbose output for debugging
- `-a <agent-file>` - Specify custom agent file (overrides config default)

## Exit Codes

- `0` - Success
- `1` - General error (invalid arguments, file not found, etc.)
- `2` - Verification failure (hash mismatch, invalid signature, etc.)
- `3` - Schema validation failure

## Environment Variables

- `JACS_CONFIG_PATH` - Override default configuration file location
- `JACS_DATA_DIR` - Override default data directory location
- `JACS_AGENT_FILE` - Default agent file to use (if not specified with `-a`)

## File Formats

### Input Files
- **JSON documents** - Must be valid JSON format
- **Schema files** - JSON Schema format (draft-07 compatible)
- **Agent files** - JACS agent format with cryptographic keys
- **Attachments** - Any file type (automatically detected MIME type)

### Output Files
- **JACS documents** - JSON format with JACS metadata, signatures, and checksums
- **Extracted files** - Original format of embedded attachments
