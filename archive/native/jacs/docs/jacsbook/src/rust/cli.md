# CLI Tutorial

This page walks through common CLI workflows. For a complete command reference, see the [CLI Command Reference](../reference/cli-commands.md). For practical scripting examples, see [CLI Examples](../examples/cli.md).

The JACS CLI provides a command-line interface for managing agents, documents, and agreements.

## Getting Help

```bash
# General help
jacs --help

# Command-specific help
jacs-compat agent --help
jacs-compat document --help
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `jacs-compat init` | Initialize JACS (create config and agent with keys) |
| `jacs-compat --version` | Print version information |
| `jacs-compat config` | Manage configuration |
| `jacs-compat agent` | Manage agents |
| `jacs-compat document` | Manage documents |
| `jacs-compat mcp` | Start the built-in MCP server (stdio transport) |

## Initialization

### Quick Start
```bash
# Initialize everything in one step
jacs-compat init
```

This command:
1. Creates a configuration file (`jacs.config.json`)
2. Generates cryptographic keys
3. Creates an initial agent document

## MCP Server

The MCP server is built into the `jacs-compat` binary. No separate install step needed.

```bash
# Start the MCP server (stdio transport)
JACS_CONFIG="$PWD/jacs.config.json" jacs-compat mcp
```

## Configuration Commands

### Create Configuration
```bash
jacs-compat config create
```
Creates a new `jacs.config.json` file in the current directory with default settings.

### Read Configuration
```bash
jacs-compat config read
```
Displays the current configuration, including values from both the config file and environment variables.

## Agent Commands

### Create Agent
```bash
jacs-compat agent create --create-keys true

# With a custom agent definition file
jacs-compat agent create --create-keys true -f my-agent.json

# Without creating new keys (use existing)
jacs-compat agent create --create-keys false -f my-agent.json
```

**Options:**
| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--create-keys` | | Yes | Whether to create new cryptographic keys |
| `-f` | | No | Path to JSON file with agent definition |

### Verify Agent
```bash
# Verify agent from config
jacs-compat agent verify

# Verify specific agent file
jacs-compat agent verify -a ./path/to/agent.json

# With DNS validation options
jacs-compat agent verify --require-dns
jacs-compat agent verify --require-strict-dns
jacs-compat agent verify --no-dns
jacs-compat agent verify --ignore-dns
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `-a` | `--agent-file` | Path to agent file (optional) |
| `--no-dns` | | Disable DNS validation |
| `--require-dns` | | Require DNS validation (not strict) |
| `--require-strict-dns` | | Require DNSSEC validation |
| `--ignore-dns` | | Ignore DNS validation entirely |

### DNS Commands
```bash
# Generate DNS TXT record commands for agent publishing
jacs-compat agent dns --domain example.com --agent-id [uuid]

# With different output formats
jacs-compat agent dns --domain example.com --encoding hex
jacs-compat agent dns --domain example.com --provider aws

# With custom TTL
jacs-compat agent dns --domain example.com --ttl 7200
```

**Options:**
| Option | Default | Description |
|--------|---------|-------------|
| `--domain` | | Domain for DNS record |
| `--agent-id` | | Agent UUID (optional, uses config if not provided) |
| `--ttl` | 3600 | Time-to-live in seconds |
| `--encoding` | base64 | Encoding format (base64, hex) |
| `--provider` | plain | Output format (plain, aws, azure, cloudflare) |

### Lookup Agent
```bash
# Look up another agent's public key from their domain
jacs-compat agent lookup agent.example.com

# With strict DNSSEC validation
jacs-compat agent lookup agent.example.com --strict

# Skip DNS lookup
jacs-compat agent lookup agent.example.com --no-dns
```

## Document Commands

### Create Document
```bash
# Create from a JSON file
jacs-compat document create -f ./document.json

# Create from a directory of files
jacs-compat document create -d ./documents/

# With custom schema
jacs-compat document create -f ./document.json -s ./custom-schema.json

# With file attachments
jacs-compat document create -f ./document.json --attach ./attachment.pdf

# Embed attachments in document
jacs-compat document create -f ./document.json --attach ./files/ --embed true

# Output to specific file
jacs-compat document create -f ./document.json -o ./output.json

# Print to stdout instead of saving
jacs-compat document create -f ./document.json --no-save
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `-f` | `--filename` | Path to input JSON file |
| `-d` | `--directory` | Path to directory of JSON files |
| `-o` | `--output` | Output filename |
| `-s` | `--schema` | Path to custom JSON schema |
| `--attach` | | Path to file/directory for attachments |
| `--embed` | `-e` | Embed documents (true/false) |
| `--no-save` | `-n` | Print to stdout instead of saving |
| `-v` | `--verbose` | Enable verbose output |
| `-a` | `--agent-file` | Path to agent file |

### Update Document
```bash
# Update an existing document with new content
jacs-compat document update -f ./original.json -n ./updated.json

# With output file
jacs-compat document update -f ./original.json -n ./updated.json -o ./result.json

# With file attachments
jacs-compat document update -f ./original.json -n ./updated.json --attach ./new-file.pdf
```

**Options:**
| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `-f` | `--filename` | Yes | Path to original document |
| `-n` | `--new` | Yes | Path to new version |
| `-o` | `--output` | No | Output filename |
| `--attach` | | No | Path to file attachments |
| `--embed` | `-e` | No | Embed documents (true/false) |

### Verify Document
```bash
# Verify a document
jacs-compat document verify -f ./document.json

# Verify all documents in a directory
jacs-compat document verify -d ./documents/

# With custom schema
jacs-compat document verify -f ./document.json -s ./schema.json

# Verbose output
jacs-compat document verify -f ./document.json -v
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `-f` | `--filename` | Path to document file |
| `-d` | `--directory` | Path to directory of documents |
| `-s` | `--schema` | Path to JSON schema for validation |
| `-v` | `--verbose` | Enable verbose output |
| `-a` | `--agent-file` | Path to agent file |

### Extract Embedded Content
```bash
# Extract embedded content from a document
jacs-compat document extract -f ./document.json

# Extract from all documents in directory
jacs-compat document extract -d ./documents/
```

### Agreement Commands
```bash
# Create an agreement requiring signatures from specified agents
jacs-compat document create-agreement -f ./document.json -i agent1-uuid,agent2-uuid

# Check agreement status
jacs-compat document check-agreement -f ./document.json

# Sign an agreement
jacs-compat document sign-agreement -f ./document.json
```

**Create Agreement Options:**
| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `-f` | `--filename` | Yes | Path to document |
| `-i` | `--agentids` | Yes | Comma-separated list of agent UUIDs |
| `-o` | `--output` | No | Output filename |
| `--no-save` | `-n` | No | Print to stdout |

## Environment Variables

The CLI respects the following environment variables:

```bash
# Use a specific configuration file
JACS_CONFIG_PATH=./custom-config.json jacs-compat agent verify

# Override settings
JACS_DATA_DIRECTORY=./data jacs-compat document create -f ./doc.json
JACS_KEY_DIRECTORY=./keys jacs-compat agent create --create-keys true
```

## Common Workflows

### Create and Sign a Document
```bash
# 1. Initialize (if not done)
jacs-compat init

# 2. Create document
jacs-compat document create -f ./my-document.json

# 3. Verify the signed document
jacs-compat document verify -f ./jacs_data/[document-id].json
```

### Multi-Agent Agreement
```bash
# 1. Create agreement on a document
jacs-compat document create-agreement -f ./document.json -i agent1-id,agent2-id

# 2. First agent signs
jacs-compat document sign-agreement -f ./document.json

# 3. Second agent signs (using their config)
JACS_CONFIG_PATH=./agent2.config.json jacs-compat document sign-agreement -f ./document.json

# 4. Check agreement is complete
jacs-compat document check-agreement -f ./document.json
```

### Verify Another Agent
```bash
# Look up agent by domain
jacs-compat agent lookup other-agent.example.com

# Verify with strict DNS
jacs-compat agent verify -a ./other-agent.json --require-strict-dns
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | File not found |
| 4 | Verification failed |
| 5 | Signature invalid |

## Next Steps

- [Creating an Agent](agent.md) - Detailed agent creation guide
- [Working with Documents](documents.md) - Document operations in depth
- [Agreements](agreements.md) - Multi-agent agreements
