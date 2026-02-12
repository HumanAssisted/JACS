# CLI Tutorial

This page walks through common CLI workflows. For a complete command reference, see the [CLI Command Reference](../reference/cli-commands.md). For practical scripting examples, see [CLI Examples](../examples/cli.md).

The JACS CLI provides a command-line interface for managing agents, documents, tasks, and agreements.

## Getting Help

```bash
# General help
jacs --help

# Command-specific help
jacs agent --help
jacs document --help
jacs task --help
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `jacs init` | Initialize JACS (create config and agent with keys) |
| `jacs version` | Print version information |
| `jacs config` | Manage configuration |
| `jacs agent` | Manage agents |
| `jacs document` | Manage documents |
| `jacs task` | Manage tasks |

## Initialization

### Quick Start
```bash
# Initialize everything in one step
jacs init
```

This command:
1. Creates a configuration file (`jacs.config.json`)
2. Generates cryptographic keys
3. Creates an initial agent document

## Configuration Commands

### Create Configuration
```bash
jacs config create
```
Creates a new `jacs.config.json` file in the current directory with default settings.

### Read Configuration
```bash
jacs config read
```
Displays the current configuration, including values from both the config file and environment variables.

## Agent Commands

### Create Agent
```bash
jacs agent create --create-keys true

# With a custom agent definition file
jacs agent create --create-keys true -f my-agent.json

# Without creating new keys (use existing)
jacs agent create --create-keys false -f my-agent.json
```

**Options:**
| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--create-keys` | | Yes | Whether to create new cryptographic keys |
| `-f` | | No | Path to JSON file with agent definition |

### Verify Agent
```bash
# Verify agent from config
jacs agent verify

# Verify specific agent file
jacs agent verify -a ./path/to/agent.json

# With DNS validation options
jacs agent verify --require-dns
jacs agent verify --require-strict-dns
jacs agent verify --no-dns
jacs agent verify --ignore-dns
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
jacs agent dns --domain example.com --agent-id [uuid]

# With different output formats
jacs agent dns --domain example.com --encoding hex
jacs agent dns --domain example.com --provider aws

# With custom TTL
jacs agent dns --domain example.com --ttl 7200
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
jacs agent lookup agent.example.com

# With strict DNSSEC validation
jacs agent lookup agent.example.com --strict

# Skip DNS lookup
jacs agent lookup agent.example.com --no-dns
```

## Task Commands

### Create Task
```bash
jacs task create -n "Task Name" -d "Task description"

# With optional agent file
jacs task create -n "Task Name" -d "Description" -a ./agent.json

# With input file
jacs task create -n "Task Name" -d "Description" -f ./task-details.json
```

**Options:**
| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `-n` | `--name` | Yes | Name of the task |
| `-d` | `--description` | Yes | Description of the task |
| `-a` | `--agent-file` | No | Path to agent file |
| `-f` | `--filename` | No | Path to JSON file with additional task data |

## Document Commands

### Create Document
```bash
# Create from a JSON file
jacs document create -f ./document.json

# Create from a directory of files
jacs document create -d ./documents/

# With custom schema
jacs document create -f ./document.json -s ./custom-schema.json

# With file attachments
jacs document create -f ./document.json --attach ./attachment.pdf

# Embed attachments in document
jacs document create -f ./document.json --attach ./files/ --embed true

# Output to specific file
jacs document create -f ./document.json -o ./output.json

# Print to stdout instead of saving
jacs document create -f ./document.json --no-save
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
jacs document update -f ./original.json -n ./updated.json

# With output file
jacs document update -f ./original.json -n ./updated.json -o ./result.json

# With file attachments
jacs document update -f ./original.json -n ./updated.json --attach ./new-file.pdf
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
jacs document verify -f ./document.json

# Verify all documents in a directory
jacs document verify -d ./documents/

# With custom schema
jacs document verify -f ./document.json -s ./schema.json

# Verbose output
jacs document verify -f ./document.json -v
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
jacs document extract -f ./document.json

# Extract from all documents in directory
jacs document extract -d ./documents/
```

### Agreement Commands
```bash
# Create an agreement requiring signatures from specified agents
jacs document create-agreement -f ./document.json -i agent1-uuid,agent2-uuid

# Check agreement status
jacs document check-agreement -f ./document.json

# Sign an agreement
jacs document sign-agreement -f ./document.json
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
JACS_CONFIG_PATH=./custom-config.json jacs agent verify

# Override settings
JACS_DATA_DIRECTORY=./data jacs document create -f ./doc.json
JACS_KEY_DIRECTORY=./keys jacs agent create --create-keys true
```

## Common Workflows

### Create and Sign a Document
```bash
# 1. Initialize (if not done)
jacs init

# 2. Create document
jacs document create -f ./my-document.json

# 3. Verify the signed document
jacs document verify -f ./jacs_data/[document-id].json
```

### Multi-Agent Agreement
```bash
# 1. Create agreement on a document
jacs document create-agreement -f ./document.json -i agent1-id,agent2-id

# 2. First agent signs
jacs document sign-agreement -f ./document.json

# 3. Second agent signs (using their config)
JACS_CONFIG_PATH=./agent2.config.json jacs document sign-agreement -f ./document.json

# 4. Check agreement is complete
jacs document check-agreement -f ./document.json
```

### Verify Another Agent
```bash
# Look up agent by domain
jacs agent lookup other-agent.example.com

# Verify with strict DNS
jacs agent verify -a ./other-agent.json --require-strict-dns
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
