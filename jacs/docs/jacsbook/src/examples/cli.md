# CLI Examples

This chapter provides practical examples of using the JACS CLI for common workflows.

## Quick Reference

```bash
jacs init                  # Initialize JACS (config + agent + keys)
jacs agent create          # Create a new agent
jacs document create       # Create a signed document
jacs document verify       # Verify a document signature
jacs document sign-agreement  # Sign an agreement
```

## Getting Started

### First-Time Setup

Initialize JACS in a new project:

```bash
# Create a new directory
mkdir my-jacs-project
cd my-jacs-project

# Initialize JACS
jacs init

# This creates:
# - jacs.config.json (configuration)
# - jacs_keys/ (private and public keys)
# - jacs_data/ (document storage)
# - An initial agent document
```

### Verify Your Setup

```bash
# Check the configuration
jacs config read

# Verify your agent
jacs agent verify

# Expected output:
# Agent verification successful
# Agent ID: 550e8400-e29b-41d4-a716-446655440000
# Agent Version: f47ac10b-58cc-4372-a567-0e02b2c3d479
```

## Document Operations

### Creating Documents

**Create from a JSON file:**

```bash
# Create input file
cat > invoice.json << 'EOF'
{
  "type": "invoice",
  "invoiceNumber": "INV-001",
  "customer": "Acme Corp",
  "amount": 1500.00,
  "items": [
    {"description": "Consulting", "quantity": 10, "price": 150}
  ]
}
EOF

# Create signed document
jacs document create -f invoice.json

# Output shows the saved document path
# Document saved to: jacs_data/documents/[uuid]/[version].json
```

**Create with custom output:**

```bash
# Specify output filename
jacs document create -f invoice.json -o signed-invoice.json

# Print to stdout (don't save)
jacs document create -f invoice.json --no-save
```

**Create with file attachments:**

```bash
# Create document with PDF attachment
jacs document create -f contract.json --attach ./contract.pdf

# Embed attachment content in document
jacs document create -f contract.json --attach ./contract.pdf --embed true

# Attach entire directory
jacs document create -f report.json --attach ./attachments/
```

**Create with custom schema:**

```bash
# Use a custom schema for validation
jacs document create -f order.json -s ./schemas/order.schema.json
```

### Verifying Documents

**Basic verification:**

```bash
# Verify a document
jacs document verify -f ./signed-invoice.json

# Expected output:
# Document verified successfully
# Document ID: 550e8400-e29b-41d4-a716-446655440000
# Signer: Agent Name (agent-uuid)
```

**Verbose verification:**

```bash
# Get detailed verification info
jacs document verify -f ./signed-invoice.json -v

# Output includes:
# - Document ID and version
# - Signature algorithm used
# - Signing agent details
# - Timestamp
# - Schema validation results
```

**Batch verification:**

```bash
# Verify all documents in a directory
jacs document verify -d ./documents/

# With custom schema
jacs document verify -d ./invoices/ -s ./schemas/invoice.schema.json
```

### Updating Documents

Create a new version of an existing document:

```bash
# Original document
cat > original.json << 'EOF'
{
  "title": "Project Plan",
  "status": "draft",
  "content": "Initial version"
}
EOF

jacs document create -f original.json -o project-v1.json

# Updated content
cat > updated.json << 'EOF'
{
  "title": "Project Plan",
  "status": "approved",
  "content": "Final version with updates"
}
EOF

# Create new version (maintains version history)
jacs document update -f project-v1.json -n updated.json -o project-v2.json

# Verify the updated document
jacs document verify -f project-v2.json -v
```

### Extracting Embedded Content

```bash
# Extract embedded files from a document
jacs document extract -f ./document-with-attachments.json

# Extracts to: jacs_data/extracted/[document-id]/

# Extract from multiple documents
jacs document extract -d ./documents/
```

## Agreement Workflows

### Creating an Agreement

An agreement requires multiple agents to sign a document:

```bash
# First, create the document to be agreed upon
cat > service-agreement.json << 'EOF'
{
  "type": "service_agreement",
  "title": "Professional Services Agreement",
  "parties": ["Company A", "Company B"],
  "terms": "...",
  "effectiveDate": "2024-02-01"
}
EOF

jacs document create -f service-agreement.json -o agreement.json

# Create agreement requiring signatures from two agents
# (Use actual agent UUIDs)
jacs document create-agreement \
  -f agreement.json \
  -i "agent1-uuid-here,agent2-uuid-here" \
  -o agreement-pending.json

# Output:
# Agreement created
# Required signatures: 2
# Current signatures: 0
```

### Signing an Agreement

```bash
# First agent signs
jacs document sign-agreement -f agreement-pending.json -o agreement-signed-1.json

# Check status
jacs document check-agreement -f agreement-signed-1.json
# Output:
# Agreement status: pending
# Signatures: 1/2
# Missing: agent2-uuid

# Second agent signs (using their configuration)
JACS_CONFIG_PATH=./agent2.config.json \
  jacs document sign-agreement -f agreement-signed-1.json -o agreement-complete.json

# Verify completion
jacs document check-agreement -f agreement-complete.json
# Output:
# Agreement status: complete
# Signatures: 2/2
```

### Complete Agreement Workflow

```bash
#!/bin/bash
# agreement-workflow.sh

# Step 1: Create the contract document
cat > contract.json << 'EOF'
{
  "type": "contract",
  "parties": {
    "seller": "Widget Corp",
    "buyer": "Acme Inc"
  },
  "terms": "Sale of 1000 widgets at $10 each",
  "totalValue": 10000
}
EOF

echo "Creating contract document..."
jacs document create -f contract.json -o contract-signed.json

# Step 2: Get agent IDs
SELLER_AGENT=$(jacs config read | grep agent_id | cut -d: -f2 | tr -d ' ')
BUYER_AGENT="buyer-agent-uuid-here"  # Replace with actual ID

# Step 3: Create agreement
echo "Creating agreement..."
jacs document create-agreement \
  -f contract-signed.json \
  -i "$SELLER_AGENT,$BUYER_AGENT" \
  -o contract-agreement.json

# Step 4: Seller signs
echo "Seller signing..."
jacs document sign-agreement \
  -f contract-agreement.json \
  -o contract-seller-signed.json

# Step 5: Check intermediate status
echo "Checking status..."
jacs document check-agreement -f contract-seller-signed.json

# Step 6: Buyer signs
echo "Buyer signing..."
JACS_CONFIG_PATH=./buyer.config.json \
  jacs document sign-agreement \
  -f contract-seller-signed.json \
  -o contract-complete.json

# Step 7: Verify complete agreement
echo "Final verification..."
jacs document verify -f contract-complete.json -v
jacs document check-agreement -f contract-complete.json

echo "Agreement workflow complete!"
```

## Agent Operations

### Creating a Custom Agent

```bash
# Create agent definition file
cat > my-agent.json << 'EOF'
{
  "jacsAgentType": "ai",
  "name": "My Custom Agent",
  "description": "An AI agent for document processing",
  "contact": {
    "email": "agent@example.com"
  },
  "services": [
    {
      "name": "document-processing",
      "description": "Process and sign documents"
    }
  ]
}
EOF

# Create agent with new keys
jacs agent create --create-keys true -f my-agent.json

# Create agent using existing keys
jacs agent create --create-keys false -f my-agent.json
```

### DNS-Based Identity

**Generate DNS record commands:**

```bash
# Generate TXT record for your domain
jacs agent dns --domain myagent.example.com

# Output (example):
# Add the following DNS TXT record:
# _v1.agent.jacs.myagent.example.com TXT "pk=<base64-public-key-hash>"

# Different providers
jacs agent dns --domain myagent.example.com --provider aws
jacs agent dns --domain myagent.example.com --provider cloudflare
jacs agent dns --domain myagent.example.com --provider azure

# Custom TTL
jacs agent dns --domain myagent.example.com --ttl 7200
```

**Verify DNS-published agent:**

```bash
# Look up agent by domain
jacs agent lookup partner.example.com

# Require strict DNSSEC validation
jacs agent lookup partner.example.com --strict

# Verify local agent file against DNS
jacs agent verify -a ./partner-agent.json --require-strict-dns
```

### Agent Verification

```bash
# Basic verification
jacs agent verify

# Verify another agent's file
jacs agent verify -a ./other-agent.json

# With DNS requirements
jacs agent verify --require-dns          # Require DNS (not strict)
jacs agent verify --require-strict-dns   # Require DNSSEC
jacs agent verify --no-dns              # Skip DNS entirely
jacs agent verify --ignore-dns          # Ignore DNS validation failures
```

## Task Management

### Creating Tasks

```bash
# Simple task
jacs task create \
  -n "Review Contract" \
  -d "Review the service contract and provide feedback"

# Task with additional data from file
cat > task-details.json << 'EOF'
{
  "priority": "high",
  "dueDate": "2024-02-15",
  "assignee": "legal-team"
}
EOF

jacs task create \
  -n "Contract Review" \
  -d "Detailed review required" \
  -f task-details.json
```

## Scripting Examples

### Batch Document Processing

```bash
#!/bin/bash
# batch-sign.sh - Sign all JSON files in a directory

INPUT_DIR=$1
OUTPUT_DIR=${2:-"./signed"}

mkdir -p "$OUTPUT_DIR"

for file in "$INPUT_DIR"/*.json; do
  filename=$(basename "$file")
  echo "Signing: $filename"

  jacs document create -f "$file" -o "$OUTPUT_DIR/$filename"

  if [ $? -eq 0 ]; then
    echo "  ✓ Signed successfully"
  else
    echo "  ✗ Signing failed"
  fi
done

echo "Batch signing complete. Output in $OUTPUT_DIR"
```

### Verification Report

```bash
#!/bin/bash
# verify-report.sh - Generate verification report

DOC_DIR=$1
REPORT="verification-report.txt"

echo "JACS Document Verification Report" > $REPORT
echo "Generated: $(date)" >> $REPORT
echo "=================================" >> $REPORT
echo "" >> $REPORT

passed=0
failed=0

for file in "$DOC_DIR"/*.json; do
  filename=$(basename "$file")

  if jacs document verify -f "$file" > /dev/null 2>&1; then
    echo "✓ PASS: $filename" >> $REPORT
    ((passed++))
  else
    echo "✗ FAIL: $filename" >> $REPORT
    ((failed++))
  fi
done

echo "" >> $REPORT
echo "Summary: $passed passed, $failed failed" >> $REPORT

cat $REPORT
```

### Watch for New Documents

```bash
#!/bin/bash
# watch-and-verify.sh - Monitor directory and verify new documents

WATCH_DIR=${1:-"./incoming"}

echo "Watching $WATCH_DIR for new documents..."

inotifywait -m "$WATCH_DIR" -e create -e moved_to |
  while read dir action file; do
    if [[ "$file" == *.json ]]; then
      echo "New document: $file"

      if jacs document verify -f "$WATCH_DIR/$file"; then
        mv "$WATCH_DIR/$file" "./verified/"
        echo "  Moved to verified/"
      else
        mv "$WATCH_DIR/$file" "./rejected/"
        echo "  Moved to rejected/"
      fi
    fi
  done
```

## Environment Configuration

### Using Environment Variables

```bash
# Use a specific config file
export JACS_CONFIG_PATH=./production.config.json
jacs document create -f invoice.json

# Override specific settings
export JACS_DATA_DIRECTORY=./custom-data
export JACS_KEY_DIRECTORY=./secure-keys
jacs agent create --create-keys true

# One-time override
JACS_CONFIG_PATH=./test.config.json jacs document verify -f test-doc.json
```

### Multiple Configurations

```bash
# Development
alias jacs-dev='JACS_CONFIG_PATH=./dev.config.json jacs'
jacs-dev document create -f test.json

# Production
alias jacs-prod='JACS_CONFIG_PATH=./prod.config.json jacs'
jacs-prod document verify -f important.json

# Different agents
alias jacs-alice='JACS_CONFIG_PATH=./alice.config.json jacs'
alias jacs-bob='JACS_CONFIG_PATH=./bob.config.json jacs'
```

## Error Handling

### Understanding Exit Codes

```bash
jacs document verify -f document.json
exit_code=$?

case $exit_code in
  0) echo "Success" ;;
  1) echo "General error" ;;
  2) echo "Invalid arguments" ;;
  3) echo "File not found" ;;
  4) echo "Verification failed" ;;
  5) echo "Signature invalid" ;;
  *) echo "Unknown error: $exit_code" ;;
esac
```

### Handling Failures

```bash
#!/bin/bash
# robust-signing.sh

sign_document() {
  local input=$1
  local output=$2

  if ! jacs document create -f "$input" -o "$output" 2>/dev/null; then
    echo "Error: Failed to sign $input" >&2
    return 1
  fi

  if ! jacs document verify -f "$output" 2>/dev/null; then
    echo "Error: Verification failed for $output" >&2
    rm -f "$output"
    return 1
  fi

  echo "Successfully signed: $output"
  return 0
}

# Usage
sign_document "invoice.json" "signed-invoice.json" || exit 1
```

## See Also

- [CLI Command Reference](../reference/cli-commands.md) - Complete command reference
- [Configuration Reference](../reference/configuration.md) - Configuration options
- [Rust CLI Usage](../rust/cli.md) - Detailed CLI documentation
