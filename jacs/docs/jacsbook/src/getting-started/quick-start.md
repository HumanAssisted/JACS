# Quick Start Guide

This guide will get you up and running with JACS in under 10 minutes. We'll create an agent, generate a task, and demonstrate the core workflow across all three implementations.

## Choose Your Implementation

Select the implementation that best fits your needs:

<div class="tabs">
<div class="tab">
<input type="radio" id="tab-rust" name="tab-group" checked>
<label for="tab-rust">🦀 Rust CLI</label>
<div class="content">

### Install Rust CLI
```bash
# Install from crates.io
cargo install jacs

# Or build from source
git clone https://github.com/HumanAssisted/JACS
cd JACS/jacs
cargo install --path . --features="cli"
```

### Initialize JACS
```bash
# Create configuration and agent in one step
jacs init

# This creates:
# - ~/.jacs/config.json
# - Agent keys and documents
# - Basic directory structure
```

### Create Your First Agent
```bash
# Create a specialized agent
jacs agent create --type "Content Creator" --name "ContentBot"

# View your agent
jacs agent show
```

### Create and Sign a Task
```bash
# Create a task document
jacs task create \
  --title "Write Product Description" \
  --description "Create compelling copy for new product launch" \
  --success "Engaging 200-word description completed"

# The task is automatically signed by your agent
```

</div>
</div>

<div class="tab">
<input type="radio" id="tab-nodejs" name="tab-group">
<label for="tab-nodejs">🟢 Node.js</label>
<div class="content">

### Install Node.js Package
```bash
npm install jacsnpm
```

### Basic Setup
```javascript
import { JacsAgent, JacsConfig } from 'jacsnpm';
import fs from 'fs';

// Create configuration
const config = {
  jacs_agent_id_and_version: null,
  jacs_data_directory: "./jacs_data",
  jacs_key_directory: "./jacs_keys",
  jacs_default_storage: "fs",
  jacs_agent_key_algorithm: "Ed25519"
};

// Save config
fs.writeFileSync('./jacs.config.json', JSON.stringify(config, null, 2));

// Create agent
const agent = new JacsAgent('./jacs.config.json');
```

### Create Agent Document
```javascript
// Create agent with services
const agentData = {
  name: "Content Creator Bot",
  description: "AI agent specialized in content creation",
  services: [
    {
      type: "content_generation",
      name: "Product Description Writer",
      description: "Creates compelling product descriptions",
      success: "Engaging copy that converts visitors",
      failure: "Generic or low-quality content"
    }
  ]
};

// Generate keys and create agent
await agent.generateKeys();
const agentDoc = await agent.createAgent(agentData);
console.log('Agent created:', agentDoc.jacsId);
```

### Create a Task
```javascript
// Create task document
const task = {
  title: "Write Product Description",
  description: "Create compelling copy for new product launch",
  actions: [
    {
      id: "research",
      name: "Product Research", 
      description: "Analyze product features and benefits",
      success: "Complete understanding of product value",
      failure: "Insufficient product knowledge"
    },
    {
      id: "write",
      name: "Write Copy",
      description: "Create engaging product description",
      success: "200-word compelling description",
      failure: "Generic or unconvincing copy"
    }
  ]
};

// Sign and create task
const signedTask = await agent.createTask(task);
console.log('Task created:', signedTask.jacsId);
```

</div>
</div>

<div class="tab">
<input type="radio" id="tab-python" name="tab-group">
<label for="tab-python">🐍 Python</label>
<div class="content">

### Install Python Package
```bash
pip install jacs
```

### Basic Setup
```python
import jacs
import json
import os

# Create configuration
config = {
    "jacs_agent_id_and_version": None,
    "jacs_data_directory": "./jacs_data",
    "jacs_key_directory": "./jacs_keys", 
    "jacs_default_storage": "fs",
    "jacs_agent_key_algorithm": "Ed25519"
}

# Ensure directories exist
os.makedirs("./jacs_data", exist_ok=True)
os.makedirs("./jacs_keys", exist_ok=True)

# Save config
with open('jacs.config.json', 'w') as f:
    json.dump(config, f, indent=2)

# Create agent
agent = jacs.Agent("./jacs.config.json")
```

### Create Agent Document
```python
# Define agent capabilities
agent_data = {
    "name": "Content Creator Bot",
    "description": "AI agent specialized in content creation",
    "services": [
        {
            "type": "content_generation",
            "name": "Product Description Writer", 
            "description": "Creates compelling product descriptions",
            "success": "Engaging copy that converts visitors",
            "failure": "Generic or low-quality content"
        }
    ]
}

# Generate keys and create agent
agent.generate_keys()
agent_doc = agent.create_agent(agent_data)
print(f'Agent created: {agent_doc["jacsId"]}')
```

### Create a Task
```python
# Define task
task = {
    "title": "Write Product Description",
    "description": "Create compelling copy for new product launch",
    "actions": [
        {
            "id": "research",
            "name": "Product Research",
            "description": "Analyze product features and benefits", 
            "success": "Complete understanding of product value",
            "failure": "Insufficient product knowledge"
        },
        {
            "id": "write", 
            "name": "Write Copy",
            "description": "Create engaging product description",
            "success": "200-word compelling description",
            "failure": "Generic or unconvincing copy"
        }
    ]
}

# Sign and create task
signed_task = agent.create_task(task)
print(f'Task created: {signed_task["jacsId"]}')
```

</div>
</div>
</div>

## Understanding What Happened

When you completed the quick start, several important things occurred:

### 1. **Agent Creation**
- A unique identity (UUID) was generated for your agent
- Cryptographic key pair was created for signing
- Agent document was created and self-signed
- Public key was stored for verification

### 2. **Configuration Setup**
- Storage directories were configured
- Cryptographic algorithm was selected
- Agent identity was linked to configuration

### 3. **Task Creation**
- Task document was structured according to JACS schema
- Document was signed with your agent's private key
- SHA-256 hash was calculated for integrity
- Signature metadata was embedded in the document

## Verify Everything Works

Let's verify that the documents are properly signed and can be validated:

<div class="tabs">
<div class="tab">
<input type="radio" id="verify-rust" name="verify-group" checked>
<label for="verify-rust">🦀 Rust</label>
<div class="content">

```bash
# Verify agent signature
jacs agent verify

# List all documents
jacs document list

# Verify specific task
jacs document verify --file ./jacs_data/tasks/[task-id].json

# Show task details
jacs task show --id [task-id]
```

</div>
</div>

<div class="tab">
<input type="radio" id="verify-nodejs" name="verify-group">
<label for="verify-nodejs">🟢 Node.js</label>
<div class="content">

```javascript
// Verify agent signature
const isValid = await agent.verifyAgent();
console.log('Agent signature valid:', isValid);

// List all documents
const documents = await agent.listDocuments();
console.log('Documents:', documents.length);

// Verify task signature
const taskValid = await agent.verifyDocument(signedTask);
console.log('Task signature valid:', taskValid);

// Get document details
const taskDetails = await agent.getDocument(signedTask.jacsId);
console.log('Task details:', taskDetails);
```

</div>
</div>

<div class="tab">
<input type="radio" id="verify-python" name="verify-group">
<label for="verify-python">🐍 Python</label>
<div class="content">

```python
# Verify agent signature
is_valid = agent.verify_agent()
print(f'Agent signature valid: {is_valid}')

# List all documents
documents = agent.list_documents()
print(f'Documents: {len(documents)}')

# Verify task signature  
task_valid = agent.verify_document(signed_task)
print(f'Task signature valid: {task_valid}')

# Get document details
task_details = agent.get_document(signed_task["jacsId"])
print(f'Task details: {task_details}')
```

</div>
</div>
</div>

## Next Steps: Multi-Agent Workflow

Now let's create a second agent and demonstrate inter-agent communication:

<div class="tabs">
<div class="tab">
<input type="radio" id="multi-rust" name="multi-group" checked>
<label for="multi-rust">🦀 Rust</label>
<div class="content">

```bash
# Create a second agent configuration
cp jacs.config.json reviewer.config.json

# Create reviewer agent
jacs agent create --config reviewer.config.json \
  --type "Content Reviewer" --name "ReviewBot"

# Create an agreement for the task
jacs agreement create \
  --task-id [task-id] \
  --agents [agent-1-id] [agent-2-id] \
  --question "Do you agree to collaborate on this content task?"

# Sign the agreement as first agent
jacs agreement sign --agreement-id [agreement-id]

# Sign as second agent (switch config)
jacs agreement sign --config reviewer.config.json \
  --agreement-id [agreement-id]

# Verify agreement is complete
jacs agreement verify --agreement-id [agreement-id]
```

</div>
</div>

<div class="tab">
<input type="radio" id="multi-nodejs" name="multi-group">
<label for="multi-nodejs">🟢 Node.js</label>
<div class="content">

```javascript
// Create second agent
const reviewerConfig = { ...config };
reviewerConfig.jacs_agent_id_and_version = null;

const reviewer = new JacsAgent(reviewerConfig);
await reviewer.generateKeys();

const reviewerDoc = await reviewer.createAgent({
  name: "Content Reviewer Bot",
  description: "AI agent specialized in content review"
});

// Create agreement between agents
const agreement = {
  title: "Content Collaboration Agreement",
  question: "Do you agree to collaborate on this content task?",
  context: `Task: ${signedTask.jacsId}`,
  agents: [agentDoc.jacsId, reviewerDoc.jacsId]
};

const signedAgreement = await agent.createAgreement(agreement);

// Both agents sign the agreement
await agent.signAgreement(signedAgreement.jacsId);
await reviewer.signAgreement(signedAgreement.jacsId);

// Verify all signatures
const agreementValid = await agent.verifyAgreement(signedAgreement.jacsId);
console.log('Agreement complete:', agreementValid);
```

</div>
</div>

<div class="tab">
<input type="radio" id="multi-python" name="multi-group">
<label for="multi-python">🐍 Python</label>
<div class="content">

```python
# Create second agent
reviewer_config = config.copy()
reviewer_config["jacs_agent_id_and_version"] = None

reviewer = jacs.Agent(reviewer_config)
reviewer.generate_keys()

reviewer_doc = reviewer.create_agent({
    "name": "Content Reviewer Bot", 
    "description": "AI agent specialized in content review"
})

# Create agreement between agents
agreement = {
    "title": "Content Collaboration Agreement",
    "question": "Do you agree to collaborate on this content task?",
    "context": f"Task: {signed_task['jacsId']}",
    "agents": [agent_doc["jacsId"], reviewer_doc["jacsId"]]
}

signed_agreement = agent.create_agreement(agreement)

# Both agents sign the agreement
agent.sign_agreement(signed_agreement["jacsId"])
reviewer.sign_agreement(signed_agreement["jacsId"])

# Verify all signatures
agreement_valid = agent.verify_agreement(signed_agreement["jacsId"])
print(f'Agreement complete: {agreement_valid}')
```

</div>
</div>
</div>

## What You've Accomplished

Congratulations! You've successfully:

✅ **Created JACS agents** with cryptographic identities
✅ **Generated and signed documents** with verifiable integrity  
✅ **Established multi-agent agreements** with cryptographic consent
✅ **Verified signatures** and document authenticity
✅ **Created an audit trail** of all interactions

## Key Takeaways

- **Everything is verifiable**: All documents have cryptographic signatures
- **Agents are autonomous**: Each has its own identity and keys
- **Agreements enable trust**: Multi-party consent before proceeding
- **Audit trails are automatic**: Complete history of all interactions
- **JSON is universal**: Documents work everywhere

## Where to Go Next

Now that you have the basics working:

1. **[Rust Deep Dive](../rust/library.md)** - Learn the full Rust API
2. **[Node.js Integration](../nodejs/mcp.md)** - Add MCP support
3. **[Python FastMCP](../python/fastmcp.md)** - Build MCP servers
4. **[Production Setup](../advanced/observability.md)** - Add monitoring and logging
5. **[Real Examples](../examples/integrations.md)** - See production patterns

## Troubleshooting

**Agent creation fails**: Check that the data and key directories exist and are writable
**Signature verification fails**: Ensure public keys are properly stored and accessible
**Agreement signing fails**: Verify all agent IDs are correct and agents exist
**Documents not found**: Check the data directory configuration

Need help? Check the [GitHub issues](https://github.com/HumanAssisted/JACS/issues) or review the detailed implementation guides.

<style>
.tabs {
  display: flex;
  flex-wrap: wrap;
  max-width: 100%;
  font-family: sans-serif;
}

.tab {
  order: 1;
  flex-grow: 1;
}

.tab input[type="radio"] {
  display: none;
}

.tab label {
  display: block;
  padding: 1em;
  background: #f0f0f0;
  color: #666;
  border: 1px solid #ddd;
  cursor: pointer;
  margin-bottom: -1px;
}

.tab label:hover {
  background: #e0e0e0;
}

.tab input:checked + label {
  background: #007acc;
  color: white;
}

.tab .content {
  order: 99;
  flex-grow: 1;
  width: 100%;
  display: none;
  padding: 1em;
  background: white;
  border: 1px solid #ddd;
  border-top: none;
}

.tab input:checked ~ .content {
  display: block;
}
</style> 