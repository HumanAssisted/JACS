# Quick Start Guide

Get signing and verifying in under a minute. No manual setup needed.

## Zero-Config Quick Start

`quickstart()` creates a persistent agent with keys on disk. If `./jacs.config.json` already exists, it loads it; otherwise it creates a new agent. Agent, keys, and config are saved to `./jacs_data`, `./jacs_keys`, and `./jacs.config.json`. If `JACS_PRIVATE_KEY_PASSWORD` is not set, a secure password is auto-generated and saved to `./jacs_keys/.jacs_password`. One call and you're signing.

<div class="tabs">
<div class="tab">
<input type="radio" id="tab-python" name="tab-group" checked>
<label for="tab-python">Python</label>
<div class="content">

```bash
pip install jacs
```

```python
import jacs.simple as jacs

jacs.quickstart()
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

</div>
</div>

<div class="tab">
<input type="radio" id="tab-nodejs" name="tab-group">
<label for="tab-nodejs">Node.js</label>
<div class="content">

```bash
npm install @hai.ai/jacs
```

```javascript
const jacs = require('@hai.ai/jacs/simple');

await jacs.quickstart();
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

</div>
</div>

<div class="tab">
<input type="radio" id="tab-rust" name="tab-group">
<label for="tab-rust">Rust CLI</label>
<div class="content">

```bash
cargo install jacs --features cli
```

```bash
# Info mode -- prints agent ID and algorithm
jacs quickstart

# Sign JSON from stdin
echo '{"action":"approve"}' | jacs quickstart --sign

# Sign a file
jacs quickstart --sign --file mydata.json
```

</div>
</div>
</div>

Pass `algorithm="ring-Ed25519"` (or `{ algorithm: 'ring-Ed25519' }` in JS, `--algorithm ring-Ed25519` in CLI) to override the default (`pq2025`).

## Advanced: Explicit Agent Setup

For full control over agent creation, you can set up an agent manually with a config file and `JACS_PRIVATE_KEY_PASSWORD` environment variable. This is optional since `quickstart()` already creates a persistent agent.

<div class="tabs">
<div class="tab">
<input type="radio" id="adv-rust" name="adv-group" checked>
<label for="adv-rust">Rust CLI</label>
<div class="content">

### Install
```bash
cargo install jacs --features cli
```

### Initialize
```bash
# Create configuration and agent in one step
jacs init

# Or step by step:
# 1. Create config
jacs config create
# 2. Create agent with keys
jacs agent create --create-keys true
# 3. Verify
jacs agent verify
```

### Sign a document
```bash
jacs document create -f mydata.json
```

</div>
</div>

<div class="tab">
<input type="radio" id="adv-nodejs" name="adv-group">
<label for="adv-nodejs">Node.js</label>
<div class="content">

### Install
```bash
npm install @hai.ai/jacs
```

### Load and use
```javascript
const jacs = require('@hai.ai/jacs/simple');

// Load from config file
await jacs.load('./jacs.config.json');

const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}`);
```

</div>
</div>

<div class="tab">
<input type="radio" id="adv-python" name="adv-group">
<label for="adv-python">Python</label>
<div class="content">

### Install
```bash
pip install jacs
```

### Load and use
```python
import jacs.simple as jacs

# Load from config file
jacs.load("./jacs.config.json")

signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}")
```

</div>
</div>
</div>

## Programmatic Agent Creation (v0.6.0+)

For scripts, CI/CD, and server environments where you need agents created programmatically with explicit parameters (without interactive prompts), use `create()`. For most cases, `quickstart()` above is simpler and also creates a persistent agent.

<div class="tabs">
<div class="tab">
<input type="radio" id="prog-python" name="prog-group" checked>
<label for="prog-python">Python</label>
<div class="content">

```python
import jacs.simple as jacs

agent = jacs.create(
    name="my-agent",
    password="Str0ng-P@ssw0rd!",  # or set JACS_PRIVATE_KEY_PASSWORD
    algorithm="pq2025",
)
print(f"Agent: {agent.agent_id}")
```

</div>
</div>

<div class="tab">
<input type="radio" id="prog-nodejs" name="prog-group">
<label for="prog-nodejs">Node.js</label>
<div class="content">

```javascript
const jacs = require('@hai.ai/jacs/simple');

const agent = await jacs.create({
  name: 'my-agent',
  password: process.env.JACS_PRIVATE_KEY_PASSWORD,
  algorithm: 'pq2025',
});
console.log(`Agent: ${agent.agentId}`);
```

</div>
</div>

<div class="tab">
<input type="radio" id="prog-go" name="prog-group">
<label for="prog-go">Go</label>
<div class="content">

```go
info, err := jacs.Create("my-agent", &jacs.CreateAgentOptions{
    Password:  os.Getenv("JACS_PRIVATE_KEY_PASSWORD"),
    Algorithm: "pq2025",
})
```

</div>
</div>

<div class="tab">
<input type="radio" id="prog-rust" name="prog-group">
<label for="prog-rust">Rust</label>
<div class="content">

```rust
use jacs::simple::{CreateAgentParams, SimpleAgent};

let params = CreateAgentParams {
    name: "my-agent".into(),
    password: std::env::var("JACS_PRIVATE_KEY_PASSWORD").unwrap(),
    algorithm: "pq2025".into(),
    ..Default::default()
};
let (agent, info) = SimpleAgent::create_with_params(params)?;
```

</div>
</div>
</div>

**Password requirements**: At least 8 characters, with uppercase, lowercase, a digit, and a special character.

**Algorithm note**: `pq-dilithium` is deprecated in v0.6.0. Use `pq2025` (ML-DSA-87, FIPS-204) instead.

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

# Verify a specific document
jacs document verify -f ./jacs_data/[document-id].json

# Sign a document
jacs document sign -f ./jacs_data/[document-id].json
```

</div>
</div>

<div class="tab">
<input type="radio" id="verify-nodejs" name="verify-group">
<label for="verify-nodejs">🟢 Node.js</label>
<div class="content">

```javascript
// Verify agent signature (async)
const isValid = await agent.verifyAgent();
console.log('Agent signature valid:', isValid);

// Verify task signature
const taskValid = await agent.verifyDocument(signedTask);
console.log('Task signature valid:', taskValid);
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
# Edit reviewer.config.json to set jacs_agent_id_and_version to null

# Create reviewer agent (uses JACS_CONFIG_PATH environment variable)
JACS_CONFIG_PATH=./reviewer.config.json jacs agent create --create-keys true

# Create an agreement on a document
jacs agreement create -f ./document.json \
  --agents [agent-1-id],[agent-2-id] \
  --question "Do you agree to collaborate on this content task?"

# Sign the agreement as first agent
jacs agreement sign -f ./document.json

# Sign as second agent (using reviewer config)
JACS_CONFIG_PATH=./reviewer.config.json jacs agreement sign -f ./document.json

# Verify agreement is complete
jacs agreement check -f ./document.json
```

</div>
</div>

<div class="tab">
<input type="radio" id="multi-nodejs" name="multi-group">
<label for="multi-nodejs">🟢 Node.js</label>
<div class="content">

```javascript
// Create second agent with separate config file
const reviewerConfig = { ...config };
reviewerConfig.jacs_agent_id_and_version = null;

fs.writeFileSync('./reviewer.config.json', JSON.stringify(reviewerConfig, null, 2));

const reviewer = new JacsAgent();
await reviewer.load('./reviewer.config.json');

// Create agreement between agents
const signedAgreement = await agent.createAgreement(
  signedTask,
  [agentDoc.jacsId, reviewerDoc.jacsId],
  'Do you agree to collaborate on this content task?'
);

// Both agents sign the agreement
const signed1 = await agent.signAgreement(signedAgreement);
const signed2 = await reviewer.signAgreement(signed1);

// Check agreement status
const status = await agent.checkAgreement(signed2);
console.log('Agreement status:', JSON.parse(status));
```

</div>
</div>

<div class="tab">
<input type="radio" id="multi-python" name="multi-group">
<label for="multi-python">🐍 Python</label>
<div class="content">

```python
# Create second agent with separate config file
reviewer_config = config.copy()
reviewer_config["jacs_agent_id_and_version"] = None

with open('reviewer.config.json', 'w') as f:
    json.dump(reviewer_config, f, indent=2)

reviewer = jacs.JacsAgent()
reviewer.load("./reviewer.config.json")
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

1. **[Framework Adapters](../python/adapters.md)** - Add auto-signing to LangChain, FastAPI, CrewAI, or Anthropic SDK in 1-3 lines
2. **[Multi-Agent Agreements](../rust/agreements.md)** - Cross-trust-boundary verification with quorum and timeout
3. **[Rust Deep Dive](../rust/library.md)** - Learn the full Rust API
4. **[Node.js Integration](../nodejs/mcp.md)** - Add MCP support
5. **[Python MCP](../python/mcp.md)** - Build authenticated MCP servers
6. **[Production Security](../advanced/security.md)** - Harden runtime settings and key management
7. **[Real Examples](../examples/integrations.md)** - See production patterns

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
