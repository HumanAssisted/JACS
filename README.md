# JACS

Welcome to JACS (JSON Agent Communication Standard).

**[Documentation](https://humanassisted.github.io/JACS/)** | **[API Reference](https://humanassisted.github.io/JACS/nodejs/api.html)** | **[Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)**

JACS is used by agents to validate the source and identity of data. The data may be ephemeral, changing, or idempotent such as files, identities, logs, http requests.

JACS is for data provenance. JACS is a set of JSON Schema definitions that provide headers for cryptographic signatures. The library is used to wrap data in an JSON envelope that can be used in a variety of untrusted where contexts every new or modified payload (web request, email, document, etc) needs to be verified. 


## In relation to MCP

MCP standardizes how a client exposes tools/resources/prompts over JSON-RPC, but it’s intentionally light on identity and artifact-level provenance. JACS fills that gap by making every artifact (tasks, messages, agreements, files) a signed, self-verifiable record with stable schemas and audit trails—orthogonal to whether you call it via MCP or not. 

##  In relation to A2A

JACS provides cryptographic document provenance for Google's A2A (Agent-to-Agent) protocol. While A2A handles agent discovery and communication, JACS adds document-level signatures with post-quantum support.

### Quick Start with A2A

```python
# Python
from jacs.a2a import JACSA2AIntegration
a2a = JACSA2AIntegration("jacs.config.json")
agent_card = a2a.export_agent_card(agent_data)
wrapped = a2a.wrap_artifact_with_provenance(artifact, "task")
```

```javascript
// Node.js
const { JACSA2AIntegration } = require('jacsnpm/a2a');
const a2a = new JACSA2AIntegration();
const agentCard = a2a.exportAgentCard(agentData);
const wrapped = a2a.wrapArtifactWithProvenance(artifact, 'task');
```

```rust
// Rust
use jacs::a2a::{agent_card::*, provenance::*};
let agent_card = export_agent_card(&agent)?;
let wrapped = wrap_artifact_with_provenance(&mut agent, artifact, "task", None)?;
```

JACS extends A2A with:
- **Document signatures** that persist with data (not just transport security)
- **Post-quantum cryptography** for future-proof security
- **Chain of custody** tracking for multi-agent workflows
- **Self-verifying artifacts** that work offline

See [jacs/src/a2a/README.md](./jacs/src/a2a/README.md) for full integration guide


Example uses:

  1. A document is sitting on a server. Where did it come from? Who has access to it?
  2. An MCP server gets a request from an unknown agent, the oauth flow doesn't guarantee the identity of the client or the server after the initial handshake. 
  3. a document is modified by multiple human and AI collaborators. Which one is latest, correct version?

This repo includes JACS available in several languages:
 
  1. the main [rust jacs lib](./jacs/) and cli to bootstrap an agent or documents 
  2. [Python library](./jacspy/) for use as middleware in any http and with MCP
  3. [Node JS library](./jacsnpm) cli, middleware, and use with MCP
  4. [Go library](./jacsgo) for use in Go applications with CGO bindings

## Python quickstart

Install with `pip install jacs` with example using [fastmcp](https://github.com/jlowin/fastmcp) 

```python
# server
import jacs
from jacs.mcp import JACSMCPServer, JACSMCPClient
from mcp.server.fastmcp import FastMCP 

# client
# client = JACSMCPClient(server_url)

# setup
jacs_config_path = "jacs.server.config.json"
# set the secret
# os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"   
jacs.load(str(jacs_config_path))

mcp = JACSMCPServer(FastMCP("Authenticated Echo Server"))

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b

if __name__ == "__main__":
    mcp.run()

```

## Node JS

Install with `npm install jacsnpm`

```js
const jacs = require('jacsnpm');

// Load configuration (set JACS_PRIVATE_KEY_PASSWORD env var first)
jacs.load('jacs.config.json');

// Sign a document
const doc = { content: 'Hello from Node.js!' };
const signed = jacs.signRequest(doc);
console.log('Signed:', signed);

// Verify a document
const result = jacs.verifyResponse(signed);
console.log('Valid:', result);

// Hash content
const hash = jacs.hashString('data to hash');
console.log('Hash:', hash);
```

## Go

```go
package main

import (
    "fmt"
    "log"
    jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
    // Load JACS configuration
    err := jacs.Load("jacs.config.json")
    if err != nil {
        log.Fatal(err)
    }
    
    // Create and sign a document
    doc := map[string]interface{}{
        "content": "Hello from Go!",
    }
    
    signed, err := jacs.SignRequest(doc)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println(signed)
}
```

## Rust

The core library is used in all other implementations. 

`cargo install jacs` is useful for it's cli, but to develop `cargo add jacs` is all that's needed. 


## Post-Quantum Cryptography (2025)

JACS now supports the NIST-standardized post-quantum algorithms for quantum-resistant security:

### Algorithms

- **ML-DSA (FIPS-204)**: Module-Lattice Digital Signature Algorithm using ML-DSA-87 (NIST Security Level 5)
  - Post-quantum signatures with ~2592 byte public keys and ~4595 byte signatures
  - Provides strong security against both classical and quantum computers
  
- **ML-KEM (FIPS-203)**: Module-Lattice Key Encapsulation Mechanism using ML-KEM-768 (NIST Security Level 3)
  - Post-quantum key encapsulation for secure communication
  - Used with HKDF + AES-256-GCM for authenticated encryption

### Usage

Set `jacs_agent_key_algorithm: "pq2025"` in your `jacs.config.json`:

```json
{
  "jacs_agent_key_algorithm": "pq2025",
  "jacs_agent_private_key_filename": "agent.private.pem.enc",
  "jacs_agent_public_key_filename": "agent.public.pem",
  "jacs_private_key_password": "your-secure-password"
}
```

Or use the CLI:

```bash
jacs config create
# Select "pq2025" when prompted for algorithm

jacs agent create --create-keys
# Keys will be generated using ML-DSA-87
```

### Backward Compatibility

The original `pq-dilithium` (Dilithium5) algorithm remains fully supported for backward compatibility. All existing signatures and keys continue to work. You can:

- Verify old `pq-dilithium` signatures with new code
- Gradually migrate agents to `pq2025` 
- Run mixed environments with both algorithms

### Migration Path

1. **New agents**: Use `pq2025` by default (it's the new default in CLI prompts)
2. **Existing agents**: Continue using current algorithm, or regenerate keys with `pq2025`
3. **Verification**: Both algorithms can verify each other's documents (if signed with respective keys)

### Security Considerations

- ML-DSA-87 provides the highest post-quantum security level standardized by NIST
- Keys are encrypted at rest using AES-256-GCM with password-derived keys
- ML-KEM-768 provides quantum-resistant key establishment for future encrypted communications
- Both algorithms are designed to be secure against Grover's and Shor's quantum algorithms


## License

The [license][./LICENSE] is a *modified* Apache 2.0, with the [Common Clause](https://commonsclause.com/) preamble. 
In simple terms, unless you are directly competing with HAI.AI, you can create commercial products with JACS.
This licensing doesn't work, please reach out to hello@hai.io. 
 
------
2024, 2025 https://hai.ai
