# Node.js Installation

The JACS Node.js package (`@hai-ai/jacs`) provides JavaScript/TypeScript bindings to the JACS Rust library, making it easy to integrate JACS into web applications, servers, and Node.js projects.

## Requirements

- **Node.js**: Version 16.0 or higher
- **npm** or **yarn**: For package management
- **Operating System**: macOS, Linux, or Windows with WSL

## Installation

### Using npm
```bash
npm install @hai-ai/jacs
```

### Using yarn
```bash
yarn add @hai-ai/jacs
```

### Using pnpm
```bash
pnpm add @hai-ai/jacs
```

## Verify Installation

Create a simple test to verify everything is working:

```javascript
// test.js
import { JacsAgent } from '@hai-ai/jacs';

console.log('JACS Node.js bindings loaded successfully!');

// Test basic functionality
try {
  const agent = new JacsAgent();
  agent.load('./jacs.config.json');
  console.log('Agent loaded successfully!');
} catch (error) {
  console.error('Error loading agent:', error);
}
```

Run the test:
```bash
node test.js
```

## Package Structure

The `@hai-ai/jacs` package includes several modules:

### Core Module (`@hai-ai/jacs`)
```javascript
import { 
  JacsAgent,
  JacsConfig,
  JacsDocument,
  JacsError
} from '@hai-ai/jacs';
```

### MCP Integration (`@hai-ai/jacs/mcp`)
```javascript
import { 
  JacsMcpServer,
  createJacsMiddleware 
} from '@hai-ai/jacs/mcp';
```

### HTTP Server (`@hai-ai/jacs/http`)
```javascript
import { 
  JacsHttpServer,
  createJacsRouter 
} from '@hai-ai/jacs/http';
```

## TypeScript Support

The package includes full TypeScript definitions:

```typescript
import { JacsAgent, createConfig, hashString } from '@hai-ai/jacs';

// Create an agent instance
const agent: JacsAgent = new JacsAgent();

// Load configuration from file
agent.load('./jacs.config.json');

// Use utility functions
const hash: string = hashString('some data');

// Create a configuration string
const configJson: string = createConfig(
  undefined,           // jacs_use_security
  './jacs_data',       // jacs_data_directory
  './jacs_keys',       // jacs_key_directory
  undefined,           // jacs_agent_private_key_filename
  undefined,           // jacs_agent_public_key_filename
  'ring-Ed25519',      // jacs_agent_key_algorithm
  undefined,           // jacs_private_key_password
  undefined,           // jacs_agent_id_and_version
  'fs'                 // jacs_default_storage
);
```

## Configuration

### Basic Configuration
```javascript
const config = {
  // Required fields
  jacs_data_directory: "./jacs_data",      // Where documents are stored
  jacs_key_directory: "./jacs_keys",       // Where keys are stored
  jacs_default_storage: "fs",              // Storage backend
  jacs_agent_key_algorithm: "ring-Ed25519",     // Signing algorithm
  
  // Optional fields
  jacs_agent_id_and_version: null,         // Existing agent to load
  jacs_agent_private_key_filename: "private.pem",
  jacs_agent_public_key_filename: "public.pem"
};
```

### Configuration File

Create a `jacs.config.json` file:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_default_storage": "fs",
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```

Load the configuration:
```javascript
import { JacsAgent } from '@hai-ai/jacs';

const agent = new JacsAgent();
agent.load('./jacs.config.json');
```

### Environment Variables

JACS reads environment variables that override configuration file settings:

```bash
export JACS_DATA_DIRECTORY="./production_data"
export JACS_KEY_DIRECTORY="./production_keys"
export JACS_AGENT_KEY_ALGORITHM="ring-Ed25519"
export JACS_DEFAULT_STORAGE="fs"
```

## Storage Backends

Configure storage in `jacs.config.json`:

### File System (Default)
```json
{
  "jacs_default_storage": "fs",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys"
}
```

### S3 Storage
```json
{
  "jacs_default_storage": "s3"
}
```

S3 credentials are read from standard AWS environment variables.

### Memory Storage (Testing)
```json
{
  "jacs_default_storage": "memory"
}
```

## Cryptographic Algorithms

### ring-Ed25519 (Recommended)
```json
{
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```

**Pros**: Fast, secure, small signatures
**Cons**: Requires elliptic curve support

### RSA-PSS
```json
{
  "jacs_agent_key_algorithm": "RSA-PSS"
}
```

**Pros**: Widely supported, proven security
**Cons**: Larger signatures, slower

### pq-dilithium (Post-Quantum)
```json
{
  "jacs_agent_key_algorithm": "pq-dilithium"
}
```

**Pros**: Quantum-resistant
**Cons**: Experimental, large signatures

### pq2025 (Post-Quantum Hybrid)
```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```

**Pros**: Combines ML-DSA-87 with hybrid approach
**Cons**: Newest algorithm, largest signatures

## Development Setup

### Project Structure
```
my-jacs-project/
├── package.json
├── jacs.config.json
├── src/
│   ├── agent.js
│   ├── tasks.js
│   └── agreements.js
├── jacs_data/
│   ├── agents/
│   ├── tasks/
│   └── documents/
└── jacs_keys/
    ├── private.pem
    └── public.pem
```

### Package.json Setup
```json
{
  "name": "my-jacs-app",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "@hai-ai/jacs": "^0.6.0",
    "express": "^4.18.0"
  },
  "scripts": {
    "start": "node src/app.js",
    "test": "node test/test.js",
    "dev": "nodemon src/app.js"
  }
}
```

### Basic Application
```javascript
// src/app.js
import { JacsAgent } from '@hai-ai/jacs';

// Create and load agent
const agent = new JacsAgent();
agent.load('./jacs.config.json');

// Create a document
const documentJson = JSON.stringify({
  title: "My First Document",
  content: "Hello from Node.js!"
});

const signedDoc = agent.createDocument(documentJson);
console.log('Document created:', signedDoc);

// Verify the document
const isValid = agent.verifyDocument(signedDoc);
console.log('Document valid:', isValid);

console.log('JACS agent ready!');
```

## Common Issues

### Module Not Found
If you get `Module not found` errors:

```bash
# Check Node.js version
node --version  # Should be 16+

# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Permission Errors
If you get permission errors accessing files:

```bash
# Check directory permissions
ls -la jacs_data/ jacs_keys/

# Fix permissions
chmod 755 jacs_data/ jacs_keys/
chmod 600 jacs_keys/*.pem
```

### Binary Compatibility
If you get binary compatibility errors:

```bash
# Rebuild native modules
npm rebuild

# Or reinstall
npm uninstall @hai-ai/jacs
npm install @hai-ai/jacs
```

### TypeScript Issues
If TypeScript can't find definitions:

```json
// tsconfig.json
{
  "compilerOptions": {
    "moduleResolution": "node",
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true
  }
}
```

## Next Steps

Now that you have JACS installed:

1. **[Basic Usage](basic-usage.md)** - Learn core JACS operations
2. **[MCP Integration](mcp.md)** - Add Model Context Protocol support
3. **[HTTP Server](http.md)** - Create JACS HTTP APIs
4. **[Express Middleware](express.md)** - Integrate with Express.js
5. **[API Reference](api.md)** - Complete API documentation

## Examples

Check out the complete examples in the [examples directory](../examples/nodejs.md):

- Basic agent creation and task management
- Express.js middleware integration
- MCP server implementation
 