# Node.js Installation

The JACS Node.js package (`jacsnpm`) provides JavaScript/TypeScript bindings to the JACS Rust library, making it easy to integrate JACS into web applications, servers, and Node.js projects.

## Requirements

- **Node.js**: Version 16.0 or higher
- **npm** or **yarn**: For package management
- **Operating System**: macOS, Linux, or Windows with WSL

## Installation

### Using npm
```bash
npm install jacsnpm
```

### Using yarn
```bash
yarn add jacsnpm
```

### Using pnpm
```bash
pnpm add jacsnpm
```

## Verify Installation

Create a simple test to verify everything is working:

```javascript
// test.js
import { JacsAgent } from 'jacsnpm';

console.log('JACS Node.js bindings loaded successfully!');

// Test basic functionality
try {
  const config = {
    jacs_data_directory: "./test_data",
    jacs_key_directory: "./test_keys",
    jacs_default_storage: "fs",
    jacs_agent_key_algorithm: "Ed25519"
  };
  
  const agent = new JacsAgent(config);
  console.log('Agent created successfully!');
} catch (error) {
  console.error('Error creating agent:', error);
}
```

Run the test:
```bash
node test.js
```

## Package Structure

The `jacsnpm` package includes several modules:

### Core Module (`jacsnpm`)
```javascript
import { 
  JacsAgent,
  JacsConfig,
  JacsDocument,
  JacsError
} from 'jacsnpm';
```

### MCP Integration (`jacsnpm/mcp`)
```javascript
import { 
  JacsMcpServer,
  createJacsMiddleware 
} from 'jacsnpm/mcp';
```

### HTTP Server (`jacsnpm/http`)
```javascript
import { 
  JacsHttpServer,
  createJacsRouter 
} from 'jacsnpm/http';
```

## TypeScript Support

The package includes full TypeScript definitions:

```typescript
import { 
  JacsAgent, 
  JacsConfig, 
  AgentDocument, 
  TaskDocument,
  AgreementDocument 
} from 'jacsnpm';

interface MyConfig extends JacsConfig {
  custom_field?: string;
}

const config: MyConfig = {
  jacs_data_directory: "./data",
  jacs_key_directory: "./keys",
  jacs_default_storage: "fs",
  jacs_agent_key_algorithm: "Ed25519",
  custom_field: "value"
};

const agent: JacsAgent = new JacsAgent(config);
```

## Configuration

### Basic Configuration
```javascript
const config = {
  // Required fields
  jacs_data_directory: "./jacs_data",      // Where documents are stored
  jacs_key_directory: "./jacs_keys",       // Where keys are stored
  jacs_default_storage: "fs",              // Storage backend
  jacs_agent_key_algorithm: "Ed25519",     // Signing algorithm
  
  // Optional fields
  jacs_agent_id_and_version: null,         // Existing agent to load
  jacs_agent_private_key_filename: "private.pem",
  jacs_agent_public_key_filename: "public.pem"
};
```

### Configuration File
You can also use a JSON configuration file:

```json
{
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys", 
  "jacs_default_storage": "fs",
  "jacs_agent_key_algorithm": "Ed25519"
}
```

Load the configuration:
```javascript
import fs from 'fs';

const config = JSON.parse(fs.readFileSync('./jacs.config.json', 'utf8'));
const agent = new JacsAgent(config);
```

### Environment Variables

You can override configuration with environment variables:

```bash
export JACS_DATA_DIRECTORY="./production_data"
export JACS_KEY_DIRECTORY="./production_keys"
export JACS_AGENT_KEY_ALGORITHM="RSA"
```

```javascript
const config = {
  jacs_data_directory: process.env.JACS_DATA_DIRECTORY || "./jacs_data",
  jacs_key_directory: process.env.JACS_KEY_DIRECTORY || "./jacs_keys",
  jacs_default_storage: "fs",
  jacs_agent_key_algorithm: process.env.JACS_AGENT_KEY_ALGORITHM || "Ed25519"
};
```

## Storage Backends

### File System (Default)
```javascript
const config = {
  jacs_default_storage: "fs",
  jacs_data_directory: "./jacs_data",
  jacs_key_directory: "./jacs_keys"
};
```

### S3 Storage
```javascript
const config = {
  jacs_default_storage: "s3",
  jacs_s3_bucket: "my-jacs-bucket",
  jacs_s3_region: "us-west-2",
  jacs_s3_prefix: "jacs/"
};
```

### Azure Blob Storage
```javascript
const config = {
  jacs_default_storage: "azure",
  jacs_azure_account: "myaccount",
  jacs_azure_container: "jacs",
  jacs_azure_key: process.env.AZURE_STORAGE_KEY
};
```

## Cryptographic Algorithms

### Ed25519 (Recommended)
```javascript
const config = {
  jacs_agent_key_algorithm: "Ed25519"
};
```

**Pros**: Fast, secure, small signatures
**Cons**: Newer standard, less universal support

### RSA-PSS
```javascript
const config = {
  jacs_agent_key_algorithm: "RSA"
};
```

**Pros**: Widely supported, proven security
**Cons**: Larger signatures, slower

### Post-Quantum (Experimental)
```javascript
const config = {
  jacs_agent_key_algorithm: "Dilithium"
};
```

**Pros**: Quantum-resistant
**Cons**: Experimental, large signatures

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
    "jacsnpm": "^0.1.0",
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
import { JacsAgent } from 'jacsnpm';
import fs from 'fs';

// Load configuration
const config = JSON.parse(fs.readFileSync('./jacs.config.json', 'utf8'));

// Create agent
const agent = new JacsAgent(config);

// Initialize if needed
if (!config.jacs_agent_id_and_version) {
  await agent.generateKeys();
  const agentDoc = await agent.createAgent({
    name: "My JACS Agent",
    description: "Example Node.js JACS agent"
  });
  
  // Update config with agent ID
  config.jacs_agent_id_and_version = `${agentDoc.jacsId}:${agentDoc.jacsVersion}`;
  fs.writeFileSync('./jacs.config.json', JSON.stringify(config, null, 2));
}

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
npm uninstall jacsnpm
npm install jacsnpm
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
 