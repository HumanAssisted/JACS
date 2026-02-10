# Migration Guide

This guide covers migrating between JACS versions and common migration scenarios.

## Version Compatibility

JACS maintains backward compatibility for document verification:
- Documents signed with older versions can be verified with newer versions
- Older JACS versions cannot verify documents using newer cryptographic algorithms

## Migrating Node.js from 0.6.x to 0.7.0

### Breaking Change: Async-First API

In v0.7.0, all NAPI operations return Promises by default. Sync variants are available with a `Sync` suffix, following the Node.js convention (like `fs.readFile` vs `fs.readFileSync`).

**Before (v0.6.x):**
```javascript
const agent = new JacsAgent();
agent.load('./jacs.config.json');
const doc = agent.createDocument(JSON.stringify(content));
const isValid = agent.verifyDocument(doc);
```

**After (v0.7.0, async -- recommended):**
```javascript
const agent = new JacsAgent();
await agent.load('./jacs.config.json');
const doc = await agent.createDocument(JSON.stringify(content));
const isValid = await agent.verifyDocument(doc);
```

**After (v0.7.0, sync -- for scripts/CLI):**
```javascript
const agent = new JacsAgent();
agent.loadSync('./jacs.config.json');
const doc = agent.createDocumentSync(JSON.stringify(content));
const isValid = agent.verifyDocumentSync(doc);
```

### Method Renaming Summary

| v0.6.x | v0.7.0 Async (default) | v0.7.0 Sync |
|--------|----------------------|-------------|
| `agent.load(path)` | `await agent.load(path)` | `agent.loadSync(path)` |
| `agent.createDocument(...)` | `await agent.createDocument(...)` | `agent.createDocumentSync(...)` |
| `agent.verifyDocument(doc)` | `await agent.verifyDocument(doc)` | `agent.verifyDocumentSync(doc)` |
| `agent.verifyAgent()` | `await agent.verifyAgent()` | `agent.verifyAgentSync()` |
| `agent.updateAgent(json)` | `await agent.updateAgent(json)` | `agent.updateAgentSync(json)` |
| `agent.updateDocument(...)` | `await agent.updateDocument(...)` | `agent.updateDocumentSync(...)` |
| `agent.signString(data)` | `await agent.signString(data)` | `agent.signStringSync(data)` |
| `agent.createAgreement(...)` | `await agent.createAgreement(...)` | `agent.createAgreementSync(...)` |
| `agent.signAgreement(...)` | `await agent.signAgreement(...)` | `agent.signAgreementSync(...)` |
| `agent.checkAgreement(...)` | `await agent.checkAgreement(...)` | `agent.checkAgreementSync(...)` |

### V8-Thread-Only Methods (No Change)

These methods remain synchronous without a `Sync` suffix because they use V8-thread-only APIs (`Env`, `JsObject`):

- `agent.signRequest(params)` -- unchanged
- `agent.verifyResponse(doc)` -- unchanged
- `agent.verifyResponseWithAgentId(doc)` -- unchanged

### Simplified API (Module-Level)

The `@hai.ai/jacs/simple` module follows the same pattern:

```javascript
// v0.6.x
jacs.quickstart();
const signed = jacs.signMessage({ action: 'approve' });

// v0.7.0 async (recommended)
await jacs.quickstart();
const signed = await jacs.signMessage({ action: 'approve' });

// v0.7.0 sync
jacs.quickstartSync();
const signed = jacs.signMessageSync({ action: 'approve' });
```

### Pure Sync Functions (No Change)

These functions do not call NAPI and remain unchanged (no suffix needed):

- `hashString()`, `createConfig()`, `getPublicKey()`, `isLoaded()`, `exportAgent()`, `getAgentInfo()`
- `getDnsRecord()`, `getWellKnownJson()`, `verifyStandalone()`
- Trust store: `trustAgent()`, `listTrustedAgents()`, `untrustAgent()`, `isTrusted()`, `getTrustedAgent()`

### Migration Steps

1. **Update dependency:** `npm install @hai.ai/jacs@0.7.0`
2. **Add `await`** to all NAPI method calls, or append `Sync` to method names
3. **Update test assertions** to handle Promises (use `async/await` in test functions)
4. **V8-thread-only methods** (`signRequest`, `verifyResponse`, `verifyResponseWithAgentId`) need no changes

## Migrating from 0.5.1 to 0.5.2

### Migration Notes

**PBKDF2 Iteration Count**: New key encryptions use 600,000 iterations (up from 100,000). Existing encrypted keys are decrypted automatically via fallback. To upgrade existing keys, re-encrypt them:

```bash
# Re-generate keys to use the new iteration count
jacs keygen
```

### Deprecated Environment Variables

- `JACS_USE_SECURITY` is now `JACS_ENABLE_FILESYSTEM_QUARANTINE`. The old name still works with a deprecation warning.

### New Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JACS_MAX_SIGNATURE_AGE_SECONDS` | `0` (no expiration) | Maximum age of valid signatures. Set to a positive value to enable (e.g., `7776000` for 90 days). |
| `JACS_REQUIRE_EXPLICIT_ALGORITHM` | `false` | When `true`, reject verification if `signingAlgorithm` is missing. |
| `JACS_ENABLE_FILESYSTEM_QUARANTINE` | `false` | Enable filesystem quarantine (replaces `JACS_USE_SECURITY`). |

## Migrating from 0.2.x to 0.3.x

### Configuration Changes

**New Configuration Fields:**

```json
{
  "observability": {
    "logs": { "enabled": true, "level": "info" },
    "metrics": { "enabled": false },
    "tracing": { "enabled": false }
  }
}
```

**Deprecated Fields:**
- `jacs_log_level` → Use `observability.logs.level`
- `jacs_log_file` → Use `observability.logs.destination`

### Migration Steps

1. **Update Configuration:**
   ```bash
   # Backup current config
   cp jacs.config.json jacs.config.json.backup

   # Update to new format
   # Add observability section if needed
   ```

2. **Update Dependencies:**
   ```bash
   # Node.js
   npm install @hai.ai/jacs@latest

   # Python
   pip install --upgrade jacs
   ```

3. **Verify Existing Documents:**
   ```bash
   jacs document verify -d ./jacs_data/documents/
   ```

## Migrating Storage Backends

### Filesystem to AWS S3

1. **Create S3 Bucket:**
   ```bash
   aws s3 mb s3://my-jacs-bucket
   ```

2. **Update Configuration:**
   ```json
   {
     "jacs_default_storage": "aws",
     "jacs_data_directory": "s3://my-jacs-bucket/data"
   }
   ```

3. **Set Environment Variables:**
   ```bash
   export AWS_ACCESS_KEY_ID="your-key"
   export AWS_SECRET_ACCESS_KEY="your-secret"
   export AWS_REGION="us-east-1"
   ```

4. **Migrate Documents:**
   ```bash
   # Upload existing documents
   aws s3 sync ./jacs_data/ s3://my-jacs-bucket/data/
   ```

5. **Verify Migration:**
   ```bash
   jacs document verify -d s3://my-jacs-bucket/data/documents/
   ```

### AWS S3 to Filesystem

1. **Download Documents:**
   ```bash
   aws s3 sync s3://my-jacs-bucket/data/ ./jacs_data/
   ```

2. **Update Configuration:**
   ```json
   {
     "jacs_default_storage": "fs",
     "jacs_data_directory": "./jacs_data"
   }
   ```

3. **Verify Documents:**
   ```bash
   jacs document verify -d ./jacs_data/documents/
   ```

## Migrating Cryptographic Algorithms

### Ed25519 to Post-Quantum

For increased security, you may want to migrate to post-quantum algorithms.

1. **Create New Agent with New Algorithm:**
   ```json
   {
     "jacs_agent_key_algorithm": "pq-dilithium"
   }
   ```

   ```bash
   jacs agent create --create-keys true -f new-agent.json
   ```

2. **Update Configuration:**
   ```json
   {
     "jacs_agent_key_algorithm": "pq-dilithium",
     "jacs_agent_id_and_version": "new-agent-id:new-version"
   }
   ```

3. **Re-sign Critical Documents (Optional):**
   ```javascript
   // Re-sign documents with new algorithm
   const oldDoc = JSON.parse(fs.readFileSync('./old-doc.json'));

   // Remove old signature fields
   delete oldDoc.jacsSignature;
   delete oldDoc.jacsSha256;

   // Create new signed version
   const newDoc = await agent.createDocument(JSON.stringify(oldDoc));
   ```

**Note:** Old documents remain valid with old signatures. Re-signing is only needed for documents that require the new algorithm.

## Migrating Between Platforms

### Node.js to Python

Both platforms use the same document format:

```javascript
// Node.js - create document
const signedDoc = await agent.createDocument(JSON.stringify(content));
fs.writeFileSync('doc.json', signedDoc);
```

```python
# Python - verify the same document
with open('doc.json', 'r') as f:
    doc_string = f.read()

is_valid = agent.verify_document(doc_string)
```

### Sharing Agents Between Platforms

Agents can be used across platforms by sharing configuration:

1. **Export Agent Files:**
   ```
   jacs_keys/
   ├── private.pem
   └── public.pem
   jacs.config.json
   ```

2. **Use Same Config in Both:**
   ```javascript
   // Node.js
   await agent.load('./jacs.config.json');
   ```

   ```python
   # Python
   agent.load('./jacs.config.json')
   ```

## Migrating Key Formats

### Unencrypted to Encrypted Keys

1. **Encrypt Existing Key:**
   ```bash
   # Backup original
   cp jacs_keys/private.pem jacs_keys/private.pem.backup

   # Encrypt with password
   openssl pkcs8 -topk8 -in jacs_keys/private.pem \
     -out jacs_keys/private.pem.enc -v2 aes-256-cbc

   # Remove unencrypted key
   rm jacs_keys/private.pem
   mv jacs_keys/private.pem.enc jacs_keys/private.pem
   ```

2. **Update Configuration:**
   ```json
   {
     "jacs_agent_private_key_filename": "private.pem"
   }
   ```

3. **Set Password:**
   ```bash
   export JACS_PRIVATE_KEY_PASSWORD="your-secure-password"
   ```

## Database Migration

### Adding Database Storage

If migrating from filesystem to include database storage:

1. **Create Database Schema:**
   ```sql
   CREATE TABLE jacs_documents (
     id UUID PRIMARY KEY,
     version_id UUID NOT NULL,
     document JSONB NOT NULL,
     created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
     UNIQUE(id, version_id)
   );
   ```

2. **Import Existing Documents:**
   ```javascript
   const fs = require('fs');
   const path = require('path');
   const { Pool } = require('pg');

   const pool = new Pool({ connectionString: process.env.DATABASE_URL });
   const docsDir = './jacs_data/documents';

   async function importDocuments() {
     const docDirs = fs.readdirSync(docsDir);

     for (const docId of docDirs) {
       const docPath = path.join(docsDir, docId);
       const versions = fs.readdirSync(docPath);

       for (const versionFile of versions) {
         const docString = fs.readFileSync(
           path.join(docPath, versionFile),
           'utf-8'
         );
         const doc = JSON.parse(docString);

         await pool.query(`
           INSERT INTO jacs_documents (id, version_id, document)
           VALUES ($1, $2, $3)
           ON CONFLICT (id, version_id) DO NOTHING
         `, [doc.jacsId, doc.jacsVersion, doc]);
       }
     }
   }

   importDocuments();
   ```

## MCP Integration Migration

### Adding JACS to Existing MCP Server

1. **Install JACS:**
   ```bash
   npm install @hai.ai/jacs
   ```

2. **Wrap Existing Transport:**
   ```javascript
   // Before
   const transport = new StdioServerTransport();
   await server.connect(transport);

   // After
   import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

   const baseTransport = new StdioServerTransport();
   const secureTransport = createJACSTransportProxy(
     baseTransport,
     './jacs.config.json',
     'server'
   );
   await server.connect(secureTransport);
   ```

3. **Update Client:**
   ```javascript
   // Client also needs JACS
   const baseTransport = new StdioClientTransport({ command: 'node', args: ['server.js'] });
   const secureTransport = createJACSTransportProxy(
     baseTransport,
     './jacs.client.config.json',
     'client'
   );
   await client.connect(secureTransport);
   ```

## HTTP API Migration

### Adding JACS to Existing Express API

1. **Install Middleware:**
   ```bash
   npm install @hai.ai/jacs
   ```

2. **Add Middleware to Routes:**
   ```javascript
   import { JACSExpressMiddleware } from '@hai.ai/jacs/http';

   // Before
   app.use('/api', express.json());

   // After - for JACS-protected routes
   app.use('/api/secure', express.text({ type: '*/*' }));
   app.use('/api/secure', JACSExpressMiddleware({
     configPath: './jacs.config.json'
   }));

   // Keep non-JACS routes unchanged
   app.use('/api/public', express.json());
   ```

3. **Update Route Handlers:**
   ```javascript
   // Before
   app.post('/api/data', (req, res) => {
     const payload = req.body;
     // ...
   });

   // After
   app.post('/api/secure/data', (req, res) => {
     const payload = req.jacsPayload;  // Verified payload
     // ...
   });
   ```

## Troubleshooting Migration

### Common Issues

**Documents Not Verifying After Migration:**
- Check algorithm compatibility
- Verify keys were copied correctly
- Ensure configuration paths are correct

**Key File Errors:**
- Verify file permissions (600 for private key)
- Check key format matches algorithm
- Ensure password is set for encrypted keys

**Storage Errors After Migration:**
- Verify storage backend is accessible
- Check credentials/permissions
- Ensure directory structure is correct

### Verification Checklist

After any migration:

1. **Verify Configuration:**
   ```bash
   jacs config read
   ```

2. **Verify Agent:**
   ```bash
   jacs agent verify
   ```

3. **Verify Sample Document:**
   ```bash
   jacs document verify -f ./sample-doc.json
   ```

4. **Test Document Creation:**
   ```bash
   echo '{"test": true}' > test.json
   jacs document create -f test.json
   ```

5. **Verify Version:**
   ```bash
   jacs version
   ```

## Rollback Procedures

If migration fails:

1. **Restore Configuration:**
   ```bash
   cp jacs.config.json.backup jacs.config.json
   ```

2. **Restore Keys:**
   ```bash
   cp -r jacs_keys.backup/* jacs_keys/
   ```

3. **Restore Dependencies:**
   ```bash
   # Node.js
   npm install @hai.ai/jacs@previous-version

   # Python
   pip install jacs==previous-version
   ```

4. **Verify Rollback:**
   ```bash
   jacs agent verify
   jacs document verify -d ./jacs_data/documents/
   ```

## See Also

- [Configuration Reference](configuration.md) - Configuration options
- [Cryptographic Algorithms](../advanced/crypto.md) - Algorithm details
- [Storage Backends](../advanced/storage.md) - Storage options
