# Databases

While JACS provides built-in storage backends (filesystem, S3, HAI Cloud), you may need to integrate JACS documents with traditional databases for querying, indexing, or application-specific requirements.

## Overview

JACS documents are JSON objects with cryptographic signatures. They can be stored in any database that supports JSON or text storage:

| Database Type | Storage Method | Best For |
|---------------|----------------|----------|
| PostgreSQL | JSONB column | Complex queries, relations |
| MongoDB | Native documents | Document-centric apps |
| SQLite | TEXT column | Local/embedded apps |
| Redis | Key-value | Caching, high-speed access |

## Why Use a Database?

The built-in JACS storage backends are optimized for document integrity and versioning. Use a database when you need:

- **Complex Queries**: Search across document fields
- **Indexing**: Fast lookups on specific attributes
- **Relations**: Link JACS documents to other data
- **Transactions**: Atomic operations across multiple documents
- **Existing Infrastructure**: Integrate with current systems

## PostgreSQL Integration

### Schema Design

```sql
-- JACS documents table
CREATE TABLE jacs_documents (
    id UUID PRIMARY KEY,
    version_id UUID NOT NULL,
    document JSONB NOT NULL,
    signature_valid BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Extracted fields for indexing
    agent_id UUID,
    document_type VARCHAR(100),

    UNIQUE(id, version_id)
);

-- Index on JACS fields
CREATE INDEX idx_jacs_agent ON jacs_documents(agent_id);
CREATE INDEX idx_jacs_type ON jacs_documents(document_type);
CREATE INDEX idx_jacs_created ON jacs_documents(created_at);

-- GIN index for JSONB queries
CREATE INDEX idx_jacs_document ON jacs_documents USING GIN (document);
```

### Node.js Example

```javascript
import { Pool } from 'pg';
import jacs from 'jacsnpm';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

class JacsDocumentStore {
  constructor(configPath) {
    this.configPath = configPath;
  }

  async initialize() {
    await jacs.load(this.configPath);
  }

  async createAndStore(content, options = {}) {
    // Create JACS document
    const docString = await jacs.createDocument(
      JSON.stringify(content),
      options.customSchema
    );

    const doc = JSON.parse(docString);

    // Store in database
    const result = await pool.query(`
      INSERT INTO jacs_documents (id, version_id, document, agent_id, document_type)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [
      doc.jacsId,
      doc.jacsVersion,
      doc,
      doc.jacsSignature?.agentID,
      content.type || 'document'
    ]);

    return result.rows[0];
  }

  async getDocument(id, versionId = null) {
    let query = 'SELECT * FROM jacs_documents WHERE id = $1';
    const params = [id];

    if (versionId) {
      query += ' AND version_id = $2';
      params.push(versionId);
    } else {
      query += ' ORDER BY created_at DESC LIMIT 1';
    }

    const result = await pool.query(query, params);
    return result.rows[0];
  }

  async verifyDocument(id) {
    const row = await this.getDocument(id);
    if (!row) return null;

    const isValid = await jacs.verifyDocument(JSON.stringify(row.document));

    // Update signature_valid flag
    await pool.query(
      'UPDATE jacs_documents SET signature_valid = $1 WHERE id = $2 AND version_id = $3',
      [isValid, row.id, row.version_id]
    );

    return { document: row.document, isValid };
  }

  async searchDocuments(query) {
    const result = await pool.query(`
      SELECT * FROM jacs_documents
      WHERE document @> $1
      ORDER BY created_at DESC
    `, [JSON.stringify(query)]);

    return result.rows;
  }
}

// Usage
const store = new JacsDocumentStore('./jacs.config.json');
await store.initialize();

// Create and store a document
const doc = await store.createAndStore({
  type: 'invoice',
  amount: 1500,
  customer: 'Acme Corp'
});

// Search documents
const invoices = await store.searchDocuments({ type: 'invoice' });
```

### Python Example

```python
import json
import jacs
import psycopg2
from psycopg2.extras import RealDictCursor

class JacsDocumentStore:
    def __init__(self, config_path, database_url):
        self.config_path = config_path
        self.database_url = database_url
        self.conn = None

    def initialize(self):
        # Initialize JACS
        agent = jacs.JacsAgent()
        agent.load(self.config_path)

        # Connect to database
        self.conn = psycopg2.connect(self.database_url)

    def create_and_store(self, content, custom_schema=None):
        # Create JACS document
        doc_string = jacs.create_document(
            json.dumps(content),
            custom_schema=custom_schema
        )
        doc = json.loads(doc_string)

        # Store in database
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO jacs_documents (id, version_id, document, agent_id, document_type)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING *
            """, (
                doc['jacsId'],
                doc['jacsVersion'],
                json.dumps(doc),
                doc.get('jacsSignature', {}).get('agentID'),
                content.get('type', 'document')
            ))
            self.conn.commit()
            return cur.fetchone()

    def get_document(self, doc_id, version_id=None):
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            if version_id:
                cur.execute(
                    "SELECT * FROM jacs_documents WHERE id = %s AND version_id = %s",
                    (doc_id, version_id)
                )
            else:
                cur.execute(
                    "SELECT * FROM jacs_documents WHERE id = %s ORDER BY created_at DESC LIMIT 1",
                    (doc_id,)
                )
            return cur.fetchone()

    def verify_document(self, doc_id):
        row = self.get_document(doc_id)
        if not row:
            return None

        is_valid = jacs.verify_document(json.dumps(row['document']))

        # Update verification status
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE jacs_documents SET signature_valid = %s WHERE id = %s AND version_id = %s",
                (is_valid, row['id'], row['version_id'])
            )
            self.conn.commit()

        return {'document': row['document'], 'is_valid': is_valid}

    def search_documents(self, query):
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM jacs_documents WHERE document @> %s ORDER BY created_at DESC",
                (json.dumps(query),)
            )
            return cur.fetchall()

# Usage
store = JacsDocumentStore('./jacs.config.json', 'postgresql://localhost/mydb')
store.initialize()

# Create and store a document
doc = store.create_and_store({
    'type': 'invoice',
    'amount': 1500,
    'customer': 'Acme Corp'
})

# Search documents
invoices = store.search_documents({'type': 'invoice'})
```

## MongoDB Integration

### Collection Design

```javascript
// MongoDB schema (using Mongoose)
const jacsDocumentSchema = new mongoose.Schema({
  jacsId: { type: String, required: true, index: true },
  jacsVersion: { type: String, required: true },
  document: { type: mongoose.Schema.Types.Mixed, required: true },
  signatureValid: { type: Boolean, default: true },
  agentId: { type: String, index: true },
  documentType: { type: String, index: true },
  createdAt: { type: Date, default: Date.now, index: true }
});

jacsDocumentSchema.index({ jacsId: 1, jacsVersion: 1 }, { unique: true });
```

### Example

```javascript
import mongoose from 'mongoose';
import jacs from 'jacsnpm';

const JacsDocument = mongoose.model('JacsDocument', jacsDocumentSchema);

class MongoJacsStore {
  async initialize(configPath) {
    await jacs.load(configPath);
    await mongoose.connect(process.env.MONGODB_URI);
  }

  async createAndStore(content, options = {}) {
    const docString = await jacs.createDocument(
      JSON.stringify(content),
      options.customSchema
    );

    const doc = JSON.parse(docString);

    const stored = await JacsDocument.create({
      jacsId: doc.jacsId,
      jacsVersion: doc.jacsVersion,
      document: doc,
      agentId: doc.jacsSignature?.agentID,
      documentType: content.type || 'document'
    });

    return stored;
  }

  async getDocument(jacsId, versionId = null) {
    const query = { jacsId };
    if (versionId) {
      query.jacsVersion = versionId;
    }

    return JacsDocument.findOne(query).sort({ createdAt: -1 });
  }

  async searchDocuments(query) {
    // Build MongoDB query from content fields
    const mongoQuery = {};
    for (const [key, value] of Object.entries(query)) {
      mongoQuery[`document.${key}`] = value;
    }

    return JacsDocument.find(mongoQuery).sort({ createdAt: -1 });
  }

  async getDocumentsByAgent(agentId) {
    return JacsDocument.find({ agentId }).sort({ createdAt: -1 });
  }
}

// Usage
const store = new MongoJacsStore();
await store.initialize('./jacs.config.json');

const doc = await store.createAndStore({
  type: 'contract',
  parties: ['Alice', 'Bob'],
  value: 50000
});

const contracts = await store.searchDocuments({ type: 'contract' });
```

## SQLite Integration

For embedded or local applications:

```javascript
import Database from 'better-sqlite3';
import jacs from 'jacsnpm';

class SqliteJacsStore {
  constructor(dbPath) {
    this.db = new Database(dbPath);
    this.initSchema();
  }

  initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS jacs_documents (
        id TEXT NOT NULL,
        version_id TEXT NOT NULL,
        document TEXT NOT NULL,
        agent_id TEXT,
        document_type TEXT,
        signature_valid INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id, version_id)
      );

      CREATE INDEX IF NOT EXISTS idx_agent ON jacs_documents(agent_id);
      CREATE INDEX IF NOT EXISTS idx_type ON jacs_documents(document_type);
    `);
  }

  async initialize(configPath) {
    await jacs.load(configPath);
  }

  async createAndStore(content, options = {}) {
    const docString = await jacs.createDocument(
      JSON.stringify(content),
      options.customSchema
    );

    const doc = JSON.parse(docString);

    const stmt = this.db.prepare(`
      INSERT INTO jacs_documents (id, version_id, document, agent_id, document_type)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(
      doc.jacsId,
      doc.jacsVersion,
      docString,
      doc.jacsSignature?.agentID,
      content.type || 'document'
    );

    return doc;
  }

  getDocument(id, versionId = null) {
    let query = 'SELECT * FROM jacs_documents WHERE id = ?';
    const params = [id];

    if (versionId) {
      query += ' AND version_id = ?';
      params.push(versionId);
    } else {
      query += ' ORDER BY created_at DESC LIMIT 1';
    }

    const stmt = this.db.prepare(query);
    const row = stmt.get(...params);

    if (row) {
      row.document = JSON.parse(row.document);
    }

    return row;
  }

  searchByType(documentType) {
    const stmt = this.db.prepare(
      'SELECT * FROM jacs_documents WHERE document_type = ? ORDER BY created_at DESC'
    );
    return stmt.all(documentType).map(row => ({
      ...row,
      document: JSON.parse(row.document)
    }));
  }
}
```

## Redis Caching

Use Redis for high-speed document access:

```javascript
import Redis from 'ioredis';
import jacs from 'jacsnpm';

class JacsRedisCache {
  constructor(redisUrl) {
    this.redis = new Redis(redisUrl);
    this.ttl = 3600; // 1 hour default TTL
  }

  async initialize(configPath) {
    await jacs.load(configPath);
  }

  async cacheDocument(docString) {
    const doc = JSON.parse(docString);
    const key = `jacs:${doc.jacsId}:${doc.jacsVersion}`;

    await this.redis.setex(key, this.ttl, docString);

    // Also cache as latest version
    await this.redis.setex(`jacs:${doc.jacsId}:latest`, this.ttl, docString);

    return doc;
  }

  async getDocument(jacsId, versionId = 'latest') {
    const key = `jacs:${jacsId}:${versionId}`;
    const docString = await this.redis.get(key);

    if (!docString) return null;

    return JSON.parse(docString);
  }

  async invalidate(jacsId, versionId = null) {
    if (versionId) {
      await this.redis.del(`jacs:${jacsId}:${versionId}`);
    } else {
      // Invalidate all versions
      const keys = await this.redis.keys(`jacs:${jacsId}:*`);
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    }
  }
}
```

## Indexing Strategies

### Extracting Searchable Fields

Extract key fields during storage for efficient querying:

```javascript
async function extractIndexFields(jacsDocument) {
  return {
    jacsId: jacsDocument.jacsId,
    jacsVersion: jacsDocument.jacsVersion,
    agentId: jacsDocument.jacsSignature?.agentID,
    createdDate: jacsDocument.jacsSignature?.date,
    hasAgreement: !!jacsDocument.jacsAgreement,
    agreementComplete: jacsDocument.jacsAgreement?.signatures?.length ===
                        jacsDocument.jacsAgreement?.agentIDs?.length,
    // Application-specific fields
    documentType: jacsDocument.type,
    status: jacsDocument.status,
    tags: jacsDocument.tags || []
  };
}
```

### Full-Text Search

PostgreSQL example with full-text search:

```sql
-- Add text search column
ALTER TABLE jacs_documents ADD COLUMN search_vector tsvector;

-- Create index
CREATE INDEX idx_search ON jacs_documents USING GIN(search_vector);

-- Update trigger
CREATE OR REPLACE FUNCTION update_search_vector() RETURNS trigger AS $$
BEGIN
  NEW.search_vector := to_tsvector('english',
    coalesce(NEW.document->>'title', '') || ' ' ||
    coalesce(NEW.document->>'content', '') || ' ' ||
    coalesce(NEW.document->>'description', '')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER jacs_search_update
  BEFORE INSERT OR UPDATE ON jacs_documents
  FOR EACH ROW EXECUTE FUNCTION update_search_vector();
```

```javascript
// Search example
async function fullTextSearch(searchQuery) {
  const result = await pool.query(`
    SELECT *, ts_rank(search_vector, plainto_tsquery($1)) as rank
    FROM jacs_documents
    WHERE search_vector @@ plainto_tsquery($1)
    ORDER BY rank DESC
  `, [searchQuery]);

  return result.rows;
}
```

## Best Practices

### 1. Store Complete Documents

Always store the complete JACS document to preserve signatures:

```javascript
// Good - stores complete document
await pool.query(
  'INSERT INTO jacs_documents (id, document) VALUES ($1, $2)',
  [doc.jacsId, JSON.stringify(doc)]  // Complete document
);

// Bad - loses signature data
await pool.query(
  'INSERT INTO documents (id, content) VALUES ($1, $2)',
  [doc.jacsId, JSON.stringify(doc.content)]  // Only content
);
```

### 2. Verify After Retrieval

Always verify signatures when retrieving documents for sensitive operations:

```javascript
async function getVerifiedDocument(id) {
  const row = await pool.query(
    'SELECT document FROM jacs_documents WHERE id = $1',
    [id]
  );

  if (!row.rows[0]) return null;

  const docString = JSON.stringify(row.rows[0].document);
  const isValid = await jacs.verifyDocument(docString);

  if (!isValid) {
    throw new Error('Document signature verification failed');
  }

  return row.rows[0].document;
}
```

### 3. Handle Version History

Maintain version history for audit trails:

```javascript
async function getDocumentHistory(jacsId) {
  const result = await pool.query(`
    SELECT * FROM jacs_documents
    WHERE id = $1
    ORDER BY created_at ASC
  `, [jacsId]);

  return result.rows;
}
```

### 4. Batch Verification

Periodically verify stored documents:

```javascript
async function verifyAllDocuments() {
  const docs = await pool.query('SELECT * FROM jacs_documents');

  for (const row of docs.rows) {
    const docString = JSON.stringify(row.document);
    const isValid = await jacs.verifyDocument(docString);

    if (!isValid) {
      console.warn(`Document ${row.id} failed verification`);
      await pool.query(
        'UPDATE jacs_documents SET signature_valid = false WHERE id = $1',
        [row.id]
      );
    }
  }
}
```

## See Also

- [Storage Backends](../advanced/storage.md) - Built-in JACS storage
- [Security Model](../advanced/security.md) - Document security
- [Testing](../advanced/testing.md) - Testing database integrations
