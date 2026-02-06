# Storage Backends

JACS supports multiple storage backends for persisting documents and agents. This flexibility allows deployment in various environments from local development to cloud infrastructure.

## Available Backends

| Backend | Config Value | Description |
|---------|--------------|-------------|
| Filesystem | `fs` | Local file storage (default) |
| AWS S3 | `aws` | Amazon S3 object storage |
| HAI Cloud | `hai` | HAI managed storage |
| PostgreSQL | `database` | PostgreSQL with JSONB queries (requires `database` feature) |

## Configuration

Set the storage backend in your configuration:

```json
{
  "jacs_default_storage": "fs",
  "jacs_data_directory": "./jacs_data"
}
```

## Filesystem Storage (fs)

The default storage backend, storing documents as JSON files on the local filesystem.

### Configuration

```json
{
  "jacs_default_storage": "fs",
  "jacs_data_directory": "./jacs_data"
}
```

### Directory Structure

```
jacs_data/
├── agents/
│   └── {agent-id}/
│       └── {version-id}.json
├── documents/
│   └── {document-id}/
│       └── {version-id}.json
└── files/
    └── {attachment-hash}
```

### Use Cases

- Local development
- Single-server deployments
- Testing and prototyping
- Air-gapped environments

### Advantages

- Simple setup
- No network dependencies
- Fast local access
- Easy backup and migration

### Considerations

- Not suitable for distributed systems
- Limited by local disk space
- Single point of failure

### Example

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')  # Using filesystem storage

# Documents are saved to jacs_data/documents/
doc = agent.create_document(json.dumps({
    'title': 'My Document'
}))
# Saved to: jacs_data/documents/{doc-id}/{version-id}.json
```

## AWS S3 Storage (aws)

Cloud object storage using Amazon S3.

### Configuration

```json
{
  "jacs_default_storage": "aws",
  "jacs_data_directory": "s3://my-jacs-bucket/data"
}
```

### Environment Variables

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

### Bucket Structure

```
my-jacs-bucket/
├── data/
│   ├── agents/
│   │   └── {agent-id}/
│   │       └── {version-id}.json
│   ├── documents/
│   │   └── {document-id}/
│   │       └── {version-id}.json
│   └── files/
│       └── {attachment-hash}
```

### Use Cases

- Production deployments
- Distributed systems
- High availability requirements
- Large document volumes

### Advantages

- Scalable storage
- High durability (99.999999999%)
- Geographic redundancy
- Built-in versioning support

### Considerations

- Requires AWS account
- Network latency
- Storage costs
- IAM configuration needed

### IAM Policy

Minimum required permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-jacs-bucket",
        "arn:aws:s3:::my-jacs-bucket/*"
      ]
    }
  ]
}
```

### Example

```python
import jacs
import json
import os

# Set AWS credentials
os.environ['AWS_ACCESS_KEY_ID'] = 'your-key'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'your-secret'
os.environ['AWS_REGION'] = 'us-east-1'

agent = jacs.JacsAgent()
agent.load('./jacs.s3.config.json')

# Documents are saved to S3
doc = agent.create_document(json.dumps({
    'title': 'Cloud Document'
}))
```

## HAI Cloud Storage (hai)

Managed storage provided by HAI.

### Configuration

```json
{
  "jacs_default_storage": "hai"
}
```

### Features

- Managed infrastructure
- Built-in agent registry
- Cross-organization document sharing
- Integrated DNS verification

### Use Cases

- Multi-agent ecosystems
- Cross-organization collaboration
- Managed deployments
- Integration with HAI services

## PostgreSQL Database Storage (database)

The `database` storage backend stores JACS documents in PostgreSQL, enabling JSONB queries, pagination, and agent-based lookups while preserving cryptographic signatures.

This backend is behind a compile-time feature flag and requires the `database` Cargo feature to be enabled.

### Compile-Time Setup

```bash
# Build with database support
cargo build --features database

# Run tests with database support (requires Docker for testcontainers)
cargo test --features database-tests
```

### Configuration

```json
{
  "jacs_default_storage": "database"
}
```

Environment variables (12-Factor compliant):

```bash
export JACS_DATABASE_URL="postgres://user:password@localhost:5432/jacs"
export JACS_DATABASE_MAX_CONNECTIONS=10       # optional, default 10
export JACS_DATABASE_MIN_CONNECTIONS=1        # optional, default 1
export JACS_DATABASE_CONNECT_TIMEOUT_SECS=30  # optional, default 30
```

### How It Works

JACS uses a **TEXT + JSONB dual-column** strategy:

- **`raw_contents` (TEXT)**: Stores the exact JSON bytes as-is. This is used when retrieving documents to preserve cryptographic signatures (PostgreSQL JSONB normalizes key ordering, which would break signatures).
- **`file_contents` (JSONB)**: Stores the same document as JSONB for efficient queries, field extraction, and indexing.

### Table Schema

```sql
CREATE TABLE jacs_document (
    jacs_id TEXT NOT NULL,
    jacs_version TEXT NOT NULL,
    agent_id TEXT,
    jacs_type TEXT NOT NULL,
    raw_contents TEXT NOT NULL,
    file_contents JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (jacs_id, jacs_version)
);
```

### Append-Only Model

Documents are **immutable once stored**. New versions create new rows keyed by `(jacs_id, jacs_version)`. There are no UPDATE operations on existing rows. Inserting a duplicate `(jacs_id, jacs_version)` is silently ignored (`ON CONFLICT DO NOTHING`).

### Query Capabilities

The database backend provides additional query methods beyond basic CRUD:

| Method | Description |
|--------|-------------|
| `query_by_type(type, limit, offset)` | Paginated queries by document type |
| `query_by_field(field, value, type, limit, offset)` | JSONB field queries |
| `count_by_type(type)` | Count documents by type |
| `get_versions(id)` | All versions of a document |
| `get_latest(id)` | Most recent version |
| `query_by_agent(agent_id, type, limit, offset)` | Documents by signing agent |

### Rust API Example

```rust
use jacs::storage::{DatabaseStorage, DatabaseDocumentTraits, StorageDocumentTraits};

// Create storage (requires tokio runtime)
let storage = DatabaseStorage::new(
    "postgres://localhost/jacs",
    Some(10),  // max connections
    Some(1),   // min connections
    Some(30),  // timeout seconds
)?;

// Run migrations (creates table + indexes)
storage.run_migrations()?;

// Store a document
storage.store_document(&doc)?;

// Query by type with pagination
let commitments = storage.query_by_type("commitment", 10, 0)?;

// Query by JSONB field
let active = storage.query_by_field(
    "jacsCommitmentStatus", "active", Some("commitment"), 10, 0
)?;

// Get latest version
let latest = storage.get_latest("some-document-id")?;
```

### Security Note

Even when using database storage, **keys are always loaded from the filesystem or keyservers** -- never from the database or configuration providers. The database stores only signed documents.

### Use Cases

- Production deployments requiring complex queries
- Multi-agent systems with shared document visibility
- Applications needing pagination and aggregation
- Environments where JSONB indexing provides significant query performance

### Considerations

- Requires PostgreSQL 14+
- Requires tokio runtime (not available in WASM)
- Compile-time feature flag (`database`)
- Network dependency on PostgreSQL server

## In-Memory Storage

For testing and temporary operations, documents can be created without saving:

```python
# Create document without saving
doc = agent.create_document(
    json.dumps({'temp': 'data'}),
    no_save=True  # Don't persist
)
```

```javascript
const doc = agent.createDocument(
  JSON.stringify({ temp: 'data' }),
  null,  // custom_schema
  null,  // output_filename
  true   // no_save = true
);
```

## Storage Selection Guide

| Scenario | Recommended Backend |
|----------|---------------------|
| Development | `fs` |
| Single server | `fs` |
| Complex queries needed | `database` |
| Multi-agent with shared queries | `database` |
| Cloud deployment | `aws` |
| High availability | `aws` |
| Multi-organization | `hai` |
| Testing | In-memory (no_save) |

## File Storage

### Embedded Files

Files can be embedded directly in documents:

```python
doc = agent.create_document(
    json.dumps({'report': 'Monthly Report'}),
    attachments='./report.pdf',
    embed=True
)
```

The file contents are base64-encoded and stored in `jacsFiles`.

### External Files

Or reference files without embedding:

```python
doc = agent.create_document(
    json.dumps({'report': 'Monthly Report'}),
    attachments='./report.pdf',
    embed=False
)
```

Only the file path and hash are stored. The file must be available when the document is accessed.

## Data Migration

### Filesystem to S3

```python
import jacs
import json
import os

# Load from filesystem
fs_agent = jacs.JacsAgent()
fs_agent.load('./jacs.fs.config.json')

# Read all documents
# (implementation depends on your document tracking)

# Configure S3
s3_agent = jacs.JacsAgent()
s3_agent.load('./jacs.s3.config.json')

# Re-create documents in S3
for doc_json in documents:
    doc = json.loads(doc_json)
    # Remove existing signatures for re-signing
    del doc['jacsSignature']
    del doc['jacsSha256']
    s3_agent.create_document(json.dumps(doc))
```

### Export/Import

For manual migration:

```bash
# Export from filesystem
tar -czf jacs_backup.tar.gz ./jacs_data

# Import to new location
tar -xzf jacs_backup.tar.gz -C /new/location
```

## Backup and Recovery

### Filesystem Backup

```bash
# Regular backups
rsync -av ./jacs_data/ /backup/jacs_data/

# Or with timestamp
tar -czf jacs_backup_$(date +%Y%m%d).tar.gz ./jacs_data
```

### S3 Backup

Enable S3 versioning for automatic backups:

```bash
aws s3api put-bucket-versioning \
    --bucket my-jacs-bucket \
    --versioning-configuration Status=Enabled
```

### Cross-Region Replication

For disaster recovery with S3:

```bash
aws s3api put-bucket-replication \
    --bucket my-jacs-bucket \
    --replication-configuration file://replication.json
```

## Performance Optimization

### Filesystem

- Use SSD storage
- Consider separate disk for jacs_data
- Enable filesystem caching

### S3

- Use regional endpoints
- Enable transfer acceleration for global access
- Consider S3 Intelligent-Tiering for cost optimization

### Caching

Implement application-level caching for frequently accessed documents:

```python
import functools

@functools.lru_cache(maxsize=100)
def get_document(doc_id, version_id):
    return agent.get_document(f"{doc_id}:{version_id}")
```

## Security Considerations

### Filesystem

```bash
# Restrict permissions
chmod 700 ./jacs_data
chmod 600 ./jacs_data/**/*.json
```

### S3

- Enable encryption at rest (SSE-S3 or SSE-KMS)
- Use VPC endpoints for private access
- Enable access logging
- Configure bucket policies carefully

```json
{
  "jacs_data_directory": "s3://my-jacs-bucket/data",
  "aws_s3_encryption": "AES256"
}
```

## See Also

- [Configuration](../schemas/configuration.md) - Storage configuration options
- [Security Model](security.md) - Storage security
- [Quick Start](../getting-started/quickstart.md) - Initial setup
