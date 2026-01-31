# Storage Backends

JACS supports multiple storage backends for persisting documents and agents. This flexibility allows deployment in various environments from local development to cloud infrastructure.

## Available Backends

| Backend | Config Value | Description |
|---------|--------------|-------------|
| Filesystem | `fs` | Local file storage (default) |
| AWS S3 | `aws` | Amazon S3 object storage |
| HAI Cloud | `hai` | HAI managed storage |

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
