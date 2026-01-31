# Core Concepts

Understanding JACS requires familiarity with several key concepts that work together to create a secure, verifiable communication framework for AI agents.

## Agents

An **Agent** is the fundamental entity in JACS - an autonomous participant that can create, sign, and verify documents.

### Agent Identity
```json
{
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsVersion": "123e4567-e89b-12d3-a456-426614174000",
  "jacsType": "agent",
  "name": "Content Creation Agent",
  "description": "Specialized in creating marketing content"
}
```

**Key Properties:**
- **jacsId**: Permanent UUID identifying the agent
- **jacsVersion**: UUID that changes with each update
- **Cryptographic Keys**: Ed25519, RSA, or post-quantum key pairs
- **Services**: Capabilities the agent offers
- **Contacts**: How to reach the agent

### Agent Lifecycle
1. **Creation**: Generate keys and initial agent document
2. **Registration**: Store public keys for verification
3. **Operation**: Create and sign documents
4. **Updates**: Version changes while maintaining identity
5. **Verification**: Other agents validate signatures

## Documents

A **Document** is any JSON object that follows JACS conventions for identity, versioning, and cryptographic integrity.

### Document Structure
```json
{
  "jacsId": "doc-uuid-here",
  "jacsVersion": "version-uuid-here",
  "jacsType": "task",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsPreviousVersion": "previous-version-uuid",
  
  "title": "Analyze Q4 Sales Data",
  "description": "Generate insights from sales data",
  
  "jacsSha256": "hash-of-document-content",
  "jacsSignature": {
    "agentID": "agent-uuid",
    "agentVersion": "agent-version-uuid",
    "signature": "base64-signature",
    "signingAlgorithm": "ring-Ed25519",
    "publicKeyHash": "hash-of-public-key",
    "date": "2024-01-15T10:30:00Z",
    "fields": ["jacsId", "title", "description"]
  }
}
```

### Required JACS Fields

| Field | Purpose | Example |
|-------|---------|---------|
| `$schema` | JSON Schema reference | URL to schema |
| `jacsId` | Permanent document identifier | UUID v4 |
| `jacsVersion` | Version identifier (changes on update) | UUID v4 |
| `jacsType` | Document type | "agent", "task", "message" |
| `jacsVersionDate` | When this version was created | RFC 3339 timestamp |
| `jacsOriginalVersion` | Original version UUID | UUID v4 |
| `jacsOriginalDate` | Original creation timestamp | RFC 3339 timestamp |
| `jacsLevel` | Data level/intent | "raw", "config", "artifact", "derived" |
| `jacsPreviousVersion` | Previous version UUID (optional) | UUID v4 or null |
| `jacsSha256` | Hash of document content | SHA-256 hex string |
| `jacsSignature` | Cryptographic signature | Signature object |

### Document Types

**Agent Documents**
- Define agent identity and capabilities
- Contain service definitions and contact information
- Self-signed by the agent

**Task Documents**  
- Describe work to be performed
- Include success/failure criteria
- Can be delegated between agents

**Message Documents**
- General communication between agents
- Can include attachments and metadata
- Support threaded conversations

**Agreement Documents**
- Multi-party consent mechanisms
- Track required and actual signatures
- Enforce completion before proceeding

## Tasks

Tasks represent work that can be delegated, tracked, and verified between agents.

### Task Structure
```json
{
  "jacsType": "task",
  "title": "Generate Marketing Copy",
  "description": "Create compelling copy for product launch",
  
  "actions": [
    {
      "id": "research",
      "name": "Research competitors",
      "description": "Analyze competitor messaging",
      "success": "Complete competitive analysis report",
      "failure": "Unable to access competitor data"
    }
  ],
  
  "jacsTaskCustomer": {
    "agentID": "customer-agent-uuid",
    "signature": "customer-signature"
  }
}
```

### Task Lifecycle
1. **Creation**: Customer agent creates task with requirements
2. **Delegation**: Task sent to service provider agent
3. **Agreement**: Provider signs agreement to accept task
4. **Execution**: Provider performs the work
5. **Completion**: Provider creates completion document
6. **Verification**: Customer verifies and accepts results

### Task Components

**Actions**: Individual steps within a task
- **id**: Unique identifier within the task
- **name**: Human-readable action name
- **description**: Detailed requirements
- **success**: Definition of successful completion
- **failure**: What constitutes failure

**Services**: Required capabilities
- **type**: Service category
- **requirements**: Specific needs
- **constraints**: Limitations or restrictions

## Agreements

Agreements enable multi-party consent and coordination between agents.

### Agreement Structure
```json
{
  "jacsType": "agreement",
  "title": "Task Acceptance Agreement",
  "question": "Do you agree to complete the marketing copy task?",
  "context": "Task ID: abc123, Deadline: 2024-01-20",
  
  "agents": [
    "agent-1-uuid",
    "agent-2-uuid",
    "agent-3-uuid"
  ],
  
  "jacsAgreement": {
    "agent-1-uuid": {
      "agentID": "agent-1-uuid",
      "signature": "base64-signature",
      "date": "2024-01-15T10:30:00Z"
    },
    "agent-2-uuid": {
      "agentID": "agent-2-uuid", 
      "signature": "base64-signature",
      "date": "2024-01-15T11:15:00Z"
    }
    // agent-3-uuid has not signed yet
  },
  
  "jacsAgreementHash": "hash-of-agreement-content"
}
```

### Agreement Process
1. **Creation**: Initial agent creates agreement with required participants
2. **Distribution**: Agreement sent to all required agents
3. **Review**: Each agent reviews terms and conditions
4. **Signing**: Agents add their signatures if they consent
5. **Completion**: Agreement becomes binding when all parties have signed
6. **Verification**: Any party can verify all signatures

### Agreement Types

**Task Agreements**: Consent to perform specific work
**Service Agreements**: Long-term service provision contracts  
**Data Sharing Agreements**: Permission to access or use data
**Update Agreements**: Consent to system or process changes

## Cryptographic Security

JACS uses industry-standard cryptographic primitives for security.

### Supported Algorithms

**Current Standards**
- **ring-Ed25519**: Fast elliptic curve signatures using the ring library (recommended)
- **RSA-PSS**: Traditional RSA with probabilistic signature scheme

**Post-Quantum**
- **pq-dilithium**: NIST-standardized post-quantum signatures

### Signature Process
1. **Content Extraction**: Specific fields are extracted for signing
2. **Canonicalization**: Fields are sorted and formatted consistently
3. **Hashing**: SHA-256 hash of the canonical content
4. **Signing**: Private key signs the hash
5. **Verification**: Public key verifies the signature

### Key Management
- **Agent Keys**: Each agent has a unique key pair
- **Public Key Distribution**: Public keys shared through secure channels
- **Key Rotation**: Agents can update keys while maintaining identity
- **Key Verification**: Public key hashes ensure integrity

## Versioning and Audit Trails

JACS provides comprehensive versioning for tracking document evolution.

### Version Management
- **Immutable IDs**: `jacsId` never changes for a document
- **Version IDs**: `jacsVersion` changes with each update
- **Previous Versions**: `jacsPreviousVersion` creates a chain
- **Timestamps**: `jacsVersionDate` provides chronological order

### Audit Trail Benefits
- **Complete History**: Track all changes to any document
- **Attribution**: Know exactly who made each change
- **Verification**: Cryptographic proof of authenticity
- **Compliance**: Meet regulatory audit requirements

## Storage and Transport

JACS documents are designed to be storage and transport agnostic.

### Storage Options
- **File System**: Simple JSON files
- **Databases**: Store as JSON/JSONB fields
- **Object Storage**: S3, Azure Blob, Google Cloud Storage
- **Version Control**: Git repositories for change tracking

### Transport Mechanisms
- **HTTP APIs**: RESTful or GraphQL endpoints
- **Message Queues**: RabbitMQ, Kafka, SQS
- **Email**: Documents as attachments
- **Direct Transfer**: USB drives, file sharing

### Format Compatibility
- **JSON**: Universal compatibility across all systems
- **Schema Validation**: Ensures consistent structure
- **Self-Contained**: All necessary information in the document
- **Human Readable**: Can be inspected and debugged easily

## Next Steps

Now that you understand the core concepts:

1. **[Quick Start](quick-start.md)** - Try JACS hands-on
2. **Choose Implementation**:
   - [Rust CLI](../rust/installation.md) for command-line usage
   - [Node.js](../nodejs/installation.md) for web applications
   - [Python](../python/installation.md) for AI/ML workflows
3. **[Examples](../examples/cli.md)** - See real-world usage patterns 