# Trust Management Feature Design

**Date:** 2026-01-30
**Status:** Design Document
**Scope:** Modular trust management for JACS agent key verification

---

## Overview

Trust management allows JACS agents to maintain a store of trusted public keys for other agents. This enables:

1. **Persistent key storage** - Avoid repeated network fetches for known agents
2. **Trust levels** - Support for explicit trust decisions (always trust, prompt, deny)
3. **Key revocation** - Mark previously trusted keys as compromised/untrusted
4. **Offline verification** - Verify signatures without network access for trusted agents

---

## Why Database, Not JSON Files?

A simple JSON file approach (`~/.jacs/trusted_keys/*.json`) has significant limitations:

| Concern | JSON Files | Database |
|---------|------------|----------|
| **Concurrent access** | Race conditions, file locking issues | ACID transactions |
| **Query performance** | O(n) scan for lookups | O(1) with indexes |
| **Scalability** | Degrades with 1000s of keys | Handles millions efficiently |
| **Consistency** | Manual integrity checks | Referential integrity |
| **Backup/Sync** | Complex file sync | Built-in replication |
| **Expiration/TTL** | Manual cleanup | Database-level TTL or scheduled jobs |
| **Audit trail** | Requires separate logs | Built-in with triggers |

**Recommendation:** Use a lightweight embedded database for local trust stores, with optional external database support for enterprise deployments.

---

## Modular Architecture Options

### Option 1: Trait-Based Backend Abstraction (Recommended)

Define a `TrustStore` trait that can be implemented by different backends:

```rust
pub trait TrustStore: Send + Sync {
    /// Add a trusted key
    fn trust(&self, entry: TrustEntry) -> Result<(), TrustError>;

    /// Remove trust for an agent
    fn untrust(&self, agent_id: &str) -> Result<(), TrustError>;

    /// Get trust info for an agent
    fn get(&self, agent_id: &str) -> Result<Option<TrustEntry>, TrustError>;

    /// Get trust info by domain
    fn get_by_domain(&self, domain: &str) -> Result<Option<TrustEntry>, TrustError>;

    /// List all trusted agents
    fn list(&self) -> Result<Vec<TrustEntry>, TrustError>;

    /// Check if an agent is trusted
    fn is_trusted(&self, agent_id: &str) -> Result<bool, TrustError>;

    /// Clean up expired entries
    fn cleanup_expired(&self) -> Result<usize, TrustError>;
}

pub struct TrustEntry {
    pub agent_id: String,
    pub domain: Option<String>,
    pub public_key: String,
    pub public_key_hash: String,
    pub algorithm: String,
    pub trust_level: TrustLevel,
    pub added_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_verified: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

pub enum TrustLevel {
    /// Always trust signatures from this agent
    AlwaysTrust,
    /// Trust but verify DNS on first use per session
    TrustOnFirstUse,
    /// Prompt user before trusting (CLI only)
    PromptOnUse,
    /// Explicitly untrusted/revoked
    Denied,
}
```

**Backend Implementations:**

1. **`SqliteTrustStore`** - Embedded SQLite for local/CLI use
2. **`PostgresTrustStore`** - PostgreSQL for server deployments
3. **`MemoryTrustStore`** - In-memory for testing
4. **`RedisTrustStore`** - Redis for distributed caching
5. **`FileTrustStore`** - JSON files for simple cases (not recommended)

---

### Option 2: Storage Adapter Pattern

Reuse JACS's existing storage abstraction:

```rust
// Extend existing StorageType enum
pub enum StorageType {
    FS,
    S3,
    HTTP,
    HAI,
    Memory,
    WebLocal,
    // New:
    SQLite,
    Postgres,
    Redis,
}

// Trust manager uses StorageType
pub struct TrustManager {
    storage: Box<dyn ObjectStore>,
    cache: LruCache<String, TrustEntry>,
}
```

**Pros:** Consistent with existing JACS architecture
**Cons:** ObjectStore interface may not fit relational queries well

---

### Option 3: Plugin Architecture

Make trust management a pluggable module:

```rust
pub trait TrustPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn init(&mut self, config: &Value) -> Result<(), PluginError>;
    fn trust_store(&self) -> &dyn TrustStore;
}

// Registry of trust plugins
pub struct TrustPluginRegistry {
    plugins: HashMap<String, Box<dyn TrustPlugin>>,
    active: String,
}
```

**Pros:** Most flexible, allows third-party implementations
**Cons:** More complex, overkill for most use cases

---

## Recommended Implementation: Option 1 with SQLite Default

### Schema Design

```sql
CREATE TABLE trusted_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT UNIQUE NOT NULL,
    domain TEXT,
    public_key TEXT NOT NULL,
    public_key_hash TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'pq2025',
    trust_level TEXT NOT NULL DEFAULT 'always_trust',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_verified TIMESTAMP,
    metadata TEXT, -- JSON

    -- Indexes
    CREATE INDEX idx_domain ON trusted_agents(domain);
    CREATE INDEX idx_trust_level ON trusted_agents(trust_level);
    CREATE INDEX idx_expires ON trusted_agents(expires_at);
);

CREATE TABLE trust_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL, -- 'trust', 'untrust', 'verify', 'deny'
    reason TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (agent_id) REFERENCES trusted_agents(agent_id)
);

CREATE TABLE revoked_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,
    reported_by TEXT -- agent_id of reporter
);
```

### Configuration

```json
{
  "trust_store": {
    "backend": "sqlite",
    "path": "~/.jacs/trust.db",
    "default_trust_level": "always_trust",
    "key_expiration_days": null,
    "auto_cleanup": true,
    "audit_log": true
  }
}
```

### API Surface

**CLI Commands:**

```bash
# Trust an agent by domain (fetches and stores key)
jacs trust add agent.example.com

# Trust an agent by ID with explicit key
jacs trust add --agent-id UUID --key-file pubkey.pem

# List trusted agents
jacs trust list

# Show details for a trusted agent
jacs trust show agent.example.com

# Remove trust
jacs trust remove agent.example.com

# Revoke a key (mark as compromised)
jacs trust revoke --key-hash HASH --reason "key compromised"

# Export trust store
jacs trust export > trusted_agents.json

# Import trust store
jacs trust import < trusted_agents.json
```

**Tools (OpenClaw/NAPI):**

```typescript
// Add trust for an agent
jacs_trust_agent(domain: string, options?: { level?: TrustLevel, expires?: Date })

// Remove trust
jacs_untrust_agent(domain: string | agentId: string)

// Check if agent is trusted
jacs_is_trusted(domain: string | agentId: string): boolean

// List all trusted agents
jacs_list_trusted(): TrustEntry[]
```

---

## Enterprise Extensions

For enterprise deployments, additional features may be needed:

### 1. Centralized Trust Authority

Organizations may want a central trust server:

```
┌─────────────────┐     ┌─────────────────┐
│   Agent A       │────▶│  Trust Server   │
│   (Employee)    │     │  (Corporate)    │
└─────────────────┘     └────────┬────────┘
                                 │
┌─────────────────┐              │
│   Agent B       │──────────────┘
│   (Contractor)  │
└─────────────────┘
```

### 2. Trust Hierarchies

Support for organizational trust chains:

```
hai.ai (root)
  └── acme.com (organization)
       ├── sales.acme.com (department)
       │    └── agent-123 (individual)
       └── eng.acme.com (department)
            └── agent-456 (individual)
```

### 3. Cross-Organization Trust

Federation between organizations:

```json
{
  "federation": {
    "partners": [
      {
        "domain": "partner.com",
        "trust_level": "trust_on_first_use",
        "trust_anchor": "https://partner.com/.well-known/jacs-trust-anchor.json"
      }
    ]
  }
}
```

### 4. Certificate Transparency

Log all trust decisions to an immutable log:

```rust
pub trait TransparencyLog {
    fn append(&self, entry: TrustLogEntry) -> Result<LogReceipt, Error>;
    fn verify(&self, receipt: &LogReceipt) -> Result<bool, Error>;
    fn audit(&self, agent_id: &str) -> Result<Vec<TrustLogEntry>, Error>;
}
```

---

## Implementation Phases

### Phase 1: Core Trust Store (MVP)

- SQLite backend with basic CRUD
- CLI commands: `trust add`, `trust list`, `trust remove`
- Integrate with `jacs_verify_auto` to check trust store first
- ~2-3 days of work

### Phase 2: OpenClaw Integration

- NAPI bindings for trust functions
- TypeScript tools: `jacs_trust_agent`, `jacs_untrust_agent`
- Update `jacs_verify_auto` to use trust store
- ~1-2 days of work

### Phase 3: Enhanced Features

- Key revocation list
- Audit logging
- Trust expiration
- Export/import
- ~2-3 days of work

### Phase 4: Enterprise Features (Future)

- PostgreSQL backend
- Trust hierarchies
- Federation
- Certificate transparency
- Scope TBD based on customer requirements

---

## Alternatives Considered

### 1. Use Operating System Keychain

**Approach:** Store trusted keys in macOS Keychain, Windows Credential Manager, or Linux Secret Service.

**Pros:**
- OS-level security
- User-familiar trust prompts
- Hardware security module support

**Cons:**
- Platform-specific implementations
- Limited metadata storage
- No cross-platform portability

### 2. Web of Trust (PGP-style)

**Approach:** Agents sign each other's keys to create a trust graph.

**Pros:**
- Decentralized
- No central authority needed
- Mathematically robust

**Cons:**
- Complex for users to understand
- Key signing ceremonies required
- Doesn't scale well

### 3. DANE/TLSA DNS Records

**Approach:** Store trust anchors in DNS with DNSSEC.

**Pros:**
- Leverages existing DNS infrastructure
- Already using DNS for discovery

**Cons:**
- DNS record size limits
- Requires DNSSEC (not universal)
- Slow updates (TTL)

### 4. Blockchain-Based Trust

**Approach:** Store trust decisions on a blockchain.

**Pros:**
- Immutable audit trail
- Decentralized

**Cons:**
- Overkill for most use cases
- Transaction costs
- Environmental concerns
- Adds significant complexity

---

## Recommendation

**Start with Option 1 (Trait-based) with SQLite default.**

This provides:
- Clean abstraction for future backends
- Simple embedded database for local use
- Clear upgrade path to PostgreSQL for servers
- No external dependencies for basic usage

The modular design allows swapping backends without changing application code, which is essential for JACS's polyglot nature (Rust CLI, Node.js plugin, Python bindings all need consistent trust management).

---

## References

- [TOFU (Trust On First Use)](https://en.wikipedia.org/wiki/Trust_on_first_use) - SSH-style trust model
- [Certificate Transparency](https://certificate.transparency.dev/) - Google's approach to public key logging
- [DANE (DNS-Based Authentication)](https://datatracker.ietf.org/doc/html/rfc6698) - RFC for DNS-based trust
- [SQLite in Production](https://www.sqlite.org/whentouse.html) - When SQLite is appropriate
