# Rust Library API

JACS provides a Rust library for programmatic agent and document management. This chapter covers how to use the JACS library in your Rust applications.

## Adding JACS as a Dependency

Add JACS to your `Cargo.toml`:

```toml
[dependencies]
jacs = "0.3"
```

### Feature Flags

```toml
[dependencies]
jacs = { version = "0.3", features = ["cli", "observability"] }
```

| Feature | Description |
|---------|-------------|
| `cli` | CLI utilities and helpers |
| `observability` | OpenTelemetry logging and metrics |
| `observability-convenience` | Helper functions for observability |
| `full` | All features enabled |

## Core Types

### Agent

The `Agent` struct is the central type in JACS. It holds:

- Schema validators
- Agent identity and keys
- Document storage
- Configuration

```rust
use jacs::{get_empty_agent, load_agent};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a new empty agent
    let agent = get_empty_agent();

    // Or load an existing agent
    let agent = load_agent(Some("path/to/agent.json".to_string()))?;

    Ok(())
}
```

### JACSDocument

Documents in JACS are represented by the `JACSDocument` struct:

```rust
pub struct JACSDocument {
    pub id: String,
    pub version: String,
    pub value: serde_json::Value,
    pub jacs_type: String,
}
```

Key methods:

- `getkey()` - Returns `"id:version"` identifier
- `getvalue()` - Returns reference to the JSON value
- `getschema()` - Returns the document's schema URL
- `signing_agent()` - Returns the ID of the signing agent

## Creating an Agent

### Minimal Agent

```rust
use jacs::{get_empty_agent, create_minimal_blank_agent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create agent JSON
    let agent_json = create_minimal_blank_agent(
        "ai".to_string(),                    // agent type
        Some("My service".to_string()),      // service description
        Some("Task completed".to_string()),  // success description
        Some("Task failed".to_string()),     // failure description
    )?;

    // Initialize and load the agent
    let mut agent = get_empty_agent();
    agent.create_agent_and_load(&agent_json, true, None)?;

    // Save the agent
    agent.save()?;

    Ok(())
}
```

### Loading by Configuration

```rust
use jacs::get_empty_agent;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut agent = get_empty_agent();

    // Load from config file
    agent.load_by_config("./jacs.config.json".to_string())?;

    // Or load by agent ID
    agent.load_by_id("agent-id:version-id".to_string())?;

    Ok(())
}
```

### DNS Strict Mode

```rust
use jacs::load_agent_with_dns_strict;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load agent with strict DNS verification
    let agent = load_agent_with_dns_strict(
        "path/to/agent.json".to_string(),
        true  // strict mode
    )?;

    Ok(())
}
```

## Working with Documents

### Creating Documents

The `DocumentTraits` trait provides document operations:

```rust
use jacs::agent::document::DocumentTraits;
use jacs::get_empty_agent;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut agent = get_empty_agent();
    agent.load_by_config("./jacs.config.json".to_string())?;

    // Create a document from JSON
    let json = r#"{"title": "My Document", "content": "Hello, World!"}"#;
    let doc = agent.create_document_and_load(json, None, None)?;

    println!("Document created: {}", doc.getkey());

    Ok(())
}
```

### Creating Documents with Attachments

```rust
use jacs::agent::document::DocumentTraits;

// With file attachments
let attachments = Some(vec!["./report.pdf".to_string()]);
let embed = Some(true);  // Embed files in document

let doc = agent.create_document_and_load(
    json,
    attachments,
    embed
)?;
```

### Loading Documents

```rust
use jacs::agent::document::DocumentTraits;

// Load a document from JSON string
let doc = agent.load_document(&document_json_string)?;

// Get a stored document by key
let doc = agent.get_document("doc-id:version-id")?;

// List all document keys
let keys = agent.get_document_keys();
```

### Updating Documents

```rust
use jacs::agent::document::DocumentTraits;

// Update creates a new version
let updated_doc = agent.update_document(
    "doc-id:version-id",    // original document key
    &modified_json_string,  // new content
    None,                   // optional attachments
    None,                   // embed flag
)?;
```

### Verifying Documents

```rust
use jacs::agent::document::DocumentTraits;

// Verify document signature with agent's public key
agent.verify_document_signature(
    "doc-id:version-id",
    None,  // signature key (uses default)
    None,  // fields to verify
    None,  // public key (uses agent's)
    None,  // key encoding type
)?;

// Verify using external public key
agent.verify_external_document_signature("doc-id:version-id")?;
```

### Saving Documents

```rust
use jacs::agent::document::DocumentTraits;

// Save document to filesystem
agent.save_document(
    "doc-id:version-id",
    Some("output.json".to_string()),  // output filename
    Some(true),                       // export embedded files
    None,                             // extract only
)?;
```

## Creating Tasks

```rust
use jacs::{get_empty_agent, create_task};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut agent = get_empty_agent();
    agent.load_by_config("./jacs.config.json".to_string())?;

    // Create a task
    let task_json = create_task(
        &mut agent,
        "Review Code".to_string(),
        "Review pull request #123".to_string(),
    )?;

    println!("Task created: {}", task_json);

    Ok(())
}
```

## Signing and Verification

### Signing Documents

The agent's `signing_procedure` method creates cryptographic signatures:

```rust
use serde_json::json;

let document = json!({
    "title": "Contract",
    "terms": "..."
});

// Sign the document
let signature = agent.signing_procedure(
    &document,
    None,           // fields to sign (None = all)
    "jacsSignature" // placement key
)?;
```

### Verification

```rust
// Verify self-signature (agent document)
agent.verify_self_signature()?;

// Verify hash integrity
agent.verify_hash(&document)?;

// Full signature verification
agent.signature_verification_procedure(
    &document,
    None,                    // fields
    "jacsSignature",         // signature key
    public_key,              // public key bytes
    Some("ring-Ed25519".to_string()),  // algorithm
    None,                    // original public key hash
    None,                    // signature override
)?;
```

## Custom Schema Validation

```rust
// Load custom schemas
agent.load_custom_schemas(&[
    "./schemas/invoice.schema.json".to_string(),
    "https://example.com/schemas/contract.schema.json".to_string(),
])?;

// Validate document against custom schema
agent.validate_document_with_custom_schema(
    "./schemas/invoice.schema.json",
    &document_value,
)?;
```

## Configuration

### Loading Configuration

```rust
use jacs::config::{load_config, find_config, Config};

// Load from specific path
let config = load_config("./jacs.config.json")?;

// Find config in directory
let config = find_config("./".to_string())?;

// Create programmatically
let config = Config::new(
    Some("false".to_string()),           // use_security
    Some("./jacs_data".to_string()),     // data_directory
    Some("./jacs_keys".to_string()),     // key_directory
    Some("private_key.pem".to_string()), // private key filename
    Some("public_key.pem".to_string()),  // public key filename
    Some("ring-Ed25519".to_string()),    // key algorithm
    Some("password".to_string()),        // private key password
    None,                                // agent ID and version
    Some("fs".to_string()),              // storage type
);
```

### Accessing Configuration

```rust
// Get key algorithm
let algorithm = config.get_key_algorithm()?;

// Access config fields
let data_dir = config.jacs_data_directory();
let key_dir = config.jacs_key_directory();
let storage_type = config.jacs_default_storage();
```

## Observability

### Initialize Default Observability

```rust
use jacs::init_default_observability;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up file-based logging
    init_default_observability()?;

    // Your application code...

    Ok(())
}
```

### Custom Observability Configuration

```rust
use jacs::{
    init_custom_observability,
    ObservabilityConfig,
    LogConfig,
    LogDestination,
    MetricsConfig,
    MetricsDestination,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "debug".to_string(),
            destination: LogDestination::Otlp {
                endpoint: "http://localhost:4317".to_string(),
                headers: None,
            },
            headers: None,
        },
        metrics: MetricsConfig {
            enabled: true,
            destination: MetricsDestination::Prometheus {
                endpoint: "http://localhost:9090".to_string(),
                headers: None,
            },
            export_interval_seconds: Some(30),
            headers: None,
        },
        tracing: None,
    };

    init_custom_observability(config)?;

    Ok(())
}
```

## Storage Backends

JACS supports multiple storage backends:

```rust
use jacs::storage::MultiStorage;

// Filesystem storage (default)
let storage = MultiStorage::new("fs".to_string())?;

// In-memory storage
let storage = MultiStorage::new("memory".to_string())?;

// S3 storage
let storage = MultiStorage::new("s3".to_string())?;
```

## Error Handling

JACS functions return `Result<T, Box<dyn Error>>`:

```rust
use jacs::get_empty_agent;

fn main() {
    match get_empty_agent().load_by_config("./jacs.config.json".to_string()) {
        Ok(()) => println!("Agent loaded successfully"),
        Err(e) => eprintln!("Failed to load agent: {}", e),
    }
}
```

## Thread Safety

The `Agent` struct uses internal mutexes for thread-safe access to:
- Document schemas (`Arc<Mutex<HashMap<String, Validator>>>`)
- Storage operations

For concurrent usage:

```rust
use std::sync::{Arc, Mutex};
use jacs::get_empty_agent;

let agent = Arc::new(Mutex::new(get_empty_agent()));

// Clone Arc for threads
let agent_clone = Arc::clone(&agent);
std::thread::spawn(move || {
    let mut agent = agent_clone.lock().unwrap();
    // Use agent...
});
```

## Complete Example

```rust
use jacs::{get_empty_agent, create_task};
use jacs::agent::document::DocumentTraits;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize agent
    let mut agent = get_empty_agent();
    agent.load_by_config("./jacs.config.json".to_string())?;

    // Create a document
    let doc_json = json!({
        "title": "Project Proposal",
        "description": "Q1 development plan",
        "budget": 50000
    });

    let doc = agent.create_document_and_load(
        &doc_json.to_string(),
        None,
        None
    )?;

    println!("Created document: {}", doc.getkey());

    // Verify the document
    agent.verify_document_signature(&doc.getkey(), None, None, None, None)?;
    println!("Document verified successfully");

    // Save to file
    agent.save_document(&doc.getkey(), Some("proposal.json".to_string()), None, None)?;

    // Create a task
    let task = create_task(
        &mut agent,
        "Review Proposal".to_string(),
        "Review and approve the project proposal".to_string(),
    )?;

    println!("Task created");

    Ok(())
}
```

## Next Steps

- [Observability](observability.md) - Logging and metrics setup
- [Storage Backends](../advanced/storage.md) - Configure different storage
- [Custom Schemas](../advanced/custom-schemas.md) - Define custom document types
