# Golden Fixtures for Cross-Language Testing

This directory contains pre-signed JACS documents for testing signature
verification across different language bindings (Rust, Python, Go, NPM).

## Fixtures

### Valid Documents

- `message_signed.json` - A simple signed message document
- `file_embedded.json` - A signed document with an embedded file attachment

### Invalid Documents (for testing error handling)

- `invalid_signature.json` - Document with a corrupted signature
- `invalid_hash.json` - Document with mismatched content hash

## Usage

These fixtures should be loadable and verifiable by all JACS bindings:

```rust
// Rust
let result = jacs::simple::verify(&std::fs::read_to_string("message_signed.json")?)?;
assert!(result.valid);
```

```python
# Python
import jacs.simple as jacs
result = jacs.verify(open("message_signed.json").read())
assert result.valid
```

```go
// Go
result, _ := jacs.Verify(string(data))
assert(result.Valid)
```

## Regenerating Fixtures

To regenerate these fixtures with a new agent:

```bash
cd /path/to/jacs
cargo run --features cli -- create
cargo test generate_golden_fixtures -- --ignored
```

Note: The fixtures include the agent's public key hash for verification.
When regenerating, all tests using these fixtures will need to use the
new agent for verification.
