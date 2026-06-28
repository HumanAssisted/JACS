# Task 002 - Role-Based Keyring and Init Behavior

**Depends on:** 001  
**Unlocks:** 003, 004  
**Reversible:** one commit; remove role metadata and compatibility key creation

## Objective

Update init/create paths so every new JACS agent has:

- `native_root`: a `pq2025` key for native JACS signing
- `ecosystem_signing`: an ES256 key for ecosystem compatibility exports

Store both private keys with the existing JACS encrypted-at-rest key storage path. Do not use the PQ signing library as encryption.

## TDD: Tests First (Red)

Add tests before implementation:

- `jacs/tests/compatibility_keyring.rs`
  - `init_creates_pq_root_and_es256_compatibility_key`
  - `compatibility_private_key_uses_existing_envelope`
  - `compatibility_key_file_permissions_are_private`
  - `keyring_records_roles_not_primary_algorithms`
  - `missing_compatibility_key_is_reported_as_typed_error`
- `binding-core/tests/contract.rs`
  - `create_with_params_returns_pq_root_and_compatibility_key_metadata`
- `jacs-cli/tests/cli_flags.rs`
  - `init_outputs_pq_root_and_es256_compatibility_summary`

Tests should inspect metadata and stored files without printing private key bytes.

## Implementation Notes

Use existing storage infrastructure:

- `jacs-core/src/envelope.rs`
  - reuse V2 AES-256-GCM + Argon2id envelope behavior
- `jacs/src/keystore/mod.rs`
  - reuse secure private key write and permission handling
  - add role-aware path helpers if needed
- `jacs/src/config/mod.rs`
  - represent compatibility key metadata without overloading `jacs_agent_key_algorithm`
- `jacs/src/simple/core.rs`
  - ensure simple/create paths call the new role-aware initialization
- `binding-core/src/lib.rs`
  - return role metadata in creation result JSON
- `jacs-cli/src/main.rs`
  - ensure `jacs init` creates or reports both roles

Suggested metadata shape:

```json
{
  "keys": [
    {"role": "native_root", "algorithm": "pq2025", "kid": "..."},
    {"role": "ecosystem_signing", "algorithm": "ES256", "kid": "..."}
  ]
}
```

The exact file layout may follow current key naming conventions, but roles must be explicit.

## TDD: Tests Pass (Green)

Run:

```bash
cargo test -p jacs --test compatibility_keyring -- --nocapture
cargo test -p jacs-binding-core --test contract -- --nocapture compatibility
cargo test -p jacs-cli --test cli_flags -- --nocapture init
```

Expected result:

- a fresh agent has both required key roles
- private key files are encrypted and permissioned
- missing compatibility key failures are typed and clear

## Acceptance Criteria

- `jacs init` and SDK/MCP equivalent creation paths produce the same role model.
- ES256 private key storage uses the existing envelope and filesystem hardening.
- PQ signing code is not used as encryption.
- Existing one-key agents load predictably and report missing compatibility key on export.

