# PASSWORD_SECURITY_PLAN

Last updated: 2026-02-19

## Problem Statement

Today JACS has exactly two paths for supplying the private key decryption password:

1. **`CreateAgentParams.password`** — programmatic, only available to Rust callers and binding wrappers
2. **`JACS_PRIVATE_KEY_PASSWORD` env var** — the universal fallback, used by `quickstart()`, CLI, `encrypt_private_key()`, and `decrypt_private_key()`

Both paths end up as a plaintext string in process memory (unavoidable for any software-based decryption). The concern is how the password gets *into* the process.

### Why the env var is problematic

Environment variables are better than config files, but they are not secrets:

- **Visible in `/proc/<pid>/environ`** on Linux (readable by same-uid processes).
- **Visible in `ps eww`** output on macOS/Linux if the process was launched with the var inline (`JACS_PRIVATE_KEY_PASSWORD=x jacs sign ...`).
- **Logged by default** in many CI systems, shell history (`export` commands), Docker inspect, Kubernetes pod describe (plain `env:` entries, as opposed to `secretKeyRef`).
- **Inherited by child processes** — any subprocess spawned by a JACS-using process inherits the password.
- **Persisted in shell rc files** — developers frequently add `export JACS_PRIVATE_KEY_PASSWORD=...` to `.bashrc` / `.zshrc`, creating a plaintext-on-disk problem identical to the old config-file password.

### History: plaintext password in config

JACS previously allowed `jacs_private_key_password` in `jacs.config.json`. This was deprecated and is now:
- Marked `deprecated: true` in the JSON schema
- Deserialized but immediately discarded (`skip_serializing`, set to `None`)
- Triggers a `SECURITY WARNING` log if detected in a config file
- Never written by any code path (`Config::new()` and `ConfigBuilder` always set it to `None`)

The quickstart bindings (Node, Python) also had auto-generated password persistence to `./jacs_keys/.jacs_password`, which is now gated behind `JACS_SAVE_PASSWORD_FILE=true` (opt-in only, off by default).

### What SECURITY_PLAN.md says

`SECURITY_PLAN.md` P0 #3 requires: "Require encrypted private-key defaults in quickstart/onboarding paths" and "Ensure guidance and examples never suggest plaintext private key storage." Exit Criteria #3: "New agent creation defaults to encrypted private-key storage." This plan addresses the *supply side* — how the password reaches the decryption code securely.

---

## Cross-Cutting Concern: Surface Area

Every password source option in this plan affects **all layers** of the JACS ecosystem. This is not just a Rust-core change. Each phase must be implemented across:

| Layer | Repository / Path | What changes |
|-------|------------------|--------------|
| **Rust core** | `jacs/src/crypt/`, `jacs/src/simple.rs`, `jacs/src/config/` | `resolve_password()`, `PasswordSource` trait, config schema |
| **Rust CLI** | `jacs/src/bin/cli.rs` | `--password-file`, `--password-source`, `jacs keychain` subcommands |
| **binding-core** | `binding-core/` | Shared binding logic that wraps `SimpleAgent` |
| **Python bindings** | `jacspy/` | `JacsAgent`, `JacsClient`, `simple.py`, `async_simple.py`, `client.py` |
| **Node.js bindings** | `jacsnpm/` | `simple.ts`, `client.ts`, NAPI wrapper, TypeScript types |
| **Go bindings** | `jacsgo/` | CGo FFI, `simple.go` |
| **MCP server** | `jacs-mcp/` | Tool definitions that create/load agents |
| **HAI SDK** | `haisdk` repo (github.com/HumanAssisted/haisdk) | Python (`haisdk`), Node (`@hai.ai/sdk`), Go (`haisdk-go`) clients that depend on JACS |
| **Framework adapters** | `jacspy/python/jacs/adapters/` | `BaseJacsAdapter`, LangChain, FastAPI, CrewAI, Anthropic adapters |
| **Documentation** | `jacsbook/`, READMEs, `SECURITY.md` | Guides, deployment docs, API references |
| **Examples** | `examples/`, binding-specific examples | Quickstarts, multi-agent demos |

**haisdk impact:** The HAI SDK wraps JACS client libraries. When JACS adds `password_file`, `keychain`, or `secrets_manager` params to `quickstart()` / `create()` / `JacsClient`, the HAI SDK must expose those same options in its own initialization and agent registration flows. The HAI SDK's Python, Node.js, and Go clients each need updated constructors, documentation, and examples.

---

## The Five Options

### Option 1: TTY Prompt (interactive terminal)

**How it works:** When running interactively (stdin is a TTY), prompt the user for the password with no echo. The password goes directly from the keyboard into process memory. It never touches the filesystem, environment, or process table.

**Rust implementation:** `rpassword` crate — `rpassword::prompt_password("Enter JACS key password: ")`.

**Security properties:**
- Password never on disk, never in env, never in `ps` output
- Not susceptible to shoulder-surfing (no echo)
- Cannot be used in non-interactive contexts (CI, containers, daemons, library calls)
- Process memory still holds the plaintext (unavoidable)

**When to use:** Local development, CLI usage, key generation, `reencrypt_key`.

**Limitations:** Cannot work for servers, CI, or any headless/automated context. Must detect TTY and fall through to next option if not interactive.

**Dependencies:** `rpassword` (pure Rust, no C deps, well-maintained)

---

### Option 2: File Descriptor / Password File

**How it works:** Accept the password via a file path (config field, CLI flag, or env var pointing to a file). The file is read once at startup, the contents are used as the password, and the file handle is closed.

**Proposed interface:**
- CLI: `--password-file /path/to/file` or `--password-fd 3`
- Config: `"jacs_password_file": "/run/secrets/jacs-password"`
- Env: `JACS_PASSWORD_FILE=/run/secrets/jacs-password`

**Security analysis — is `--password-file` secure?**

This is an important question given the history of plaintext passwords in the config file. The answer: **it depends entirely on what protects the file.**

| Scenario | Secure? | Why |
|----------|---------|-----|
| Kubernetes Secret volume mount (`/run/secrets/...`) | Yes | tmpfs, never hits disk, namespace-isolated, RBAC-controlled |
| Docker secret (`/run/secrets/...`) | Yes | tmpfs, swarm-encrypted, removed when container stops |
| `~/.jacs_password` with `chmod 600` | Marginal | Better than env var in `.bashrc`, but still plaintext on disk. Equivalent to SSH passphrase caching. |
| `./jacs_keys/.jacs_password` (old quickstart behavior) | No | Plaintext in project directory, likely committed to git. This is what we already deprecated. |
| Named pipe / process substitution (`--password-file <(vault read ...)`) | Yes | Password exists only in kernel pipe buffer, never on disk |
| `/dev/stdin` piped from a secret manager | Yes | Transient, never on disk |

**The key distinction:** A password *file* is secure when the file is:
1. On a tmpfs / in-memory filesystem (Kubernetes Secrets, Docker secrets)
2. A named pipe or process substitution (never persists)
3. Created with restrictive permissions (0400/0600) and the disk is encrypted

A password file is **not** secure when it's a regular file in a project directory, home directory, or anywhere that might be backed up, committed, or readable by other users.

**Safeguards:**
- **Validate file permissions** on Unix: warn (or error in strict mode) if the file is group/world-readable
- **Never create password files by default** (the `JACS_SAVE_PASSWORD_FILE` gate stays)
- **Document clearly** that this is intended for Kubernetes/Docker secret mounts and process substitution, not for storing passwords in project directories

**Dependencies:** None (just `std::fs::read_to_string` + permission check)

---

### Option 3: OS Keychain / Credential Store

**How it works:** Store and retrieve the password using the OS-native secure credential store:
- macOS: Keychain (`security` CLI or Keychain Services API)
- Linux: libsecret (GNOME Keyring) / KWallet / kernel keyring
- Windows: Credential Manager (DPAPI-backed)

**Rust implementation:** `keyring` crate — provides a unified API across all three platforms.

```rust
let entry = keyring::Entry::new("jacs", &agent_id)?;
// Store
entry.set_password(&password)?;
// Retrieve
let password = entry.get_password()?;
```

**Security properties:**
- Password encrypted at rest by the OS (Keychain uses AES-256, DPAPI uses user's login key)
- On macOS: protected by the login keychain, optionally requires biometric/password confirmation
- On Linux: protected by the user's session keyring (unlocked at login)
- On Windows: encrypted with DPAPI, tied to the user account
- No plaintext on disk, no env var needed

**When to use:** Desktop/laptop development. The developer sets the password once (via TTY prompt on first use), and subsequent runs retrieve it silently.

**Limitations:**
- Requires a desktop session / login keyring on Linux (won't work in headless containers)
- Cross-platform behavior is inconsistent (Linux keyring support varies by distro)
- Adds a native dependency (`libsecret-1-dev` on Linux)
- Not suitable for servers or CI — graceful fallback required

**Dependencies:** `keyring` crate (has native deps on Linux)

---

### Option 4: External Secrets Manager SDK

**How it works:** At agent load time, call out to an external secrets manager to retrieve the password. The config specifies *where* the secret lives, not the secret itself.

**Proposed config:**
```json
{
  "jacs_password_source": {
    "type": "aws-secretsmanager",
    "secret_id": "prod/jacs/agent-key-password"
  }
}
```

Or:
```json
{
  "jacs_password_source": {
    "type": "vault",
    "path": "secret/data/jacs/agent-key",
    "field": "password"
  }
}
```

Or:
```json
{
  "jacs_password_source": {
    "type": "gcp-secretmanager",
    "project": "my-project",
    "secret_id": "jacs-agent-key-password",
    "version": "latest"
  }
}
```

**Security properties:**
- Password never on disk or in env
- Access controlled by IAM / Vault policies
- Audit trail of every access
- Secret rotation without redeploying the application

**When to use:** Production cloud deployments where direct SDK integration is preferred over the sidecar/file pattern.

**Note:** The `--password-file` option (Option 2) already covers many production use cases when combined with a sidecar/init-container that fetches the secret and writes it to a tmpfs mount. Direct SDK integration provides a tighter, single-process alternative without the sidecar indirection.

**Dependencies:** AWS SDK / hashicorp_vault / gcloud crates (heavy, behind feature flags)

---

### Option 5: PKCS#11 / HSM / Cloud KMS Delegation

**How it works:** Instead of decrypting the private key in-process, delegate all signing operations to a hardware security module or cloud KMS. The private key *never leaves the HSM*. There is no password to supply because the key material is not extractable.

**Examples:**
- AWS CloudHSM / KMS
- Google Cloud HSM
- Azure Key Vault (HSM-backed)
- YubiKey via PKCS#11
- Local PKCS#11 tokens (SoftHSM for testing)

**Security properties:**
- Strongest possible: private key is non-extractable
- Signing happens in tamper-resistant hardware
- Audit trail built into the HSM/KMS
- No password, no key file, no key material in process memory

**When to use:** High-security production deployments, regulated environments, FIPS requirements.

**Limitations:**
- Fundamentally different architecture: the `Agent` signing path needs a `CryptoBackend` trait that dispatches to either local crypto or an external HSM
- Every supported algorithm needs an HSM counterpart (Ed25519 is widely supported; ML-DSA-87/pq2025 is not yet available in most HSMs)
- Latency: every sign/verify goes over a network call (KMS) or USB (YubiKey)
- Cost: cloud HSM services are expensive
- Major refactor of `crypt/` module

**Dependencies:** `pkcs11` crate, cloud SDKs, significant refactoring of crypto abstraction layer

---

## Implementation Plan

### Phase A: TTY Prompt + Password File

**Goal:** A developer can use JACS without ever setting an env var or creating a password file. Containers and CI can use secure file-based password supply.

#### A.1: Add `rpassword` dependency and TTY prompt utility

**File:** new `jacs/src/crypt/password.rs`

Add a helper:
```rust
/// Prompt for password on TTY if available.
/// Returns None if stdin is not a terminal.
pub fn prompt_password_tty(prompt: &str) -> Option<String> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).ok()
    } else {
        None
    }
}
```

**Crate deps:** `rpassword` (use `std::io::IsTerminal` from Rust 1.70+ instead of `atty`).

#### A.2: Add password-file reading utility

**File:** `jacs/src/crypt/password.rs`

```rust
/// Read password from a file, validating permissions.
/// Returns the password string (trimmed of trailing newline).
/// In strict mode, errors if the file is group/world-readable on Unix.
pub fn read_password_file(path: &Path, strict: bool) -> Result<String, JacsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            let msg = format!(
                "Password file {} has insecure permissions {:o}. \
                 Expected 0400 or 0600 (owner-only read).",
                path.display(), mode & 0o777
            );
            if strict {
                return Err(JacsError::ConfigError(msg));
            } else {
                warn!("{}", msg);
            }
        }
    }
    let contents = std::fs::read_to_string(path)?;
    Ok(contents.trim_end_matches('\n').trim_end_matches('\r').to_string())
}
```

#### A.3: Unified password resolution function

**File:** `jacs/src/crypt/password.rs`

Replace the scattered `env::var("JACS_PRIVATE_KEY_PASSWORD")` calls with a single resolution function:

```rust
/// Resolve the private key password using the following precedence:
/// 1. Explicit password (from CreateAgentParams or function argument)
/// 2. Password file (JACS_PASSWORD_FILE env var or config field)
/// 3. TTY prompt (if stdin is a terminal)
/// 4. Environment variable (JACS_PRIVATE_KEY_PASSWORD)
/// 5. Error with guidance
pub fn resolve_password(explicit: Option<&str>, for_encryption: bool) -> Result<String, JacsError> {
    // 1. Explicit password
    if let Some(pw) = explicit.filter(|p| !p.is_empty()) {
        return Ok(pw.to_string());
    }

    // 2. Password file
    if let Ok(path) = std::env::var("JACS_PASSWORD_FILE") {
        let pw = read_password_file(Path::new(&path), /* strict= */ true)?;
        if !pw.is_empty() {
            return Ok(pw);
        }
    }

    // 3. TTY prompt
    let prompt = if for_encryption {
        "Enter new JACS key password: "
    } else {
        "Enter JACS key password: "
    };
    if let Some(pw) = prompt_password_tty(prompt) {
        if !pw.is_empty() {
            // For encryption, confirm the password
            if for_encryption {
                if let Some(confirm) = prompt_password_tty("Confirm password: ") {
                    if pw != confirm {
                        return Err(JacsError::ConfigError(
                            "Passwords do not match.".to_string()
                        ));
                    }
                }
            }
            return Ok(pw);
        }
    }

    // 4. Environment variable (existing behavior)
    if let Ok(pw) = std::env::var("JACS_PRIVATE_KEY_PASSWORD") {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }

    // 5. Error
    Err(JacsError::ConfigError(
        "No password available. Supply it via one of:\n\
         - JACS_PASSWORD_FILE env var pointing to a secure file\n\
         - Interactive TTY prompt (run in a terminal)\n\
         - JACS_PRIVATE_KEY_PASSWORD env var\n\
         - CreateAgentParams.password (programmatic API)"
            .to_string(),
    ))
}
```

#### A.4: Wire into existing Rust call sites

Update these locations to use `resolve_password()`:

| File | Current code | Change |
|------|-------------|--------|
| `simple.rs:744` | `params.password` then `env::var` | Call `resolve_password(Some(&params.password), true)` |
| `simple.rs:1257` | `env::var("JACS_PRIVATE_KEY_PASSWORD")` | Call `resolve_password(None, false)` |
| `aes_encrypt.rs:320` | `get_required_env_var("JACS_PRIVATE_KEY_PASSWORD")` | Call `resolve_password(None, true)` |
| `aes_encrypt.rs:414` | `get_required_env_var("JACS_PRIVATE_KEY_PASSWORD")` | Call `resolve_password(None, false)` |
| `cli.rs` (quickstart/create) | Delegates to simple.rs | No change needed if simple.rs is updated |

#### A.5: CLI `--password-file` flag

Add `--password-file <PATH>` to relevant CLI subcommands (`quickstart`, `create`, `sign`, `verify`). When provided, set `JACS_PASSWORD_FILE` env var before calling into core, so the resolution function picks it up.

#### A.6: Config schema update

Add to `jacs.config.schema.json`:
```json
"jacs_password_file": {
  "description": "Path to a file containing the private key password. The file should have 0400 or 0600 permissions. Intended for Kubernetes Secret volume mounts, Docker secrets, or process substitution. Do NOT point this at a plaintext file in your project directory.",
  "type": "string"
}
```

#### A.7: Update bindings (all languages)

| Binding | Changes |
|---------|---------|
| **binding-core** | Expose `password_file` param on shared agent creation functions |
| **Python (`jacspy`)** | Add `password_file` param to `JacsAgent.__init__()`, `JacsClient.quickstart()`, `JacsClient.create()`, `simple.quickstart()`, `async_simple.quickstart()`. Sets `JACS_PASSWORD_FILE` before calling Rust. |
| **Node.js (`jacsnpm`)** | Add `passwordFile` option to `JacsClient.quickstart()`, `JacsClient.create()`, `quickstart()` in `simple.ts`. Sets `JACS_PASSWORD_FILE` before calling NAPI. |
| **Go (`jacsgo`)** | Add `PasswordFile` field to Go config struct. Sets `JACS_PASSWORD_FILE` env var before calling CGo FFI. No new C exports needed. |
| **MCP server (`jacs-mcp`)** | Accept `password_file` param on `jacs_create_agent` tool. Set env var before agent creation. |
| **Framework adapters** | `BaseJacsAdapter` accepts `password_file` and passes through to `JacsClient`. All adapters (LangChain, FastAPI, CrewAI, Anthropic) inherit it. |
| **HAI SDK (`haisdk`)** | Python `haisdk`, Node `@hai.ai/sdk`, Go `haisdk-go` all wrap JACS client libraries. Each must expose `password_file` on their agent initialization/registration flows and pass it through to the underlying JACS client. |

#### A.8: Tests

- Unit test `resolve_password` precedence (mock TTY with `rpassword` test helpers or skip TTY in CI)
- Test `read_password_file` with correct permissions (0600), wrong permissions (0644), missing file
- Integration test: create agent with `JACS_PASSWORD_FILE` instead of `JACS_PRIVATE_KEY_PASSWORD`
- Integration test: password-file with trailing newline is handled correctly
- Test that password-file takes precedence over env var
- Binding tests: Python, Node, Go each test `password_file` param
- haisdk: integration tests for password-file flow in each language

#### A.9: Documentation

- Update `SECURITY.md` to list the full resolution order
- Update `jacsbook/src/getting-started/quick-start.md` with TTY prompt flow
- Update `jacsbook/src/getting-started/deployment.md` with Kubernetes Secret mount example
- Add warning box: "Never store passwords in plaintext files in your project directory"
- Update `jacspy/README.md`, `jacsnpm/README.md`, `jacsgo/README.md` with `password_file` examples
- Update haisdk docs in all three languages

---

### Phase B: OS Keychain Integration

**Goal:** "Set once, forget" password management for desktop developers.

#### B.1: Feature-gated `keyring` dependency

Add to `jacs/Cargo.toml`:
```toml
[features]
default = ["keychain"]
keychain = ["dep:keyring"]

[dependencies]
keyring = { version = "3", optional = true }
```

Keychain is enabled by default for desktop builds. Users building for headless/container targets can disable it with `--no-default-features`.

#### B.2: Keychain store/retrieve functions

**File:** `jacs/src/crypt/password.rs`

```rust
#[cfg(feature = "keychain")]
pub fn store_password_keychain(service: &str, agent_id: &str, password: &str) -> Result<(), JacsError> {
    let entry = keyring::Entry::new(service, agent_id)
        .map_err(|e| JacsError::ConfigError(format!("Keychain error: {}", e)))?;
    entry.set_password(password)
        .map_err(|e| JacsError::ConfigError(format!("Keychain store failed: {}", e)))?;
    Ok(())
}

#[cfg(feature = "keychain")]
pub fn retrieve_password_keychain(service: &str, agent_id: &str) -> Option<String> {
    let entry = keyring::Entry::new(service, agent_id).ok()?;
    entry.get_password().ok()
}

#[cfg(feature = "keychain")]
pub fn delete_password_keychain(service: &str, agent_id: &str) -> Result<(), JacsError> {
    let entry = keyring::Entry::new(service, agent_id)
        .map_err(|e| JacsError::ConfigError(format!("Keychain error: {}", e)))?;
    entry.delete_credential()
        .map_err(|e| JacsError::ConfigError(format!("Keychain delete failed: {}", e)))?;
    Ok(())
}
```

#### B.3: Insert into resolution order

The full resolution order becomes:
```
1. Explicit password           (CreateAgentParams.password / API param)
2. Password file               (JACS_PASSWORD_FILE)
3. OS keychain                 (if keychain feature enabled and agent_id known)
4. TTY prompt                  (if stdin is a terminal)
5. Environment variable        (JACS_PRIVATE_KEY_PASSWORD)
6. Error with guidance
```

Note: keychain comes *before* TTY prompt. If the developer already stored their password in the keychain, they should not be prompted again. TTY prompt is the fallback for when no stored credential exists.

#### B.4: CLI integration

- `jacs keychain store [--agent-id <ID>]` — prompts for password via TTY, stores in OS keychain
- `jacs keychain clear [--agent-id <ID>]` — removes stored password from keychain
- `jacs keychain status` — reports whether a stored credential exists (without revealing it)
- `jacs quickstart` — after creating agent, offer to store password in keychain (if TTY + keychain feature)
- `jacs create` — same offer after agent creation

#### B.5: Update bindings (all languages)

| Binding | Changes |
|---------|---------|
| **Python (`jacspy`)** | Add `use_keychain=True` param to `JacsClient` and `simple.quickstart()`. When set, stores password after creation and retrieves on load. |
| **Node.js (`jacsnpm`)** | Add `useKeychain: true` option. Same store/retrieve pattern. |
| **Go (`jacsgo`)** | Add `UseKeychain bool` config field. Calls Rust keychain functions via CGo. |
| **MCP server** | No change needed — MCP runs headless, keychain would not apply. Document this. |
| **HAI SDK (`haisdk`)** | All three language clients expose `use_keychain` option, pass through to underlying JACS client. |

#### B.6: Platform testing

- macOS: test with Keychain Access (should work out of the box)
- Linux: test with `gnome-keyring-daemon` (may require `dbus` in CI — use `KEYRING_BACKEND` env override or mock)
- Windows: test with Credential Manager
- Headless Linux (no keyring): verify graceful fallback (returns `None`, does not error), proceeds to TTY/env var
- CI: verify `--no-default-features` builds without `keyring` dep

#### B.7: Documentation

- `jacsbook/src/getting-started/quick-start.md`: document keychain flow for local dev
- `jacsbook/src/advanced/security.md`: document keychain security properties per platform
- All binding READMEs: `use_keychain` examples
- haisdk docs: keychain option

---

### Phase C: External Secrets Manager SDK

**Goal:** Production deployments can fetch the password directly from a secrets manager without sidecar/init-container indirection.

**Note:** The password-file approach (Phase A) already covers most production use cases via sidecar pattern. Phase C provides a tighter single-process alternative for teams that prefer direct SDK integration.

#### C.1: `PasswordSource` trait and config model

**File:** new `jacs/src/crypt/secrets.rs`

```rust
/// Trait for pluggable password sources.
#[async_trait]
pub trait PasswordSource: Send + Sync {
    /// Retrieve the password from this source.
    async fn get_password(&self) -> Result<String, JacsError>;

    /// Human-readable name for error messages.
    fn source_name(&self) -> &str;
}
```

**Config model** (added to `jacs.config.schema.json`):
```json
"jacs_password_source": {
  "description": "External secrets manager configuration for password retrieval.",
  "type": "object",
  "properties": {
    "type": {
      "type": "string",
      "enum": ["aws-secretsmanager", "vault", "gcp-secretmanager", "azure-keyvault"]
    },
    "secret_id": { "type": "string" },
    "field": { "type": "string", "default": "password" },
    "region": { "type": "string" },
    "vault_addr": { "type": "string" },
    "vault_path": { "type": "string" },
    "project": { "type": "string" },
    "version": { "type": "string", "default": "latest" }
  },
  "required": ["type", "secret_id"]
}
```

#### C.2: Feature-gated provider implementations

Each secrets manager is behind its own feature flag to avoid bloating core:

```toml
# jacs/Cargo.toml
[features]
secrets-aws = ["dep:aws-sdk-secretsmanager", "dep:aws-config"]
secrets-vault = ["dep:vaultrs"]
secrets-gcp = ["dep:google-cloud-secretmanager"]
secrets-azure = ["dep:azure_security_keyvault_secrets"]
secrets-all = ["secrets-aws", "secrets-vault", "secrets-gcp", "secrets-azure"]
```

**Implementations** (each in its own file under `jacs/src/crypt/secrets/`):

| Provider | Crate | File |
|----------|-------|------|
| AWS Secrets Manager | `aws-sdk-secretsmanager` + `aws-config` | `secrets/aws.rs` |
| HashiCorp Vault | `vaultrs` | `secrets/vault.rs` |
| GCP Secret Manager | `google-cloud-secretmanager` | `secrets/gcp.rs` |
| Azure Key Vault | `azure_security_keyvault_secrets` | `secrets/azure.rs` |

Each implementation:
- Reads provider-specific config from `jacs_password_source`
- Uses the provider's standard credential chain (IAM roles, service accounts, managed identity)
- Caches the password for the lifetime of the `Agent` (no repeated fetches per sign operation)
- Logs the source name (not the password) for diagnostics

#### C.3: Insert into resolution order

```
1. Explicit password           (CreateAgentParams.password / API param)
2. Password file               (JACS_PASSWORD_FILE)
3. External secrets manager    (jacs_password_source config)
4. OS keychain                 (if keychain feature enabled)
5. TTY prompt                  (if stdin is a terminal)
6. Environment variable        (JACS_PRIVATE_KEY_PASSWORD)
7. Error with guidance
```

The secrets manager sits between file and keychain. It's config-driven (requires explicit opt-in via `jacs_password_source`), so it won't fire unless configured.

#### C.4: Update bindings (all languages)

| Binding | Changes |
|---------|---------|
| **Python (`jacspy`)** | `JacsClient` accepts `password_source={"type": "aws-secretsmanager", ...}` dict. Passed through to Rust config. |
| **Node.js (`jacsnpm`)** | `JacsClient` accepts `passwordSource: { type: "vault", ... }` object. |
| **Go (`jacsgo`)** | `PasswordSource` config struct field. |
| **MCP server** | Accept `password_source` in `jacs_create_agent` tool config. |
| **HAI SDK (`haisdk`)** | All three language clients expose `password_source` config, pass through to JACS. |

#### C.5: Tests

- Mock-based unit tests for each provider (mock the SDK client, verify correct API calls)
- Integration test with LocalStack (AWS) or Vault dev server
- Test that secrets manager takes precedence over keychain/env but not over explicit password or file
- Test graceful error when feature flag is not enabled but config references a provider
- Binding tests in Python and Node

#### C.6: Documentation

- `jacsbook/src/getting-started/deployment.md`: examples for each cloud provider
- `jacsbook/src/advanced/security.md`: secrets manager security model
- Per-provider setup guides (IAM policy examples, Vault policy, GCP IAM binding)
- All binding READMEs: `password_source` config examples
- haisdk docs: secrets manager integration

---

### Phase D: PKCS#11 / HSM / Cloud KMS Delegation

**Goal:** High-security deployments can keep private keys in hardware. The private key never enters JACS process memory. Signing is delegated to the HSM/KMS.

This is an architectural change, not just a password management change. It eliminates the need for a password entirely by moving the private key outside the software boundary.

#### D.1: `CryptoBackend` trait

**File:** new `jacs/src/crypt/backend.rs`

```rust
/// Abstraction over signing/verification backends.
/// Allows the Agent to use either local key material or an external HSM/KMS.
#[async_trait]
pub trait CryptoBackend: Send + Sync {
    /// Sign a message. Returns the signature bytes.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JacsError>;

    /// Verify a signature against a message and public key.
    async fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, JacsError>;

    /// Return the public key bytes (for embedding in documents).
    fn public_key(&self) -> &[u8];

    /// Return the algorithm identifier string (e.g., "ring-Ed25519", "pq2025", "aws-kms-ecdsa").
    fn algorithm(&self) -> &str;

    /// Human-readable backend name for diagnostics.
    fn backend_name(&self) -> &str;
}
```

#### D.2: `LocalCryptoBackend` — wrap existing code

Refactor current `crypt/` signing code into a `LocalCryptoBackend` that implements the trait. This is a no-op for existing users — the behavior is identical, just behind a trait.

**Files affected:**
- `jacs/src/crypt/mod.rs` — extract sign/verify logic
- `jacs/src/crypt/aes_encrypt.rs` — key loading stays here
- `jacs/src/crypt/ed25519.rs`, `jacs/src/crypt/rsa.rs`, `jacs/src/crypt/pq2025.rs` — implement `CryptoBackend`

#### D.3: `KmsCryptoBackend` implementations

Feature-gated, one per cloud:

```toml
[features]
kms-aws = ["dep:aws-sdk-kms"]
kms-gcp = ["dep:google-cloud-kms"]
kms-azure = ["dep:azure_security_keyvault_keys"]
hsm-pkcs11 = ["dep:cryptoki"]
```

| Backend | Crate | Supported algorithms |
|---------|-------|---------------------|
| AWS KMS | `aws-sdk-kms` | ECDSA (P-256, P-384), RSA-PSS |
| GCP Cloud KMS | `google-cloud-kms` | ECDSA (P-256, P-384), RSA-PSS |
| Azure Key Vault | `azure_security_keyvault_keys` | ECDSA, RSA |
| PKCS#11 (YubiKey, SoftHSM) | `cryptoki` | Ed25519 (YubiKey 5+), RSA, ECDSA |

**ML-DSA-87 / pq2025 note:** Post-quantum algorithms are not yet available in commercial HSMs. When PQ HSM support becomes available, add it as a new backend variant. Until then, PQ signing requires `LocalCryptoBackend`.

#### D.4: Config model

```json
{
  "jacs_crypto_backend": {
    "type": "aws-kms",
    "key_id": "arn:aws:kms:us-east-1:123456789:key/abcd-1234",
    "region": "us-east-1"
  }
}
```

Or:
```json
{
  "jacs_crypto_backend": {
    "type": "pkcs11",
    "module_path": "/usr/lib/softhsm/libsofthsm2.so",
    "slot": 0,
    "pin_env": "PKCS11_PIN",
    "key_label": "jacs-signing-key"
  }
}
```

When `jacs_crypto_backend` is not configured, the `Agent` uses `LocalCryptoBackend` (current behavior). No migration required.

#### D.5: Refactor `Agent` to use `CryptoBackend`

**File:** `jacs/src/agent/mod.rs`

Change `Agent` to hold:
```rust
pub struct Agent {
    // ... existing fields ...
    crypto_backend: Box<dyn CryptoBackend>,
}
```

All signing/verification call sites change from direct crypto calls to `self.crypto_backend.sign()` / `self.crypto_backend.verify()`.

**Key consideration:** `SimpleAgent` wraps `Agent` in a `Mutex`. The `CryptoBackend` trait is `Send + Sync`, so this is compatible. For async KMS backends, the signing path may need to become async or use `tokio::runtime::Handle::block_on()` inside the mutex lock.

#### D.6: Update bindings (all languages)

| Binding | Changes |
|---------|---------|
| **binding-core** | `SimpleAgent` creation accepts optional `crypto_backend` config |
| **Python (`jacspy`)** | `JacsClient` accepts `crypto_backend={"type": "aws-kms", ...}` |
| **Node.js (`jacsnpm`)** | `JacsClient` accepts `cryptoBackend: { type: "aws-kms", ... }` |
| **Go (`jacsgo`)** | `CryptoBackend` config struct field |
| **MCP server** | Accept `crypto_backend` in agent creation tools |
| **HAI SDK (`haisdk`)** | All three language clients expose `crypto_backend` config, pass through to JACS |

#### D.7: Tests

- Unit tests with SoftHSM (PKCS#11) — can run in CI with `softhsm2` installed
- Mock-based tests for KMS backends (mock SDK clients)
- Integration tests: sign with KMS backend, verify with local backend (and vice versa) to ensure interoperability
- Test that documents signed by KMS backends are verifiable by any JACS agent with the public key
- Test algorithm mismatch errors (e.g., configuring KMS for Ed25519 when agent is pq2025)
- Benchmark comparison: local vs KMS signing latency

#### D.8: Documentation

- `jacsbook/src/advanced/hsm.md`: HSM/KMS integration guide
- Setup guides per cloud provider (IAM policy for KMS, PKCS#11 module configuration)
- `jacsbook/src/advanced/security.md`: updated threat model with HSM option
- Migration guide: how to move an existing agent's signing to KMS (re-register public key, old signatures still verify)
- All binding READMEs and haisdk docs

---

## Final Resolution Order (All Phases Complete)

```
1. Explicit password           (CreateAgentParams.password / API param)
2. Password file               (JACS_PASSWORD_FILE env / --password-file / config)
3. External secrets manager    (jacs_password_source config — Phase C)
4. OS keychain                 (keychain feature — Phase B)
5. TTY prompt                  (rpassword, if stdin is terminal — Phase A)
6. Environment variable        (JACS_PRIVATE_KEY_PASSWORD — existing, demoted)
7. HSM/KMS backend             (no password needed — Phase D, separate path)
8. Error with guidance
```

Note: Option 7 (HSM/KMS) is not really part of the password resolution chain — it's a separate code path where no password is needed at all. When `jacs_crypto_backend` is configured, the entire password resolution is skipped.

## Risk Assessment

| Change | Risk | Mitigation |
|--------|------|------------|
| TTY prompt in library code | Blocks if accidentally called in non-interactive context | Guard with `IsTerminal` check; never prompt in library mode, only CLI |
| Password file permission check | May reject valid files on non-Unix or exotic filesystems | `#[cfg(unix)]` gate; warn-only in permissive mode, error in strict |
| Resolution order change | Existing users relying on env var are unaffected | Env var is still checked (position 6). No behavior change for users who already set it |
| `rpassword` dependency | Supply chain risk | Pure Rust, well-audited, used by `cargo`, `gh`, `1password-cli` |
| `keyring` native deps | Build complexity on Linux | Feature-gated, default-on. CI tests with and without feature. Document `libsecret-1-dev` requirement. |
| Secrets manager SDKs | Heavy transitive deps, version churn | Each behind its own feature flag. Not in default features. Separate `secrets-*` flags. |
| `CryptoBackend` refactor | Large diff touching core signing path | Phase D is last. All existing tests must pass with `LocalCryptoBackend`. Feature-flag new backends. |
| Cross-repo coordination (haisdk) | Version skew between JACS and haisdk | Pin haisdk to JACS minor version. Release haisdk update alongside each JACS phase. |
| Deprecating env var as primary | Documentation churn | Env var is *not removed*, just demoted in docs and resolution order |

## Relationship to SECURITY_PLAN.md

This plan directly addresses:
- **P0 #3**: "Require encrypted private-key defaults" — by providing secure password supply paths (Phases A-C)
- **Exit Criteria #3**: "New agent creation defaults to encrypted private-key storage" — quickstart now prompts interactively rather than requiring env var setup (Phase A)
- **"What We Should Not Do Now" #1 (FIPS)**: Phase D lays the groundwork for FIPS by introducing `CryptoBackend` abstraction and PKCS#11 support

## Phasing and Dependencies

```
Phase A (TTY + File)
  └── Phase B (Keychain)        — depends on A (resolution function exists)
  └── Phase C (Secrets Manager)  — depends on A (PasswordSource trait builds on resolve_password)
        └── Phase D (HSM/KMS)    — depends on C conceptually (same trait pattern),
                                   but is architecturally independent (CryptoBackend, not PasswordSource)
```

Phase B and C can be developed in parallel after Phase A is complete. Phase D can begin once the `CryptoBackend` trait design is agreed upon, independent of B and C.

## Open Questions

1. Should TTY prompt be enabled by default in `quickstart()`, or require an explicit `--interactive` flag?
2. For `--password-file`, should we support reading from stdin via `-` (like `gpg --passphrase-fd 0`)?
3. Should the keychain feature (Phase B) be included in default features, or require explicit opt-in?
4. Should we add a `JACS_PASSWORD_SOURCE` env var to explicitly select the method (`tty`, `file`, `env`, `keychain`, `vault`), or is the auto-detection precedence sufficient?
5. For Phase D, should KMS-signed documents use a distinct algorithm identifier (e.g., `aws-kms-ecdsa-p256`) or reuse the existing algorithm names (e.g., `ECDSA-P256`) with backend metadata in the signature?
6. For haisdk coordination: should haisdk releases be locked to JACS releases, or can they lag by one minor version?
