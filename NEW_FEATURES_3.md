# Phase 3: Runtime Configuration (Steps 176-225)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 176-225
**Dependencies**: Phase 2 must be complete. Phase 2 delivers `DatabaseStorage`, `DatabaseDocumentTraits`, `StorageBackend` enum, `JACS_DATABASE_URL` in Config, and MultiStorage integration. Phase 3 builds the runtime configuration layer that lets higher-level libraries (hai, libhai) wire all of that together at startup without recompiling JACS.
**Summary**: Implement the `JacsConfigProvider` trait, runtime configuration system with `RwLock`-based mutation, `AgentBuilder` integration, HAI integration pattern, observability runtime reconfiguration, and backward compatibility guarantees.

---

## What This Phase Delivers

Phase 3 introduces a **trait-based runtime configuration system** so that higher-level libraries like `hai` and `libhai` can provide JACS configuration at runtime rather than relying solely on config files and environment variables. Today, JACS loads configuration once via `load_config_12factor()` (defaults -> config file -> env vars). This works for standalone usage but does not accommodate libraries that discover their own configuration at startup and need to pass it down to JACS programmatically.

After Phase 3:

- **Any Rust library** can implement `JacsConfigProvider` and inject configuration into JACS at initialization time.
- **Runtime config mutation** is supported via `RuntimeConfig` with `RwLock<Config>`, enabling observability reconfiguration without restart.
- **The override chain** is extended to four levels: built-in defaults -> config file -> environment variables -> runtime config provider.
- **AgentBuilder** gains `.config_provider()`, `.with_storage()`, and `.with_storage_and_database()` methods.
- **Observability** (logs, metrics, tracing) can be toggled at runtime through the config provider or direct `RuntimeConfig` mutation.
- **Security invariant preserved**: Keys ALWAYS load from the filesystem or keyservers. The `JacsConfigProvider` trait intentionally has NO key-related methods.

---

## Architecture: Runtime Configuration

### What We Want

A trait-based configuration interface where higher-level libraries provide JACS configuration at runtime. The `hai` crate, for example, reads its own environment variables and database connection strings at startup, then passes that configuration down to JACS. Today this requires either writing a `jacs.config.json` file to disk or setting environment variables before JACS initialization -- neither of which is ergonomic for library consumers.

The trait approach means:
- `hai` implements `JacsConfigProvider` with its own startup logic.
- `libhai` implements `JacsConfigProvider` with its database connector discovery.
- Any third-party consumer can implement the trait for their own deployment pattern.
- JACS never needs to know about its consumers' configuration mechanisms.

### Why Runtime, Not Compile-Time

1. **Higher-level libraries discover config at startup.** The `hai` crate reads database URLs, observability endpoints, and storage preferences from its own configuration system. These values are not known at JACS compile time.

2. **Same binary for multiple environments.** A single compiled JACS binary should run in development (filesystem storage, stderr logs), staging (database storage, OTLP tracing), and production (database storage, Prometheus metrics). Compile-time feature flags gate dependency *inclusion*; runtime config gates *activation*.

3. **Observability is toggleable.** In production, operators need to enable or change tracing sampling ratios, switch log levels, or enable metrics export without redeploying. This requires runtime mutation of the observability configuration.

4. **12-Factor compliance.** Environment variables remain the primary override mechanism. Runtime config providers are an additional layer for programmatic consumers, not a replacement for env vars.

### Compile-Time vs. Runtime Distinction

| Concern | Compile-Time (Cargo features) | Runtime (Config/Provider) |
|---------|-------------------------------|---------------------------|
| `sqlx` dependency | `database` feature includes the crate | Database URL activates the connection |
| `opentelemetry` dependency | `otlp-tracing` feature includes the crate | `TracingConfig.enabled` activates tracing |
| `pgvector` dependency | `database-vector` feature includes the crate | Vector search queries activate the extension |
| Storage backend | Feature flags control which backends compile | `jacs_default_storage` or provider selects which backend runs |

### The JacsConfigProvider Trait

```rust
/// Trait for providing JACS configuration at runtime.
///
/// Implement this trait in higher-level libraries (hai, libhai, or any consumer)
/// to inject configuration into JACS without relying on config files or env vars alone.
///
/// # Security Invariant
/// This trait intentionally has NO key-related methods. Private keys, public keys,
/// and key algorithms are ALWAYS loaded from secure locations (filesystem via
/// `FileLoader::fs_load_keys` / `fs_preload_keys`, or from keyservers). The config
/// provider can specify WHERE keys are stored (directories) but never the key material
/// itself.
///
/// # Thread Safety
/// Implementations must be `Send + Sync` to allow sharing across threads via `Arc`.
pub trait JacsConfigProvider: Send + Sync {
    /// Returns the complete JACS configuration.
    /// This is called once during `AgentBuilder::build()` and merged into the
    /// override chain after env vars.
    fn get_config(&self) -> Result<Config, Box<dyn Error>>;

    /// Returns the storage type (e.g., "fs", "database", "memory").
    /// Returns None to use the default from the override chain.
    fn get_storage_type(&self) -> Option<String>;

    /// Returns the database connection URL.
    /// Only meaningful when storage type is "database".
    /// Returns None to use the default from the override chain.
    fn get_database_url(&self) -> Option<String>;

    /// Returns the data directory path for filesystem storage.
    /// Returns None to use the default from the override chain.
    fn get_data_directory(&self) -> Option<String>;

    /// Returns the key directory path where keys are stored on the filesystem.
    /// This controls WHERE keys are looked for, not the key material itself.
    /// Returns None to use the default from the override chain.
    fn get_key_directory(&self) -> Option<String>;

    /// Returns the observability configuration (logs, metrics, tracing).
    /// Returns None to use the default from the override chain.
    fn get_observability_config(&self) -> Option<ObservabilityConfig>;

    // NOTE: No key-related methods. Keys always from filesystem/keyservers.
    // Key loading stays in FileLoader::fs_load_keys / fs_preload_keys.
    // The trait has NO methods for private key material, public key material,
    // or key algorithm selection.
}
```

### Override Chain

Configuration values are resolved in this order, with later sources overriding earlier ones (highest precedence last):

```
1. Built-in defaults       (Config::with_defaults())
2. Config file             (load from jacs.config.json if provided)
3. Environment variables   (JACS_* env vars via apply_env_overrides())
4. Runtime config provider (JacsConfigProvider::get_config() merged last)
```

This means:
- A config file can override defaults.
- An env var always overrides a config file value (12-Factor compliance).
- A runtime provider can override everything, including env vars, because the provider represents explicit programmatic intent from the consuming library.

### Agent Initialization Pattern

```rust
// In hai or libhai:
use std::sync::Arc;
use jacs::config::JacsConfigProvider;
use jacs::agent::AgentBuilder;

let provider = Arc::new(MyAppConfigProvider::new());
let agent = AgentBuilder::new()
    .config_provider(provider)
    .build()?;

// The provider's get_config() is called during build() and merged
// into the override chain as the highest-precedence source.
```

For consumers that do not need a provider (standalone JACS usage), nothing changes:

```rust
// Existing pattern still works identically:
let agent = AgentBuilder::new()
    .config_path("./jacs.config.json")
    .build()?;
```

### Security: Keys Always From Secure Locations

This is a hard constraint inherited from the original requirements (see NEW_FEATURES.md, Decision 11). The `JacsConfigProvider` trait deliberately excludes:

- `get_private_key()` -- private key material must never flow through configuration.
- `get_public_key()` -- public keys are loaded from filesystem or fetched from keyservers.
- `get_key_algorithm()` -- key algorithm is derived from the loaded keys, not injected.

Key loading remains in the existing `FileLoader` trait (`jacs/src/agent/loaders.rs`):
- `fs_load_keys(&mut self)` -- loads keys from the configured key directory.
- `fs_preload_keys(&mut self, private_key_filename, public_key_filename, custom_key_algorithm)` -- loads specific key files.
- `fs_save_keys(&mut self)` -- saves generated keys to the key directory.

The provider CAN specify `get_key_directory()` to tell JACS where to look for keys on the filesystem, but it cannot provide the key bytes themselves.

### RuntimeConfig with RwLock

For post-initialization config changes (primarily observability reconfiguration), Phase 3 introduces `RuntimeConfig`:

```rust
/// Thread-safe mutable configuration container.
///
/// Wraps a `Config` in an `RwLock` to allow safe concurrent reads and
/// exclusive writes. Used for runtime reconfiguration of observability
/// settings without restarting the agent.
///
/// # Lock Poisoning
/// All lock acquisitions handle poisoning explicitly. A poisoned lock
/// returns `JacsError::ConfigError` with a descriptive message rather
/// than panicking. This ensures that a panic in one thread during a
/// config write does not crash the entire application.
pub struct RuntimeConfig {
    inner: RwLock<Config>,
}

impl RuntimeConfig {
    pub fn new(config: Config) -> Self { ... }
    pub fn read(&self) -> Result<RwLockReadGuard<Config>, JacsError> { ... }
    pub fn write(&self) -> Result<RwLockWriteGuard<Config>, JacsError> { ... }
    pub fn update_observability(&self, obs: ObservabilityConfig) -> Result<(), JacsError> { ... }
    pub fn snapshot(&self) -> Result<Config, JacsError> { ... }
}
```

---

## Phase 3A: JacsConfigProvider Trait (Steps 176-195)

### Step 176. Test: `test_jacs_config_provider_trait`

- **Why**: Establish the trait contract before writing any implementation. TDD ensures the trait is object-safe and usable with `Arc<dyn JacsConfigProvider>`.
- **What**: Create a mock struct `MockConfigProvider` that implements `JacsConfigProvider`. Verify it can be stored in `Arc<dyn JacsConfigProvider>`, passed across thread boundaries (`Send + Sync`), and that `get_config()` returns the expected `Config`. Test that all optional methods (`get_storage_type`, `get_database_url`, etc.) return `None` by default in the mock, and specific values when configured.
- **Where**: `jacs/src/config/mod.rs` (test module at bottom). Follow the existing test pattern: `#[cfg(test)] mod tests { ... }`. The mock lives inside the test module, not in production code.

### Step 177. Test: `test_config_provider_override_chain`

- **Why**: The override chain (defaults -> config file -> env vars -> provider) is the core architectural guarantee. This test locks down the precedence order.
- **What**: Create a test that sets values at each level and verifies the final merged config reflects the correct precedence. Specifically: set `jacs_data_directory` to "/default" in `Config::with_defaults()`, "/from-file" in a mock file config, "/from-env" via env var, and "/from-provider" via a mock provider. Assert the final result is "/from-provider". Also test partial overrides: provider returns `None` for `get_data_directory()`, so env var wins. Provider returns `Some` for `get_storage_type()`, so it overrides env var.
- **Where**: `jacs/src/config/mod.rs` test module. Use `#[serial]` for env var tests (follow `test_apply_env_overrides` pattern). Use `clear_jacs_env_vars()` for isolation.

### Step 178. Define `JacsConfigProvider` trait

- **Why**: This is the primary deliverable of Phase 3. It decouples JACS configuration from file/env-only patterns.
- **What**: Define the trait exactly as shown in the Architecture section above. Place it in `src/config/mod.rs` after the `ObservabilityConfig` struct definitions and before the `#[cfg(test)]` module. The trait must be `pub` and require `Send + Sync`. All methods except `get_config()` should have default implementations returning `None` so that simple providers only need to implement `get_config()`. Add comprehensive rustdoc with examples showing a minimal implementation.
- **Where**: `jacs/src/config/mod.rs`, approximately after line 1210 (after `TracingDestination` impl block, before the test module). Add `use std::sync::Arc;` to the imports if not already present.

### Step 179. Default impl of `JacsConfigProvider` for `Config`

- **Why**: Allow a bare `Config` to be used as a provider for simple cases. This means `Arc::new(config)` satisfies `Arc<dyn JacsConfigProvider>` without writing a custom struct.
- **What**: Implement `JacsConfigProvider for Config`. `get_config()` returns `Ok(self.clone())` (requires `Config: Clone`, which will need to be derived). `get_storage_type()` delegates to `self.jacs_default_storage().clone()`. `get_database_url()` returns `self.jacs_database_url.clone()` (field added in Step 187). Other methods follow the same pattern. Note: `Config` must derive `Clone` -- currently it only has `Serialize, Deserialize, Debug, Getters`. Add `Clone` to the derive list.
- **Where**: `jacs/src/config/mod.rs`, immediately after the `JacsConfigProvider` trait definition.

### Step 180. Test: `test_default_config_provider`

- **Why**: Verify that a `Config` instance works correctly as a `JacsConfigProvider`.
- **What**: Create a `Config` via `Config::builder().data_directory("/test").build()`, wrap it in `Arc::new(...)`, and call `get_config()`, `get_data_directory()`, `get_storage_type()` through the `dyn JacsConfigProvider` interface. Assert all values match. Verify `get_database_url()` returns `None` when no database URL is set.
- **Where**: `jacs/src/config/mod.rs` test module.

### Step 181. Create `EnvConfigProvider` impl

- **Why**: Provide a ready-made provider that reads all configuration from environment variables. This is useful for containerized deployments where all config comes from the environment and the consuming library wants to pass it to JACS programmatically rather than relying on JACS's own env var loading.
- **What**: Create `pub struct EnvConfigProvider;` (unit struct, no fields). Implement `JacsConfigProvider`: `get_config()` calls `load_config_12factor(None)`. `get_storage_type()` reads `JACS_DEFAULT_STORAGE`. `get_database_url()` reads `JACS_DATABASE_URL`. `get_data_directory()` reads `JACS_DATA_DIRECTORY`. `get_key_directory()` reads `JACS_KEY_DIRECTORY`. `get_observability_config()` reads `JACS_OBSERVABILITY_CONFIG` (JSON string, parsed with `serde_json::from_str`).
- **Where**: `jacs/src/config/mod.rs`, after the `Config` impl of `JacsConfigProvider`.

### Step 182. Test: `test_env_config_provider`

- **Why**: Ensure `EnvConfigProvider` correctly reads from environment variables.
- **What**: Set `JACS_DATA_DIRECTORY=/env/test/data` and `JACS_DEFAULT_STORAGE=memory` via `set_env_var()`. Create `EnvConfigProvider`, call `get_data_directory()` and `get_storage_type()`. Assert values match. Clean up with `clear_jacs_env_vars()`. Also test that `get_database_url()` returns `None` when `JACS_DATABASE_URL` is not set.
- **Where**: `jacs/src/config/mod.rs` test module. Use `#[serial]` and `clear_jacs_env_vars()`.

### Step 183. Add `config_provider` field to `Agent`

- **Why**: The `Agent` struct needs to hold a reference to the config provider so it can be queried after initialization (e.g., for runtime reconfiguration of observability).
- **What**: Add `config_provider: Option<Arc<dyn JacsConfigProvider>>` to the `Agent` struct in `src/agent/mod.rs`. This field is `None` when no provider is used (backward compatible). The `Arc` wrapper allows sharing the provider across threads and cloning cheaply. Update `Agent::new()` to set this field to `None`. Update `Agent::fmt::Display` if needed (skip the provider in display output).
- **Where**: `jacs/src/agent/mod.rs`, line 89 (`Agent` struct). Add the field after `dns_required: Option<bool>`. Add `use std::sync::Arc;` and `use crate::config::JacsConfigProvider;` to imports.

### Step 184. Add `config_provider()` method to `AgentBuilder`

- **Why**: The builder pattern is the idiomatic way to configure agents. The provider must be settable through the builder.
- **What**: Add `config_provider: Option<Arc<dyn JacsConfigProvider>>` field to `AgentBuilder`. Add `pub fn config_provider(mut self, provider: Arc<dyn JacsConfigProvider>) -> Self` method. Document that when a provider is set, it becomes the highest-precedence configuration source, overriding config file and env vars.
- **Where**: `jacs/src/agent/mod.rs`, in the `AgentBuilder` struct (line 1146) and its `impl` block (line 1157).

### Step 185. Modify `AgentBuilder::build()` to use provider

- **Why**: The provider must be integrated into the existing config loading flow within `build()`.
- **What**: After the existing config loading logic (lines 1286-1299), add a new step: if `self.config_provider` is `Some`, call `provider.get_config()` and merge the result into the loaded config via `config.merge(provider_config)`. This ensures the override chain is: defaults -> file -> env -> provider. Also pass the provider to the `Agent` struct constructor. The merge happens AFTER `apply_env_overrides()` to give the provider highest precedence. If the provider's `get_config()` returns `Err`, propagate the error as `JacsError::ConfigError`.
- **Where**: `jacs/src/agent/mod.rs`, in `AgentBuilder::build()` method (lines 1275-1337). Insert the provider merge after line 1299 (after config is loaded) and before line 1301 (storage initialization).

### Step 186. Test: `test_agent_builder_with_config_provider`

- **Why**: Verify end-to-end that a provider injects config into the agent.
- **What**: Create a mock provider returning `Config::builder().data_directory("/from-provider").build()`. Build an agent with `.config_provider(Arc::new(mock))`. Assert `agent.config.unwrap().jacs_data_directory()` is `Some("/from-provider")`. Also test that a provider overrides an env var: set `JACS_DATA_DIRECTORY=/from-env`, provider returns "/from-provider", final config should be "/from-provider".
- **Where**: `jacs/src/agent/mod.rs`, `builder_tests` module (line 1362).

### Step 187. Add `jacs_database_url` field to `Config`

- **Why**: Phase 2 introduced `JACS_DATABASE_URL` but the field may not yet be in the Config struct (Step 141 in Phase 2 adds it to config, but this step ensures it is properly integrated with the provider system).
- **What**: If not already present from Phase 2, add `jacs_database_url: Option<String>` to the `Config` struct with `#[getset(get = "pub")]`, `#[serde(default, skip_serializing_if = "Option::is_none")]`. Add it to `Config::with_defaults()` as `None`. Add it to `ConfigBuilder` with a `.database_url()` builder method. Ensure `Config::merge()` handles it. If Phase 2 already added this field, this step verifies and extends it with provider integration.
- **Where**: `jacs/src/config/mod.rs`, in the `Config` struct, `ConfigBuilder` struct, and their impl blocks.

### Step 188. Add `database_url` to `ConfigBuilder`

- **Why**: ConfigBuilder must support all Config fields for completeness.
- **What**: Add `database_url: Option<String>` field to `ConfigBuilder`. Add `pub fn database_url(mut self, url: &str) -> Self` method. Update `ConfigBuilder::build()` to include `jacs_database_url: self.database_url` in the constructed `Config`.
- **Where**: `jacs/src/config/mod.rs`, `ConfigBuilder` struct (line 334) and its impl block (line 350).

### Step 189. Add `JACS_DATABASE_URL` to env override and check functions

- **Why**: The database URL must participate in the 12-Factor env var override chain.
- **What**: In `Config::apply_env_overrides()`, add: `if let Some(val) = env_opt("JACS_DATABASE_URL") { self.jacs_database_url = Some(val); }`. In `check_env_vars()`, add `("JACS_DATABASE_URL", false)` to the vars array (not required, since database is optional). In `Config::Display`, add the database URL line with REDACTED value (URLs may contain credentials): `JACS_DATABASE_URL: REDACTED({} chars)`.
- **Where**: `jacs/src/config/mod.rs`, methods `apply_env_overrides()` (line 610), `check_env_vars()` (line 1151), and `fmt::Display for Config` (line 746).

### Step 190. Update `Config::merge()` and `Config::Display` for database URL

- **Why**: Merge must handle the new field; display must redact credentials.
- **What**: Add `if other.jacs_database_url.is_some() { self.jacs_database_url = other.jacs_database_url; }` to `Config::merge()`. In the `Display` impl, show `JACS_DATABASE_URL: REDACTED (N chars)` where N is the length, or "NOT SET" if None. Never display the actual URL since it may contain passwords.
- **Where**: `jacs/src/config/mod.rs`, `Config::merge()` (line 549) and `fmt::Display for Config` (line 746).

### Step 191. Test: `test_config_database_url_12factor`

- **Why**: Verify the database URL flows correctly through all four override levels.
- **What**: Test 1: Default has no database URL. Test 2: Config file sets it, env var overrides it. Test 3: Provider overrides env var. Test 4: URL is redacted in Display output (assert the display string does NOT contain "postgres://"). Use `#[serial]` for env var tests.
- **Where**: `jacs/src/config/mod.rs` test module.

### Step 192. Create `RuntimeConfig` in `src/config/runtime.rs`

- **Why**: Post-initialization config mutation requires thread-safe access. Observability settings (log level, tracing sampling ratio) must be changeable without restarting.
- **What**: Create a new file `src/config/runtime.rs`. Define `RuntimeConfig` as shown in the Architecture section. Implement:
  - `new(config: Config) -> Self` -- wraps config in `RwLock`.
  - `read(&self) -> Result<RwLockReadGuard<Config>, JacsError>` -- acquires read lock, handles poisoning with `JacsError::ConfigError("RuntimeConfig read lock poisoned: {}")`.
  - `write(&self) -> Result<RwLockWriteGuard<Config>, JacsError>` -- acquires write lock, handles poisoning similarly.
  - `update_observability(&self, obs: ObservabilityConfig) -> Result<(), JacsError>` -- acquires write lock, sets `config.observability = Some(obs)`.
  - `snapshot(&self) -> Result<Config, JacsError>` -- acquires read lock, clones the config (requires `Config: Clone`).
  Add `pub mod runtime;` to `src/config/mod.rs`.
- **Where**: New file `jacs/src/config/runtime.rs`. Module declaration in `jacs/src/config/mod.rs` (after `pub mod constants;`, line 134).

### Step 193. Test: `test_runtime_config_mutation`

- **Why**: Verify that `RuntimeConfig` supports concurrent reads and exclusive writes safely.
- **What**: Create a `RuntimeConfig`, spawn two threads that read config concurrently (should not block each other). Then spawn a thread that writes an observability config while another thread reads. Verify the write is visible to subsequent reads. Test `snapshot()` returns a cloned copy that does not hold any lock. Test lock poisoning: spawn a thread that panics while holding the write lock, then verify subsequent `read()` and `write()` calls return `JacsError::ConfigError` rather than panicking.
- **Where**: `jacs/src/config/runtime.rs` test module.

### Steps 194-195. Backward Compatibility Tests

- **Why**: Phase 3 must not break any existing configuration patterns.
- **What**:
  - **Step 194**: Test that a `jacs.config.json` file from JACS 0.5.x (without database URL, without observability config) still loads correctly via `load_config_12factor()`. Missing fields default to `None`. No errors, no warnings about missing fields.
  - **Step 195**: Test that an agent built with `AgentBuilder::new().build()` (no provider, no config path, no env vars) produces the same config as JACS 0.5.x defaults. Specifically: `jacs_data_directory` resolves to CWD + "/jacs_data" for filesystem storage, `jacs_database_url` is `None`, `config_provider` is `None`.
- **Where**: `jacs/src/config/mod.rs` test module (Step 194) and `jacs/src/agent/mod.rs` `builder_tests` module (Step 195).

---

## Phase 3B: HAI Integration Pattern (Steps 196-210)

### Step 196. Test: `test_hai_config_provider`

- **Why**: Validate that the trait works for the primary consumer: the `hai` crate pattern.
- **What**: Create a `HaiConfigProvider` struct that simulates how `hai` configures JACS: reads `HAI_DATABASE_URL` from env, sets storage to "database", sets data directory from `HAI_DATA_DIR`, sets observability from `HAI_OBSERVABILITY_ENDPOINT`. Verify that `get_config()` returns a Config with all these values populated. Verify `get_storage_type()` returns `Some("database")`.
- **Where**: `jacs/src/config/mod.rs` test module.

### Step 197. Create `HaiConfigProvider` example struct

- **Why**: Provide a reference implementation that documents the HAI integration pattern.
- **What**: Create `examples/hai_config_provider.rs` (or a doc example in the trait documentation) showing a complete `JacsConfigProvider` implementation. Include comments explaining each method. Show the full lifecycle: create provider, create agent, load agent identity, sign a document. This is documentation, not production code -- it lives in examples or rustdoc.
- **Where**: `jacs/examples/hai_config_provider.rs` or as expanded rustdoc on the `JacsConfigProvider` trait in `jacs/src/config/mod.rs`.

### Step 198. Test: `test_init_from_env_pattern`

- **Why**: The `hai_signing::init_from_env()` pattern in the `hai` crate initializes JACS entirely from environment variables. This test replicates that pattern using the new provider system.
- **What**: Set all necessary env vars (`JACS_DATA_DIRECTORY`, `JACS_KEY_DIRECTORY`, `JACS_DEFAULT_STORAGE`, `JACS_DATABASE_URL`). Create an `EnvConfigProvider`. Build an agent with that provider. Assert all config values match env vars. This proves the migration path: `hai` can switch from calling `set_env_vars()` (deprecated) to using `EnvConfigProvider` with no behavior change.
- **Where**: `jacs/src/config/mod.rs` test module. Use `#[serial]`.

### Step 199. Add `init_agent_from_provider()` convenience function

- **Why**: Reduce boilerplate for the common case: create an agent from a provider.
- **What**: Add a public function `pub fn init_agent_from_provider(provider: Arc<dyn JacsConfigProvider>) -> Result<Agent, JacsError>` that calls `AgentBuilder::new().config_provider(provider).build()`. This is a one-liner convenience but saves consumers from importing `AgentBuilder`.
- **Where**: `jacs/src/agent/mod.rs`, as a free function after the `AgentBuilder` impl block (or in a new `jacs/src/agent/convenience.rs` if the file grows too large). Re-export from `jacs/src/lib.rs`.

### Step 200. Test: `test_init_agent_from_provider`

- **Why**: Verify the convenience function works end-to-end.
- **What**: Create a mock provider, call `init_agent_from_provider(Arc::new(mock))`, verify the returned agent has the expected config.
- **Where**: `jacs/src/agent/mod.rs` test module.

### Step 201. Add `init_agent_from_config()` convenience function

- **Why**: Another common case: create an agent from a pre-built `Config` (no provider needed).
- **What**: Add `pub fn init_agent_from_config(config: Config) -> Result<Agent, JacsError>` that calls `AgentBuilder::new().config(config).build()`.
- **Where**: Same location as Step 199.

### Step 202. Test: `test_init_agent_from_config`

- **Why**: Verify the Config convenience function.
- **What**: Create a `Config` via builder, call `init_agent_from_config(config)`, verify the agent config.
- **Where**: `jacs/src/agent/mod.rs` test module.

### Step 203. Document security constraint: keys from secure locations only

- **Why**: The security invariant must be documented at every relevant touchpoint to prevent future contributors from adding key methods to the provider trait.
- **What**: Add a `# Security` section to the module-level doc comment in `src/config/mod.rs` explaining that keys are never part of runtime configuration. Add a `// SECURITY INVARIANT: ...` comment above the `JacsConfigProvider` trait. Add a section to the `AgentBuilder::build()` doc comment. Reference Decision 11 from `NEW_FEATURES.md`.
- **Where**: `jacs/src/config/mod.rs` (module doc comment and trait doc comment) and `jacs/src/agent/mod.rs` (`AgentBuilder::build()` doc comment).

### Step 204. Add validation in `AgentBuilder::build()` for database+key constraint

- **Why**: When storage is "database", keys must still be loaded from the filesystem. This should be validated explicitly so misconfiguration fails fast.
- **What**: In `AgentBuilder::build()`, after config is resolved, check: if `jacs_default_storage` is "database", verify that `jacs_key_directory` is set and is a valid filesystem path (not empty, not "database://..."). If validation fails, return `JacsError::ConfigError("Database storage requires keys from filesystem. Set JACS_KEY_DIRECTORY to a valid directory path.")`.
- **Where**: `jacs/src/agent/mod.rs`, in `AgentBuilder::build()`, after the config merge step.

### Step 205. Test: `test_database_storage_keys_still_from_filesystem`

- **Why**: Lock down the security invariant with a concrete test.
- **What**: Build an agent with storage="database" and a valid key directory. Verify it succeeds. Then build with storage="database" and no key directory. Verify it fails with the expected error message. Also verify that the `FileLoader` trait methods (`fs_load_keys`, `fs_preload_keys`) are still the only way keys are loaded regardless of storage backend.
- **Where**: `jacs/src/agent/mod.rs` `builder_tests` module.

### Step 206. Add `with_storage()` to `AgentBuilder`

- **Why**: Allow explicit storage type selection through the builder, independent of config.
- **What**: Add `storage_type: Option<String>` field to `AgentBuilder`. Add `pub fn with_storage(mut self, storage_type: &str) -> Self` method. In `build()`, if `self.storage_type` is set, it overrides the config's `jacs_default_storage`. This is syntactic sugar for setting storage in the builder rather than through config.
- **Where**: `jacs/src/agent/mod.rs`, `AgentBuilder` struct and impl.

### Step 207. Test: `test_agent_builder_with_storage`

- **Why**: Verify storage type selection through the builder.
- **What**: Build agent with `.with_storage("memory")`. Assert config shows "memory" storage. Build with `.with_storage("database")` and valid key directory. Assert config shows "database".
- **Where**: `jacs/src/agent/mod.rs` `builder_tests` module.

### Step 208. Add `with_storage_and_database()` to `AgentBuilder` (cfg-gated)

- **Why**: Convenience method that sets storage to "database" and provides the database URL in one call.
- **What**: Add `#[cfg(feature = "database")] pub fn with_storage_and_database(mut self, database_url: &str) -> Self` that sets `self.storage_type = Some("database".to_string())` and stores the URL. In `build()`, the URL is merged into config as `jacs_database_url`. The `#[cfg]` gate ensures this method only exists when the `database` feature is enabled.
- **Where**: `jacs/src/agent/mod.rs`, `AgentBuilder` impl.

### Step 209. Test: `test_agent_builder_with_database`

- **Why**: Verify the database convenience method.
- **What**: Feature-gated test (`#[cfg(feature = "database")]`). Build agent with `.with_storage_and_database("postgres://localhost/jacs")`. Assert storage is "database" and database URL is set. Verify key directory is still required.
- **Where**: `jacs/src/agent/mod.rs` `builder_tests` module.

### Step 210. Run all Phase 3A and 3B tests

- **Why**: Checkpoint before moving to observability.
- **What**: Run `cargo test` (all default features), `cargo test --features database` (with database), and `cargo check --target wasm32-unknown-unknown` (WASM compat). Fix any failures. Verify no clippy warnings with `cargo clippy --all-features -- -D warnings`.
- **Where**: CI/terminal.

---

## Phase 3C: Observability Runtime Config (Steps 211-225)

### Step 211. Test: `test_observability_runtime_reconfiguration`

- **Why**: Validate that observability settings can be changed after agent initialization.
- **What**: Create an agent with observability disabled. Call `runtime_config.update_observability(new_obs_config)` where `new_obs_config` has `logs.enabled = true` and `logs.level = "debug"`. Verify the config change is visible via `runtime_config.read()`. Then call `reconfigure_observability()` to apply it. Verify logging is now active at debug level.
- **Where**: `jacs/src/observability/mod.rs` test module.

### Step 212. Add `reconfigure_observability()` function

- **Why**: Bridge between `RuntimeConfig` mutation and actual observability system reconfiguration.
- **What**: Add `pub fn reconfigure_observability(config: &ObservabilityConfig) -> Result<(), Box<dyn std::error::Error>>` to `src/observability/mod.rs`. This function: (1) updates the static `CONFIG` Mutex, (2) re-initializes log layer if log config changed, (3) re-initializes metrics if metrics config changed, (4) re-initializes tracing if tracing config changed. Handle the case where the tracing subscriber is already set globally (cannot re-set; log a warning). Metrics and logs CAN be reconfigured.
- **Where**: `jacs/src/observability/mod.rs`, after `init_observability()`.

### Step 213. Test: `test_observability_toggle_at_runtime`

- **Why**: The key use case: toggle observability on/off without restart.
- **What**: Start with observability disabled. Toggle logs on, verify logging works. Toggle metrics on, verify metrics work. Toggle logs off, verify logging stops. Use `force_reset_for_tests()` for cleanup.
- **Where**: `jacs/src/observability/mod.rs` test module.

### Step 214. Add `ObservabilityConfig` to `JacsConfigProvider` and `RuntimeConfig`

- **Why**: Providers need to supply observability config; RuntimeConfig needs to mutate it.
- **What**: `get_observability_config()` is already on the trait (Step 178). This step ensures that `AgentBuilder::build()` extracts observability config from the provider and: (1) merges it into the Config, (2) initializes observability if enabled, (3) stores the observability config in `RuntimeConfig` for later mutation. Add `runtime_config: Option<Arc<RuntimeConfig>>` field to `Agent`.
- **Where**: `jacs/src/agent/mod.rs` (Agent struct) and `AgentBuilder::build()`.

### Step 215. Test: `test_runtime_config_observability`

- **Why**: Verify the full flow: provider supplies observability config, agent initializes with it, runtime mutation changes it.
- **What**: Create a provider that returns an `ObservabilityConfig` with `logs.enabled = true, logs.level = "warn"`. Build agent. Assert observability was initialized. Mutate via `agent.runtime_config.update_observability(new_config)` where `new_config` changes level to "debug". Call `reconfigure_observability()`. Verify the change took effect.
- **Where**: `jacs/src/config/runtime.rs` or `jacs/src/observability/mod.rs` test module.

### Step 216. Add `JACS_OBSERVABILITY_CONFIG` env var

- **Why**: Allow observability configuration via environment variable (JSON string).
- **What**: In `Config::apply_env_overrides()`, add: read `JACS_OBSERVABILITY_CONFIG`, parse as JSON into `ObservabilityConfig`, set `self.observability = Some(parsed)`. If parsing fails, log a warning and skip (do not fail config loading). This follows the same pattern as other env vars but with JSON parsing.
- **Where**: `jacs/src/config/mod.rs`, `apply_env_overrides()` method.

### Step 217. Test: `test_observability_config_from_env`

- **Why**: Verify the JSON env var parsing.
- **What**: Set `JACS_OBSERVABILITY_CONFIG='{"logs":{"enabled":true,"level":"debug"},"metrics":{"enabled":false}}'`. Load config via `load_config_12factor(None)`. Assert `config.observability` is `Some` with `logs.enabled = true` and `logs.level = "debug"`. Also test invalid JSON: set the env var to "not-json", verify config loads without error (observability stays None) and a warning is logged.
- **Where**: `jacs/src/config/mod.rs` test module. Use `#[serial]`.

### Step 218. Config validation for database + observability combinations

- **Why**: Certain combinations need validation (e.g., database storage with OTLP tracing requires specific connection handling).
- **What**: Add `pub fn validate_config_combinations(config: &Config) -> Result<(), JacsError>` that checks: (1) if storage is "database" and database_url is None, return error. (2) if OTLP tracing is enabled but the `otlp-tracing` feature is not compiled, return error with guidance. (3) if metrics destination is Prometheus but storage is not "database", log a warning (not an error). Call this function in `AgentBuilder::build()` after final config resolution.
- **Where**: `jacs/src/config/mod.rs` (new function). Called from `jacs/src/agent/mod.rs`.

### Step 219. Test: `test_config_validation_complete`

- **Why**: Lock down all validation rules.
- **What**: Test each validation case: database storage without URL (error), OTLP tracing without feature (error), valid database config (passes), valid filesystem config (passes). Verify error messages are actionable.
- **Where**: `jacs/src/config/mod.rs` test module.

### Step 220. Update `jacs.config.schema.json` with all new fields

- **Why**: The JSON Schema must accept the new config fields so that schema validation does not reject valid configs.
- **What**: Add to `jacs.config.schema.json`: `jacs_database_url` (type: string, format: uri, optional). Add `observability` object with the full `ObservabilityConfig` schema (logs, metrics, tracing sub-objects). Ensure the schema validates both old configs (no new fields) and new configs (with new fields) correctly. Do NOT add any new required fields (backward compat).
- **Where**: `jacs/schemas/jacs.config.schema.json`.

### Step 221. Test: `test_config_schema_validation_with_new_fields`

- **Why**: Verify the schema accepts new fields and rejects invalid values.
- **What**: Validate a JSON config with `jacs_database_url` and `observability` fields against the schema. Verify it passes. Validate a config with `jacs_database_url: 123` (wrong type). Verify it fails with a helpful error. Validate an old-format config (no new fields). Verify it still passes.
- **Where**: `jacs/src/config/mod.rs` test module (uses `validate_config()` function).

### Steps 222-223. Backward Compatibility Regression Tests

- **Why**: Final safety net before Phase 3 is declared complete.
- **What**:
  - **Step 222**: Load every test config file in the repository (`jacs/tests/` directory, any `*.config.json` fixtures). Verify they all load without errors via `load_config_12factor()`. Verify default values are applied for missing fields (database_url = None, observability = None).
  - **Step 223**: Test env var override behavior: set `JACS_DEFAULT_STORAGE=fs` (old value), verify no regression. Set `JACS_DEFAULT_STORAGE=database` (new value), verify it's accepted. Set `JACS_DATABASE_URL=postgres://test`, verify it's loaded. Unset all, verify defaults hold.
- **Where**: `jacs/src/config/mod.rs` test module. Use `#[serial]`.

### Step 224. Add `JACS_MIGRATION_VERSION` tracking

- **Why**: Track which config schema version is in use for future migration tooling.
- **What**: Add `jacs_migration_version: Option<String>` to `Config` (default: "3" for Phase 3). Add `JACS_MIGRATION_VERSION` env var. In `load_config_12factor()`, after all overrides are applied, if `jacs_migration_version` is None, set it to the current version ("3"). Log the migration version at startup. This field is informational -- it does not gate any behavior in Phase 3 but provides a hook for future phases.
- **Where**: `jacs/src/config/mod.rs`.

### Step 225. Full regression suite

- **Why**: Phase 3 completion checkpoint.
- **What**: Run the complete test suite:
  - `cargo test` -- all default-feature tests pass.
  - `cargo test --features database` -- database feature tests pass.
  - `cargo test --features database,database-tests` -- integration tests pass (if DB available).
  - `cargo test --features otlp-tracing` -- tracing tests pass.
  - `cargo check --target wasm32-unknown-unknown` -- WASM compilation succeeds.
  - `cargo clippy --all-features -- -D warnings` -- no warnings.
  - Verify all 50 steps (176-225) have corresponding passing tests.
- **Where**: CI/terminal.

---

## Files Created/Modified

| File | Action | Description |
|------|--------|-------------|
| `jacs/src/config/mod.rs` | **Modified** | Add `JacsConfigProvider` trait, `EnvConfigProvider`, `Config: Clone` derive, `jacs_database_url` field, `jacs_migration_version` field, `JACS_DATABASE_URL` env override, `JACS_OBSERVABILITY_CONFIG` env override, `validate_config_combinations()`, security doc comments, backward compat tests |
| `jacs/src/config/runtime.rs` | **Created** | `RuntimeConfig` struct with `RwLock<Config>`, `read()`, `write()`, `update_observability()`, `snapshot()`, lock poisoning handling |
| `jacs/src/agent/mod.rs` | **Modified** | Add `config_provider: Option<Arc<dyn JacsConfigProvider>>` and `runtime_config: Option<Arc<RuntimeConfig>>` to `Agent`. Add `config_provider()`, `with_storage()`, `with_storage_and_database()` to `AgentBuilder`. Modify `build()` for provider merge and validation. Add `init_agent_from_provider()`, `init_agent_from_config()` convenience functions |
| `jacs/src/observability/mod.rs` | **Modified** | Add `reconfigure_observability()` function |
| `jacs/schemas/jacs.config.schema.json` | **Modified** | Add `jacs_database_url`, `jacs_migration_version`, and `observability` object schema |
| `jacs/examples/hai_config_provider.rs` | **Created** | Example/reference implementation of `JacsConfigProvider` for HAI pattern |
