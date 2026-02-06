# Phase 3: Runtime Configuration (Steps 176-225)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 176-225
**Summary**: Implement the JacsConfigProvider trait, runtime configuration system, AgentBuilder integration, HAI integration pattern, and observability runtime configuration.

---

## Phase 3A: JacsConfigProvider Trait (Steps 176-195)

**Step 176.** Write test `test_jacs_config_provider_trait` (mock).

**Step 177.** Write test `test_config_provider_override_chain` (defaults -> config -> env -> provider).

**Step 178.** Define `JacsConfigProvider` trait in `src/config/mod.rs` with `get_config()`, `get_storage_type()`, `get_database_url()`, `get_data_directory()`, `get_key_directory()`, `get_observability_config()`.

**Step 179.** Default impl of `JacsConfigProvider` for `Config`.

**Step 180.** Write test `test_default_config_provider`.

**Step 181.** Create `EnvConfigProvider` impl.

**Step 182.** Write test `test_env_config_provider`.

**Step 183.** Add `config_provider: Option<Arc<dyn JacsConfigProvider>>` to `Agent`.

**Step 184.** Add `config_provider()` to `AgentBuilder` (accepts `Arc<dyn JacsConfigProvider>`).

**Step 185.** Modify `AgentBuilder::build()` to use provider if set, fallback to existing config.

**Step 186.** Write test `test_agent_builder_with_config_provider`.

**Step 187.** Add `jacs_database_url: Option<String>` to `Config`.

**Step 188.** Add `database_url` to `ConfigBuilder`.

**Step 189.** Add `JACS_DATABASE_URL` to `apply_env_overrides()` and `check_env_vars()`.

**Step 190.** Update `Config::merge()` and `Config::Display` (redacted URL).

**Step 191.** Write test `test_config_database_url_12factor`.

**Step 192.** Create `src/config/runtime.rs`: `RuntimeConfig` with `RwLock<Config>`, mutation methods. Handle lock poisoning with proper errors.

**Step 193.** Write test `test_runtime_config_mutation`.

**Step 194-195.** Backward compatibility tests: old configs still load, missing fields default correctly.

---

## Phase 3B: HAI Integration Pattern (Steps 196-210)

**Step 196.** Write test `test_hai_config_provider` simulating HAI's pattern.

**Step 197.** Create `HaiConfigProvider` example struct (documentation/example).

**Step 198.** Write test replicating `hai_signing::init_from_env()` pattern.

**Step 199.** Add `init_agent_from_provider()` convenience function.

**Step 200.** Write test `test_init_agent_from_provider`.

**Step 201.** Add `init_agent_from_config()` convenience function.

**Step 202.** Write test `test_init_agent_from_config`.

**Step 203.** Document security constraint: keys MUST load from secure locations only.

**Step 204.** Add validation in `AgentBuilder::build()`: if storage=Database, keys still from filesystem.

**Step 205.** Write test `test_database_storage_keys_still_from_filesystem`.

**Step 206.** Add `with_storage()` to `AgentBuilder`.

**Step 207.** Write test `test_agent_builder_with_storage`.

**Step 208.** Add `with_storage_and_database()` (cfg-gated).

**Step 209.** Write test `test_agent_builder_with_database`.

**Step 210.** Run all tests.

---

## Phase 3C: Observability Runtime Config (Steps 211-225)

**Step 211.** Write test `test_observability_runtime_reconfiguration`.

**Step 212.** Add `reconfigure_observability()` in `src/observability/mod.rs`.

**Step 213.** Write test `test_observability_toggle_at_runtime`.

**Step 214.** Add `ObservabilityConfig` to `JacsConfigProvider` and `RuntimeConfig`.

**Step 215.** Write test `test_runtime_config_observability`.

**Step 216.** Add `JACS_OBSERVABILITY_CONFIG` env var.

**Step 217.** Write test `test_observability_config_from_env`.

**Step 218.** Config validation for db + observability combinations.

**Step 219.** Write test `test_config_validation_complete`.

**Step 220.** Update `jacs.config.schema.json` with all new fields.

**Step 221.** Write test `test_config_schema_validation_with_new_fields`.

**Step 222-223.** Backward compatibility tests (old configs, missing fields, env overrides).

**Step 224.** Add `JACS_MIGRATION_VERSION` tracking.

**Step 225.** Full regression suite.
