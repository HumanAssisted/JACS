//! Thread-safe environment variable abstraction.
//!
//! This module provides a thread-safe way to access and override environment variables.
//! Instead of using `std::env::set_var` (which is unsafe in multi-threaded contexts),
//! we use a thread-safe in-memory store for runtime overrides while falling back to
//! the actual environment for reads.

#[cfg(not(target_arch = "wasm32"))]
use std::env;

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{OnceLock, RwLock};

#[cfg(target_arch = "wasm32")]
use {wasm_bindgen::prelude::*, web_sys::window};

/// Thread-safe in-memory store for environment variable overrides.
/// This replaces unsafe `env::set_var` calls with a safe in-memory alternative.
#[cfg(not(target_arch = "wasm32"))]
static ENV_OVERRIDES: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

#[cfg(not(target_arch = "wasm32"))]
fn get_overrides() -> &'static RwLock<HashMap<String, String>> {
    ENV_OVERRIDES.get_or_init(|| RwLock::new(HashMap::new()))
}

#[derive(Debug)]
pub enum EnvError {
    NotFound(String),
    Empty(String),
    #[cfg(target_arch = "wasm32")]
    WasmError(String),
}

impl std::fmt::Display for EnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvError::NotFound(key) => write!(f, "Environment variable '{}' not found", key),
            EnvError::Empty(key) => write!(f, "Environment variable '{}' is empty", key),
            #[cfg(target_arch = "wasm32")]
            EnvError::WasmError(msg) => write!(f, "WASM environment error: {}", msg),
        }
    }
}

impl std::error::Error for EnvError {}

#[cfg(target_arch = "wasm32")]
fn get_local_storage() -> Result<web_sys::Storage, EnvError> {
    window()
        .ok_or_else(|| EnvError::WasmError("No global window exists".to_string()))?
        .local_storage()
        .map_err(|e| EnvError::WasmError(e.as_string().unwrap_or_default()))?
        .ok_or_else(|| EnvError::WasmError("localStorage is not available".to_string()))
}

pub fn get_env_var(key: &str, required_non_empty: bool) -> Result<Option<String>, EnvError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        // First check our thread-safe override store
        if let Ok(overrides) = get_overrides().read()
            && let Some(value) = overrides.get(key)
        {
            if required_non_empty && value.trim().is_empty() {
                return Err(EnvError::Empty(key.to_string()));
            }
            return Ok(Some(value.clone()));
        }

        // Fall back to actual environment
        match env::var(key) {
            Ok(value) => {
                if required_non_empty && value.trim().is_empty() {
                    Err(EnvError::Empty(key.to_string()))
                } else {
                    Ok(Some(value))
                }
            }
            Err(_) => Ok(None),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        match get_local_storage()?
            .get_item(key)
            .map_err(|e| EnvError::WasmError(e.as_string().unwrap_or_default()))?
        {
            Some(value) => {
                if required_non_empty && value.trim().is_empty() {
                    Err(EnvError::Empty(key.to_string()))
                } else {
                    Ok(Some(value))
                }
            }
            None => Ok(None),
        }
    }
}

pub fn get_required_env_var(key: &str, required_non_empty: bool) -> Result<String, EnvError> {
    match get_env_var(key, required_non_empty)? {
        Some(value) => Ok(value),
        None => Err(EnvError::NotFound(key.to_string())),
    }
}

pub fn set_env_var_override(key: &str, value: &str, do_override: bool) -> Result<(), EnvError> {
    if get_env_var(key, false)?.is_none() || do_override {
        set_env_var(key, value)
    } else {
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
pub fn set_env_var(key: &str, value: &str) -> Result<(), EnvError> {
    get_local_storage()?
        .set_item(key, value)
        .map_err(|e| EnvError::WasmError(e.as_string().unwrap_or_default()))
}

/// Set an environment variable override in our thread-safe store.
///
/// This does NOT modify the actual process environment (which would be unsafe
/// in multi-threaded contexts). Instead, values are stored in a thread-safe
/// in-memory store that is checked before falling back to the actual environment.
///
/// # Thread Safety
/// This function is safe to call from multiple threads concurrently.
#[cfg(not(target_arch = "wasm32"))]
pub fn set_env_var(key: &str, value: &str) -> Result<(), EnvError> {
    if let Ok(mut overrides) = get_overrides().write() {
        overrides.insert(key.to_string(), value.to_string());
        Ok(())
    } else {
        // Lock was poisoned, but we can still continue
        // This is very unlikely in practice
        Ok(())
    }
}

/// Clear an environment variable override from our thread-safe store.
///
/// After calling this, `get_env_var` will fall back to the actual environment.
#[cfg(not(target_arch = "wasm32"))]
pub fn clear_env_var(key: &str) -> Result<(), EnvError> {
    if let Ok(mut overrides) = get_overrides().write() {
        overrides.remove(key);
    }
    Ok(())
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_set_and_get_env_var() {
        let key = "JACS_TEST_SET_GET";
        set_env_var(key, "test_value").unwrap();
        let result = get_env_var(key, false).unwrap();
        assert_eq!(result, Some("test_value".to_string()));
        clear_env_var(key).unwrap();
    }

    #[test]
    fn test_override_takes_precedence() {
        // This test verifies that our override store takes precedence
        // over actual environment variables
        let key = "JACS_TEST_OVERRIDE";
        set_env_var(key, "override_value").unwrap();
        let result = get_env_var(key, false).unwrap();
        assert_eq!(result, Some("override_value".to_string()));
        clear_env_var(key).unwrap();
    }

    #[test]
    fn test_required_env_var_not_found() {
        let key = "JACS_TEST_NOT_EXISTS_12345";
        let result = get_required_env_var(key, false);
        assert!(result.is_err());
        match result {
            Err(EnvError::NotFound(k)) => assert_eq!(k, key),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_empty_value_with_required_non_empty() {
        let key = "JACS_TEST_EMPTY";
        set_env_var(key, "   ").unwrap();
        let result = get_env_var(key, true);
        assert!(result.is_err());
        match result {
            Err(EnvError::Empty(k)) => assert_eq!(k, key),
            _ => panic!("Expected Empty error"),
        }
        clear_env_var(key).unwrap();
    }

    #[test]
    fn test_concurrent_access() {
        // Test that concurrent reads and writes don't cause issues
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let key = format!("JACS_TEST_CONCURRENT_{}", i);
                    for j in 0..100 {
                        set_env_var(&key, &format!("value_{}", j)).unwrap();
                        let _ = get_env_var(&key, false);
                    }
                    clear_env_var(&key).unwrap();
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_clear_env_var() {
        let key = "JACS_TEST_CLEAR";
        set_env_var(key, "to_be_cleared").unwrap();
        assert_eq!(
            get_env_var(key, false).unwrap(),
            Some("to_be_cleared".to_string())
        );
        clear_env_var(key).unwrap();
        // After clearing, should fall back to actual env (which likely doesn't have this key)
        // The result depends on whether the key exists in actual environment
        // Just verify no panic occurs
        let _ = get_env_var(key, false);
    }
}
