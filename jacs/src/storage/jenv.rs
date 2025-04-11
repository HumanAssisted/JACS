#[cfg(not(target_arch = "wasm32"))]
use std::env;

#[cfg(target_arch = "wasm32")]
use {wasm_bindgen::prelude::*, web_sys::window};

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

#[cfg(not(target_arch = "wasm32"))]
pub fn set_env_var(key: &str, value: &str) -> Result<(), EnvError> {
    unsafe {
        env::set_var(key, value);
    }
    Ok(())
}
