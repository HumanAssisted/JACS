//! Storage backends for JACS documents.
//!
//! This module provides the [`MultiStorage`] abstraction layer and the
//! [`StorageDocumentTraits`] base trait that all storage backends implement.
//!
//! # Built-in Backends
//!
//! | Backend | Type | Feature Flag | Description |
//! |---------|------|-------------|-------------|
//! | Filesystem | `fs` | (always) | Documents as JSON files on disk. Default. |
//! | Memory | `memory` | (always) | In-memory store for testing. |
//! | AWS S3 | `aws` | (always) | Object storage via `object_store` crate. |
//! | SQLite (sync) | `rusqlite` | `sqlite` (default) | Local indexed storage via rusqlite. |
//! | SQLite (async) | `sqlite` | `sqlx-sqlite` | Async indexed storage via sqlx + tokio. |
//!
//! # External Backend Crates
//!
//! These backends have been extracted to standalone crates:
//!
//! | Crate | Install | Description |
//! |-------|---------|-------------|
//! | [`jacs-postgresql`](https://crates.io/crates/jacs-postgresql) | `cargo add jacs-postgresql` | PostgreSQL with pgvector search |
//! | [`jacs-surrealdb`](https://crates.io/crates/jacs-surrealdb) | `cargo add jacs-surrealdb` | SurrealDB multi-model backend |
//! | [`jacs-duckdb`](https://crates.io/crates/jacs-duckdb) | `cargo add jacs-duckdb` | DuckDB analytical queries |
//! | [`jacs-redb`](https://crates.io/crates/jacs-redb) | `cargo add jacs-redb` | Redb embedded key-value store |
//!
//! External crates implement [`StorageDocumentTraits`], [`DatabaseDocumentTraits`],
//! and [`SearchProvider`](crate::search::SearchProvider).
//!
//! # Trait Hierarchy
//!
//! ```text
//! StorageDocumentTraits        (base -- CRUD, list, versions, bulk)
//!     +-- DatabaseDocumentTraits   (indexed queries -- type, field, agent, pagination)
//!         +-- SearchProvider       (fulltext/vector/hybrid search -- in crate::search)
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use jacs::storage::{MultiStorage, StorageType, StorageDocumentTraits};
//!
//! // Default: filesystem storage rooted in the current directory
//! let storage = MultiStorage::default_new()?;
//!
//! // Or specify a backend type
//! let memory_storage = MultiStorage::new("memory".to_string())?;
//!
//! // With SQLite (requires `sqlite` feature, enabled by default)
//! #[cfg(feature = "sqlite")]
//! {
//!     use jacs::storage::RusqliteStorage;
//!     // RusqliteStorage provides indexed queries + FTS5 search
//! }
//! ```

// use futures_util::stream::stream::StreamExt;
use crate::storage::jenv::get_required_env_var;
#[cfg(target_arch = "wasm32")]
use crate::time_utils;
use futures_executor::block_on;
use futures_util::StreamExt;
use object_store::{
    Error as ObjectStoreError, ObjectStore, PutPayload,
    aws::{AmazonS3, AmazonS3Builder},
    local::LocalFileSystem,
    memory::InMemory,
    path::Path as ObjectPath,
};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use strum_macros::{AsRefStr, Display, EnumString};
use tracing::debug;

pub mod jenv;

// Database trait definitions are always available (no feature gate) so external
// storage backend crates (jacs-postgresql, jacs-surrealdb, etc.) can implement
// them without pulling in any storage-specific dependencies.
#[cfg(not(target_arch = "wasm32"))]
pub mod database_traits;
#[cfg(not(target_arch = "wasm32"))]
pub use database_traits::DatabaseDocumentTraits;

#[cfg(all(not(target_arch = "wasm32"), feature = "sqlx-sqlite"))]
pub mod sqlite;
#[cfg(all(not(target_arch = "wasm32"), feature = "sqlx-sqlite"))]
pub use sqlite::SqliteStorage;

#[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
pub mod rusqlite_storage;
#[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
pub use rusqlite_storage::RusqliteStorage;
#[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
pub use rusqlite_storage::SqliteDocumentService;

// Extracted storage backends (now standalone crates):
// - PostgreSQL: `jacs-postgresql`
// - SurrealDB:  `jacs-surrealdb`
// - DuckDB:     `jacs-duckdb`
// - Redb:       `jacs-redb`

#[cfg(target_arch = "wasm32")]
use web_sys::window;

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct WebLocalStorage {
    storage: web_sys::Storage,
}

#[cfg(target_arch = "wasm32")]
impl WebLocalStorage {
    pub fn new() -> Result<Self, ObjectStoreError> {
        let storage = window()
            .ok_or_else(|| ObjectStoreError::Generic {
                store: "WebLocalStorage",
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No global window exists",
                )),
            })?
            .local_storage()
            .map_err(|e| ObjectStoreError::Generic {
                store: "WebLocalStorage",
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.as_string().unwrap_or_default(),
                )),
            })?
            .ok_or_else(|| ObjectStoreError::Generic {
                store: "WebLocalStorage",
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "localStorage is not available",
                )),
            })?;

        Ok(Self { storage })
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait]
impl ObjectStore for WebLocalStorage {
    async fn put(&self, location: &ObjectPath, bytes: PutPayload) -> Result<(), ObjectStoreError> {
        let data = bytes.into_vec().await?;
        let encoded = crate::crypt::base64_encode(&data);
        self.storage
            .set_item(location.as_ref(), &encoded)
            .map_err(|e| ObjectStoreError::Generic {
                store: "WebLocalStorage",
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.as_string().unwrap_or_default(),
                )),
            })?;
        Ok(())
    }

    async fn get(&self, location: &ObjectPath) -> Result<GetResult, ObjectStoreError> {
        let value = self
            .storage
            .get_item(location.as_ref())
            .map_err(|e| ObjectStoreError::Generic {
                store: "WebLocalStorage",
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.as_string().unwrap_or_default(),
                )),
            })?
            .ok_or_else(|| ObjectStoreError::NotFound {
                path: location.to_string(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Key not found in localStorage",
                )),
            })?;

        let decoded =
            crate::crypt::base64_decode(&value).map_err(|e| ObjectStoreError::Generic {
                store: "WebLocalStorage",
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                )),
            })?;

        Ok(GetResult::Stream(Box::pin(futures_util::stream::once(
            async move { Ok(bytes::Bytes::from(decoded)) },
        ))))
    }

    fn list(
        &self,
        prefix: Option<&ObjectPath>,
    ) -> BoxStream<'_, Result<ObjectMeta, ObjectStoreError>> {
        let mut items = Vec::new();
        for i in 0..self.storage.length().unwrap_or(0) {
            if let Ok(Some(key)) = self.storage.key(i) {
                if let Some(prefix) = prefix {
                    if !key.starts_with(prefix.as_ref()) {
                        continue;
                    }
                }
                if let Ok(Some(value)) = self.storage.get_item(&key) {
                    items.push(Ok(ObjectMeta {
                        location: ObjectPath::parse(&key).unwrap(),
                        last_modified: time_utils::now_utc(),
                        size: value.len(),
                    }));
                }
            }
        }
        Box::pin(futures_util::stream::iter(items))
    }
}

/// Multi-backend storage abstraction that delegates to filesystem, in-memory, S3, or SQLite.
///
/// You pick **one** backend at construction via a storage-type string (`"fs"`, `"memory"`,
/// `"aws"`, `"sqlite"`, `"rusqlite"`, or `"local"` on wasm32). All file operations are
/// then routed to that backend through the [`ObjectStore`] trait.
#[derive(Debug, Clone)]
pub struct MultiStorage {
    aws: Option<Arc<AmazonS3>>,
    fs: Option<Arc<LocalFileSystem>>,
    memory: Option<Arc<InMemory>>,
    #[cfg(target_arch = "wasm32")]
    web_local: Option<Arc<WebLocalStorage>>,
    default_storage: StorageType,
    #[cfg(not(target_arch = "wasm32"))]
    filesystem_base_dir: Option<PathBuf>,
    storages: Vec<Arc<dyn ObjectStore>>,
}

/// Storage backend type selector for `MultiStorage`.
///
/// Core variants (AWS, FS, Memory, WebLocal) are always available.
/// SQLite variants require their respective feature flags.
///
/// PostgreSQL, SurrealDB, DuckDB, and Redb have been extracted to
/// standalone crates (`jacs-postgresql`, `jacs-surrealdb`, `jacs-duckdb`,
/// `jacs-redb`) and are no longer part of jacs core.
#[derive(Debug, AsRefStr, Display, EnumString, Clone, PartialEq)]
pub enum StorageType {
    #[strum(serialize = "aws")]
    AWS,
    #[strum(serialize = "fs")]
    FS,
    #[strum(serialize = "memory")]
    Memory,
    #[cfg(target_arch = "wasm32")]
    #[strum(serialize = "local")]
    WebLocal,
    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlx-sqlite"))]
    #[strum(serialize = "sqlite")]
    Sqlite,
    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
    #[strum(serialize = "rusqlite")]
    Rusqlite,
}

impl MultiStorage {
    /// Strip leading slashes from a path for non-filesystem backends. Returns `"."` if empty.
    pub fn clean_path(path: &str) -> String {
        // Non-filesystem backends use object-store paths, which are always relative.
        let cleaned = path.trim_start_matches('/');

        // If path is empty after cleaning, return "." to indicate current directory
        if cleaned.is_empty() {
            ".".to_string()
        } else {
            cleaned.to_string()
        }
    }

    /// Returns the filesystem base directory, if this storage uses a filesystem backend.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn root(&self) -> Option<&std::path::Path> {
        self.filesystem_base_dir.as_deref()
    }

    /// Create a new `MultiStorage` with the default filesystem backend.
    pub fn default_new() -> Result<Self, ObjectStoreError> {
        let storage_type = "fs".to_string();
        Self::new(storage_type)
    }

    /// Create a new `MultiStorage` with the given backend type, rooted at the process CWD.
    pub fn new(storage_type: String) -> Result<Self, ObjectStoreError> {
        let absolute_path = std::env::current_dir().unwrap();
        Self::_new(storage_type, absolute_path)
    }

    /// Create a new `MultiStorage` with an explicit base directory for filesystem storage.
    pub fn _new(storage_type: String, absolute_path: PathBuf) -> Result<Self, ObjectStoreError> {
        let mut _s3;
        let mut _local;
        let mut _memory: Option<Arc<InMemory>>;

        let default_storage: StorageType =
            StorageType::from_str(&storage_type).map_err(|_| ObjectStoreError::Generic {
                store: "MultiStorage",
                source: Box::new(std::io::Error::other(format!(
                    "Unknown storage type '{}'. Supported types: fs, memory, aws{}",
                    storage_type,
                    if cfg!(all(not(target_arch = "wasm32"), feature = "sqlite")) {
                        ", rusqlite, sqlite"
                    } else {
                        ""
                    }
                ))),
            })?;

        let mut storages: Vec<Arc<dyn ObjectStore>> = Vec::new();

        // Check AWS storage
        if default_storage == StorageType::AWS {
            let bucket_name = get_required_env_var("JACS_ENABLE_AWS_BUCKET_NAME", true).expect(
                "JACS_ENABLE_AWS_BUCKET_NAME must be set when JACS_ENABLE_AWS_STORAGE is set",
            );
            let allow_http = std::env::var("AWS_ALLOW_HTTP")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            let s3 = AmazonS3Builder::from_env()
                .with_bucket_name(bucket_name)
                .with_allow_http(allow_http)
                .build()?;
            let tmps3 = Arc::new(s3);
            _s3 = Some(tmps3.clone());
            storages.push(tmps3);
        } else {
            _s3 = None;
        }

        let is_fs = default_storage == StorageType::FS;

        // Check filesystem storage
        if is_fs {
            // Use the filesystem root so callers can mix relative paths (resolved below
            // against the startup CWD) and true absolute paths from config files.
            let local: LocalFileSystem = LocalFileSystem::new();
            let tmplocal = Arc::new(local);
            _local = Some(tmplocal.clone());
            storages.push(tmplocal);
        } else {
            _local = None;
        }

        // Add memory storage initialization
        let memory = if default_storage == StorageType::Memory {
            let mem = InMemory::new();
            let tmp_mem = Arc::new(mem);
            storages.push(tmp_mem.clone());
            Some(tmp_mem)
        } else {
            None
        };

        #[cfg(target_arch = "wasm32")]
        let web_local = if default_storage == StorageType::WebLocal {
            let storage = WebLocalStorage::new()?;
            let tmp_storage = Arc::new(storage);
            storages.push(tmp_storage.clone());
            Some(tmp_storage)
        } else {
            None
        };

        #[cfg(target_arch = "wasm32")]
        if _local.is_none() && _s3.is_none() && web_local.is_none() {
            return Err(ObjectStoreError::Generic {
                store: "MultiStorage",
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "At least one storage option must be enabled",
                )),
            });
        }

        Ok(Self {
            aws: _s3,
            fs: _local,
            memory,
            #[cfg(target_arch = "wasm32")]
            web_local,
            default_storage,
            #[cfg(not(target_arch = "wasm32"))]
            filesystem_base_dir: is_fs.then_some(absolute_path),
            storages,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn object_path(&self, path: &str) -> Result<ObjectPath, ObjectStoreError> {
        if self.default_storage == StorageType::FS {
            let raw = PathBuf::from(path);
            let absolute = if raw.is_absolute() {
                raw
            } else {
                self.filesystem_base_dir
                    .as_ref()
                    .map(|base| base.join(raw))
                    .ok_or_else(|| ObjectStoreError::Generic {
                        store: "MultiStorage",
                        source: Box::new(std::io::Error::other(
                            "filesystem base directory missing for fs storage",
                        )),
                    })?
            };
            return ObjectPath::from_absolute_path(absolute).map_err(ObjectStoreError::from);
        }

        ObjectPath::parse(Self::clean_path(path)).map_err(ObjectStoreError::from)
    }

    #[cfg(target_arch = "wasm32")]
    fn object_path(&self, path: &str) -> Result<ObjectPath, ObjectStoreError> {
        ObjectPath::parse(Self::clean_path(path)).map_err(ObjectStoreError::from)
    }

    /// Write `contents` to `path` in all configured storage backends.
    pub fn save_file(&self, path: &str, contents: &[u8]) -> Result<(), ObjectStoreError> {
        let object_path = self.object_path(path)?;
        let mut errors = Vec::new();
        let contents_vec = contents.to_vec();
        let contents_payload = PutPayload::from(contents_vec);

        for storage in &self.storages {
            if let Err(e) = block_on(storage.put(&object_path, contents_payload.clone())) {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ObjectStoreError::Generic {
                store: "MultiStorage",
                source: Box::new(std::io::Error::other(format!(
                    "Failed to save to some storages: {:?}",
                    errors
                ))),
            })
        }
    }

    /// Read a file from the preferred (or default) storage backend.
    pub fn get_file(
        &self,
        path: &str,
        preference: Option<StorageType>,
    ) -> Result<Vec<u8>, ObjectStoreError> {
        let object_path = self.object_path(path)?;
        let storage = self.get_read_storage(preference)?;
        let get_result = block_on(storage.get(&object_path))?;
        let bytes = block_on(get_result.bytes())?;
        Ok(bytes.to_vec())
    }

    /// Check whether a file exists in the preferred (or default) storage backend.
    pub fn file_exists(
        &self,
        path: &str,
        preference: Option<StorageType>,
    ) -> Result<bool, ObjectStoreError> {
        let object_path = self.object_path(path)?;
        let storage = self.get_read_storage(preference)?;

        // --- Debugging Start ---
        let current_process_cwd =
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("unknown_cwd"));
        debug!(
            "[MultiStorage::file_exists DEBUG]\n  - Input Path: '{}'\n  - Object Path: '{}'\n  - Process CWD: {:?}\n  - Attempting storage.head...",
            path, object_path, current_process_cwd
        );
        // --- Debugging End ---

        match block_on(storage.head(&object_path)) {
            Ok(_) => {
                debug!("  - storage.head: OK (Found)"); // Log success
                Ok(true)
            }
            Err(ObjectStoreError::NotFound { path: _, source: _ }) => {
                debug!("  - storage.head: Err (NotFound)"); // Log not found
                Ok(false)
            }
            Err(e) => {
                debug!("  - storage.head: Err ({:?})", e); // Log other errors
                Err(e)
            }
        }
    }

    /// List all files under `prefix` in the preferred (or default) storage backend.
    pub fn list(
        &self,
        prefix: &str,
        preference: Option<StorageType>,
    ) -> Result<Vec<String>, ObjectStoreError> {
        let mut file_list = Vec::new();
        let object_store = self.get_read_storage(preference)?;
        let prefix_path = self.object_path(prefix)?;
        let mut list_stream = object_store.list(Some(&prefix_path));

        while let Some(meta) = block_on(list_stream.next()) {
            let meta = meta?;
            debug!("Name: {}, size: {}", meta.location, meta.size);
            file_list.push(meta.location.to_string());
        }

        Ok(file_list)
    }

    /// Rename (move) a file across all configured storage backends.
    pub fn rename_file(&self, from: &str, to: &str) -> Result<(), ObjectStoreError> {
        let from_path = self.object_path(from)?;
        let to_path = self.object_path(to)?;
        let mut errors = Vec::new();

        for storage in &self.storages {
            if let Err(e) = block_on(storage.rename(&from_path, &to_path)) {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ObjectStoreError::Generic {
                store: "MultiStorage",
                source: Box::new(std::io::Error::other(format!(
                    "Failed to rename in some storages: {:?}",
                    errors
                ))),
            })
        }
    }

    fn get_read_storage(
        &self,
        preference: Option<StorageType>,
    ) -> Result<Arc<dyn ObjectStore>, ObjectStoreError> {
        let selected = match preference {
            Some(pref) => pref,
            _ => self.default_storage.clone(),
        };

        match selected {
            StorageType::AWS => self
                .aws
                .clone()
                .map(|a| a as Arc<dyn ObjectStore>)
                .ok_or_else(|| ObjectStoreError::Generic {
                    store: "MultiStorage",
                    source: Box::new(std::io::Error::other("AWS storage not loaded")),
                }),
            StorageType::FS => self
                .fs
                .clone()
                .map(|f| f as Arc<dyn ObjectStore>)
                .ok_or_else(|| ObjectStoreError::Generic {
                    store: "MultiStorage",
                    source: Box::new(std::io::Error::other("Filesystem storage not loaded")),
                }),
            StorageType::Memory => self
                .memory
                .clone()
                .map(|m| m as Arc<dyn ObjectStore>)
                .ok_or_else(|| ObjectStoreError::Generic {
                    store: "MultiStorage",
                    source: Box::new(std::io::Error::other("Memory storage not loaded")),
                }),
            #[cfg(target_arch = "wasm32")]
            StorageType::WebLocal => {
                self.web_local
                    .clone()
                    .ok_or_else(|| ObjectStoreError::Generic {
                        store: "MultiStorage",
                        source: Box::new(std::io::Error::other("Web local storage not loaded")),
                    })
            }
            #[cfg(all(not(target_arch = "wasm32"), feature = "sqlx-sqlite"))]
            StorageType::Sqlite => Err(ObjectStoreError::Generic {
                store: "MultiStorage",
                source: Box::new(std::io::Error::other(
                    "SQLite storage does not use ObjectStore. Use SqliteStorage or DocumentService directly.",
                )),
            }),
            #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
            StorageType::Rusqlite => Err(ObjectStoreError::Generic {
                store: "MultiStorage",
                source: Box::new(std::io::Error::other(
                    "Rusqlite storage does not use ObjectStore. Use SqliteDocumentService directly.",
                )),
            }),
            // SurrealDB, DuckDB, Redb have been extracted to standalone crates.
        }
    }
}

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use serde_json::Value;
use std::collections::HashMap;
/// Base trait for document storage operations (Level 1 in the trait hierarchy).
///
/// Provides CRUD, listing, versioning, and bulk operations for JACS documents.
/// All storage backends (filesystem, in-memory, S3, SQLite, and extracted crates)
/// implement this trait.
///
/// # Trait Hierarchy
///
/// ```text
/// StorageDocumentTraits        (base -- CRUD, list, versions, bulk)
///     └── DatabaseDocumentTraits   (indexed queries -- type, field, agent, pagination)
///         └── SearchProvider       (fulltext/vector/hybrid search -- defined in search/)
/// ```
///
/// External backend crates (`jacs-postgresql`, `jacs-surrealdb`, `jacs-duckdb`,
/// `jacs-redb`) implement all three levels. Built-in backends (filesystem,
/// in-memory, S3) implement only `StorageDocumentTraits`.
pub trait StorageDocumentTraits: Send + Sync {
    // Basic document operations
    fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError>;
    fn get_document(&self, key: &str) -> Result<JACSDocument, JacsError>;
    fn remove_document(&self, key: &str) -> Result<JACSDocument, JacsError>;
    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, JacsError>;
    fn document_exists(&self, key: &str) -> Result<bool, JacsError>;

    // Advanced query operations (placeholders for now)
    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, JacsError>;
    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, JacsError>;
    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, JacsError>;
    fn merge_documents(&self, doc_id: &str, v1: &str, v2: &str) -> Result<JACSDocument, JacsError>;

    // Bulk operations
    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<JacsError>>;
    fn get_documents(&self, keys: Vec<String>) -> Result<Vec<JACSDocument>, Vec<JacsError>>;
}

/// Caching wrapper over [`MultiStorage`] that keeps recently-accessed documents in an
/// in-memory `HashMap`. Thread-safe via `Arc<Mutex<...>>`. Disable caching by passing
/// `cache_enabled: false` at construction.
pub struct CachedMultiStorage {
    storage: MultiStorage,
    cache: Arc<Mutex<HashMap<String, JACSDocument>>>,
    cache_enabled: bool,
}

impl CachedMultiStorage {
    /// Wrap an existing `MultiStorage` with an optional document cache.
    pub fn new(storage: MultiStorage, cache_enabled: bool) -> Self {
        Self {
            storage,
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_enabled,
        }
    }

    /// Evict all entries from the document cache (no-op if caching is disabled).
    pub fn clear_cache(&self) {
        if self.cache_enabled
            && let Ok(mut cache) = self.cache.lock()
        {
            cache.clear();
        }
    }
}

impl StorageDocumentTraits for MultiStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError> {
        let key = doc.getkey();
        let path = format!("documents/{}.json", key);
        let json_string = serde_json::to_string_pretty(&doc.value)?;
        self.save_file(&path, json_string.as_bytes())
            .map_err(|e| JacsError::StorageError(e.to_string()))
    }

    fn get_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let path = format!("documents/{}.json", key);
        let contents = self
            .get_file(&path, None)
            .map_err(|e| JacsError::StorageError(e.to_string()))?;
        let json_string = String::from_utf8(contents)
            .map_err(|e| JacsError::StorageError(format!("Invalid UTF-8 in document: {}", e)))?;
        let value: Value = serde_json::from_str(&json_string)?;

        // Extract required fields from the JSON value
        let id = value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .ok_or("Document missing required field: jacsId")?
            .to_string();
        let version = value
            .get("jacsVersion")
            .and_then(|v| v.as_str())
            .ok_or("Document missing required field: jacsVersion")?
            .to_string();
        let jacs_type = value
            .get("jacsType")
            .and_then(|v| v.as_str())
            .ok_or("Document missing required field: jacsType")?
            .to_string();

        Ok(JACSDocument {
            id,
            version,
            value,
            jacs_type,
        })
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        // First get the document before removing
        let doc = self.get_document(key)?;

        // Archive the document
        let old_path = format!("documents/{}.json", key);
        let archive_path = format!("documents/archive/{}.json", key);

        // Move the object so the primary key no longer resolves after removal.
        self.rename_file(&old_path, &archive_path)
            .map_err(|e| JacsError::StorageError(e.to_string()))?;

        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, JacsError> {
        let search_prefix = if prefix.is_empty() {
            "documents/".to_string()
        } else {
            format!("documents/{}", prefix)
        };

        let files = self
            .list(&search_prefix, None)
            .map_err(|e| JacsError::StorageError(e.to_string()))?;

        // Extract document keys from file paths.
        // object_store returns paths relative to the store root (e.g.
        // "path/to/workspace/documents/id:version.json" for LocalFileSystem
        // rooted at "/"). We match on "documents/" anywhere in the path.
        let mut document_keys = Vec::new();
        for file in files {
            if file.ends_with(".json") && !file.contains("/archive/") {
                if let Some(pos) = file.rfind("documents/") {
                    let after_prefix = &file[pos + "documents/".len()..];
                    if let Some(key) = after_prefix.strip_suffix(".json") {
                        // Reject keys with path separators to prevent traversal
                        if !key.contains('/') && !key.contains('\\') {
                            document_keys.push(key.to_string());
                        }
                    }
                }
            }
        }

        Ok(document_keys)
    }

    fn document_exists(&self, key: &str) -> Result<bool, JacsError> {
        let path = format!("documents/{}.json", key);
        self.file_exists(&path, None)
            .map_err(|e| JacsError::StorageError(e.to_string()))
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, JacsError> {
        // List all documents and filter by agent_id
        let all_docs = self.list_documents("")?;
        let mut agent_docs = Vec::new();

        for doc_key in all_docs {
            // Document keys are in format "id:version", extract the id
            if let Some(id) = doc_key.split(':').next()
                && id == agent_id
            {
                agent_docs.push(doc_key);
            }
        }

        Ok(agent_docs)
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, JacsError> {
        // List all documents with this ID prefix
        let all_docs = self.list_documents("")?;
        let mut versions = Vec::new();

        for doc_key in all_docs {
            if doc_key.starts_with(&format!("{}:", document_id)) {
                versions.push(doc_key);
            }
        }

        Ok(versions)
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        let versions = self.get_document_versions(document_id)?;

        if versions.is_empty() {
            return Err(JacsError::DocumentError(format!(
                "No documents found with ID: {}",
                document_id
            )));
        }

        // Select deterministically by latest `jacsVersionDate` (RFC3339), falling back to key.
        let mut latest_doc: Option<JACSDocument> = None;
        let mut latest_date = String::new();
        let mut latest_key = String::new();

        for key in versions {
            let doc = self.get_document(&key)?;
            let date = doc
                .value
                .get("jacsVersionDate")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if latest_doc.is_none()
                || date > latest_date
                || (date == latest_date && key > latest_key)
            {
                latest_date = date;
                latest_key = key;
                latest_doc = Some(doc);
            }
        }

        latest_doc.ok_or_else(|| {
            JacsError::DocumentError(format!("No documents found with ID: {}", document_id))
        })
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, JacsError> {
        // Placeholder implementation
        // TODO: Implement proper document merging logic
        Err("Document merging not yet implemented: feature pending".into())
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<JacsError>> {
        let mut stored_keys = Vec::new();
        let mut errors = Vec::new();

        for doc in docs {
            let key = doc.getkey();
            match self.store_document(&doc) {
                Ok(_) => stored_keys.push(key),
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            Ok(stored_keys)
        } else {
            Err(errors)
        }
    }

    fn get_documents(&self, keys: Vec<String>) -> Result<Vec<JACSDocument>, Vec<JacsError>> {
        let mut documents = Vec::new();
        let mut errors = Vec::new();

        for key in keys {
            match self.get_document(&key) {
                Ok(doc) => documents.push(doc),
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            Ok(documents)
        } else {
            Err(errors)
        }
    }
}

impl StorageDocumentTraits for CachedMultiStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError> {
        // Store in underlying storage
        self.storage.store_document(doc)?;

        // Update cache if enabled
        if self.cache_enabled
            && let Ok(mut cache) = self.cache.lock()
        {
            cache.insert(doc.getkey(), doc.clone());
        }

        Ok(())
    }

    fn get_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        // Check cache first if enabled
        if self.cache_enabled
            && let Ok(cache) = self.cache.lock()
            && let Some(doc) = cache.get(key)
        {
            return Ok(doc.clone());
        }

        // Not in cache, get from storage
        let doc = self.storage.get_document(key)?;

        // Update cache if enabled
        if self.cache_enabled
            && let Ok(mut cache) = self.cache.lock()
        {
            cache.insert(key.to_string(), doc.clone());
        }

        Ok(doc)
    }

    fn remove_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let doc = self.storage.remove_document(key)?;

        // Remove from cache if enabled
        if self.cache_enabled
            && let Ok(mut cache) = self.cache.lock()
        {
            cache.remove(key);
        }

        Ok(doc)
    }

    // Delegate other methods to underlying storage
    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, JacsError> {
        self.storage.list_documents(prefix)
    }

    fn document_exists(&self, key: &str) -> Result<bool, JacsError> {
        // Check cache first
        if self.cache_enabled
            && let Ok(cache) = self.cache.lock()
            && cache.contains_key(key)
        {
            return Ok(true);
        }
        self.storage.document_exists(key)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, JacsError> {
        self.storage.get_documents_by_agent(agent_id)
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, JacsError> {
        self.storage.get_document_versions(document_id)
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        self.storage.get_latest_document(document_id)
    }

    fn merge_documents(&self, doc_id: &str, v1: &str, v2: &str) -> Result<JACSDocument, JacsError> {
        self.storage.merge_documents(doc_id, v1, v2)
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<JacsError>> {
        let result = self.storage.store_documents(docs.clone())?;

        // Update cache if enabled
        if self.cache_enabled
            && let Ok(mut cache) = self.cache.lock()
        {
            for doc in docs {
                cache.insert(doc.getkey(), doc);
            }
        }

        Ok(result)
    }

    fn get_documents(&self, keys: Vec<String>) -> Result<Vec<JACSDocument>, Vec<JacsError>> {
        self.storage.get_documents(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::MultiStorage;
    use super::StorageDocumentTraits;
    use crate::agent::document::JACSDocument;
    use serde_json::json;
    use serial_test::serial;
    use std::path::PathBuf;

    struct CwdGuard {
        original: PathBuf,
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.original).expect("restore cwd");
        }
    }

    fn chdir_guard(target: &std::path::Path) -> CwdGuard {
        let original = std::env::current_dir().expect("current cwd");
        std::env::set_current_dir(target).expect("set cwd");
        CwdGuard { original }
    }

    #[test]
    fn rename_file_moves_content_and_removes_source() {
        let storage = MultiStorage::new("memory".to_string()).expect("memory storage");
        storage
            .save_file("source/path.txt", b"hello world")
            .expect("write source");

        storage
            .rename_file("source/path.txt", "dest/path.txt")
            .expect("rename should succeed");

        let moved = storage
            .get_file("dest/path.txt", None)
            .expect("destination file should exist");
        assert_eq!(moved, b"hello world");

        let source_exists = storage
            .file_exists("source/path.txt", None)
            .expect("source exists check");
        assert!(!source_exists, "source file should not exist after rename");
    }

    #[test]
    fn rename_file_accepts_paths_with_leading_slashes() {
        let storage = MultiStorage::new("memory".to_string()).expect("memory storage");
        storage
            .save_file("/source/leading.txt", b"slash-test")
            .expect("write source with leading slash");

        storage
            .rename_file("/source/leading.txt", "/dest/leading.txt")
            .expect("rename should succeed");

        let moved = storage
            .get_file("dest/leading.txt", None)
            .expect("destination file should exist");
        assert_eq!(moved, b"slash-test");
    }

    #[test]
    fn rename_file_missing_source_returns_error() {
        let storage = MultiStorage::new("memory".to_string()).expect("memory storage");
        let result = storage.rename_file("missing/source.txt", "dest/path.txt");
        assert!(result.is_err(), "renaming a missing source should fail");
    }

    #[test]
    #[serial]
    fn fs_storage_supports_absolute_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _cwd = chdir_guard(temp.path());
        let storage = MultiStorage::new("fs".to_string()).expect("fs storage");
        let absolute_path = temp.path().join("nested").join("absolute.txt");

        storage
            .save_file(absolute_path.to_string_lossy().as_ref(), b"absolute")
            .expect("save absolute path");

        assert_eq!(
            std::fs::read(&absolute_path).expect("read saved absolute file"),
            b"absolute"
        );
        assert_eq!(
            storage
                .get_file(absolute_path.to_string_lossy().as_ref(), None)
                .expect("load absolute path"),
            b"absolute"
        );
    }

    #[test]
    #[serial]
    fn fs_storage_resolves_relative_paths_against_creation_cwd() {
        let home = tempfile::tempdir().expect("home tempdir");
        let elsewhere = tempfile::tempdir().expect("elsewhere tempdir");
        let _cwd = chdir_guard(home.path());
        let storage = MultiStorage::new("fs".to_string()).expect("fs storage");

        std::env::set_current_dir(elsewhere.path()).expect("move cwd after storage creation");
        storage
            .save_file("relative/path.txt", b"stable")
            .expect("save relative path");

        assert_eq!(
            std::fs::read(home.path().join("relative").join("path.txt"))
                .expect("read file under original cwd"),
            b"stable"
        );
        assert!(
            !elsewhere.path().join("relative").join("path.txt").exists(),
            "relative writes must stay rooted to the storage creation cwd"
        );
    }

    #[test]
    fn hai_storage_type_is_rejected() {
        use super::StorageType;
        use std::str::FromStr;
        assert!(
            StorageType::from_str("hai").is_err(),
            "\"hai\" should not be accepted as a storage type"
        );
    }

    #[test]
    fn remove_document_removes_primary_copy() {
        let storage = MultiStorage::new("memory".to_string()).expect("memory storage");
        let doc = JACSDocument {
            id: "rm-doc".to_string(),
            version: "v1".to_string(),
            jacs_type: "message".to_string(),
            value: json!({
                "jacsId": "rm-doc",
                "jacsVersion": "v1",
                "jacsType": "message",
                "jacsLevel": "raw",
                "content": {"ok": true}
            }),
        };

        storage.store_document(&doc).expect("store document");
        assert!(
            storage
                .document_exists("rm-doc:v1")
                .expect("exists before remove"),
            "document should exist before remove_document"
        );

        storage
            .remove_document("rm-doc:v1")
            .expect("remove_document should succeed");

        assert!(
            !storage
                .document_exists("rm-doc:v1")
                .expect("exists after remove"),
            "document should not remain at primary location after remove_document"
        );
    }
}
