// use futures_util::stream::stream::StreamExt;
use crate::storage::jenv::get_required_env_var;
#[cfg(target_arch = "wasm32")]
use crate::time_utils;
use futures_executor::block_on;
use futures_util::StreamExt;
use object_store::{
    Error as ObjectStoreError, ObjectStore, PutPayload,
    aws::{AmazonS3, AmazonS3Builder},
    http::{HttpBuilder, HttpStore},
    local::LocalFileSystem,
    memory::InMemory,
    path::Path as ObjectPath,
};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use strum_macros::{AsRefStr, Display, EnumString};
use tracing::debug;
use url::Url;

pub mod jenv;

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

        let decoded = crate::crypt::base64_decode(&value)
            .map_err(|e| ObjectStoreError::Generic {
                store: "WebLocalStorage",
                source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())),
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

#[derive(Debug, Clone)]
pub struct MultiStorage {
    aws: Option<Arc<AmazonS3>>,
    fs: Option<Arc<LocalFileSystem>>,
    hai_ai: Option<Arc<HttpStore>>,
    memory: Option<Arc<InMemory>>,
    #[cfg(target_arch = "wasm32")]
    web_local: Option<Arc<WebLocalStorage>>,
    default_storage: StorageType,
    storages: Vec<Arc<dyn ObjectStore>>,
}

#[derive(Debug, AsRefStr, Display, EnumString, Clone, PartialEq)]
pub enum StorageType {
    #[strum(serialize = "aws")]
    AWS,
    #[strum(serialize = "fs")]
    FS,
    #[strum(serialize = "hai")]
    HAI,
    #[strum(serialize = "memory")]
    Memory,
    #[cfg(target_arch = "wasm32")]
    #[strum(serialize = "local")]
    WebLocal,
}

impl MultiStorage {
    pub fn clean_path(path: &str) -> String {
        // Remove any leading slashes to ensure consistent path format
        // and convert absolute paths to relative
        let cleaned = path.trim_start_matches('/');

        // If path is empty after cleaning, return "." to indicate current directory
        if cleaned.is_empty() {
            ".".to_string()
        } else {
            cleaned.to_string()
        }
    }

    pub fn default_new() -> Result<Self, ObjectStoreError> {
        let storage_type = "fs".to_string();
        Self::new(storage_type)
    }

    pub fn new(storage_type: String) -> Result<Self, ObjectStoreError> {
        let absolute_path = std::env::current_dir().unwrap();
        Self::_new(storage_type, absolute_path)
    }

    pub fn _new(storage_type: String, absolute_path: PathBuf) -> Result<Self, ObjectStoreError> {
        let mut _s3;
        let mut _http;
        let mut _local;
        let mut _memory: Option<Arc<InMemory>>;

        let default_storage: StorageType = StorageType::from_str(&storage_type)
            .unwrap_or_else(|_| panic!("storage_type {} is not known", storage_type));

        let mut storages: Vec<Arc<dyn ObjectStore>> = Vec::new();

        // Check AWS storage
        if default_storage == StorageType::AWS {
            let bucket_name = get_required_env_var("JACS_ENABLE_AWS_BUCKET_NAME", true).expect(
                "JACS_ENABLE_AWS_BUCKET_NAME must be set when JACS_ENABLE_AWS_STORAGE is set",
            );
            let s3 = AmazonS3Builder::from_env()
                .with_bucket_name(bucket_name)
                .with_allow_http(false)
                .build()?;
            let tmps3 = Arc::new(s3);
            _s3 = Some(tmps3.clone());
            storages.push(tmps3);
        } else {
            _s3 = None;
        }

        // Check HAI storage
        if default_storage == StorageType::HAI {
            let http_url = get_required_env_var("HAI_STORAGE_URL", true)
                .expect("HAI_STORAGE_URL must be set when JACS_ENABLE_HAI_STORAGE is enabled");
            let url_obj = Url::parse(&http_url).unwrap();
            let http = HttpBuilder::new().with_url(url_obj).build()?;
            let tmphttp = Arc::new(http);
            _http = Some(tmphttp.clone());
            storages.push(tmphttp);
        } else {
            _http = None;
        }

        // Check filesystem storage
        if default_storage == StorageType::FS {
            // get the curent local absolute path
            let local: LocalFileSystem = LocalFileSystem::new_with_prefix(absolute_path)?;
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
        if _local.is_none() && _http.is_none() && _s3.is_none() && web_local.is_none() {
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
            hai_ai: _http,
            memory,
            #[cfg(target_arch = "wasm32")]
            web_local,
            default_storage,
            storages,
        })
    }

    pub fn save_file(&self, path: &str, contents: &[u8]) -> Result<(), ObjectStoreError> {
        let clean = Self::clean_path(path);
        let object_path = ObjectPath::parse(&clean)?;
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

    pub fn get_file(
        &self,
        path: &str,
        preference: Option<StorageType>,
    ) -> Result<Vec<u8>, ObjectStoreError> {
        let clean = Self::clean_path(path);
        let object_path = ObjectPath::parse(&clean)?;
        let storage = self.get_read_storage(preference);
        let get_result = block_on(storage.get(&object_path))?;
        let bytes = block_on(get_result.bytes())?;
        Ok(bytes.to_vec())
    }

    pub fn file_exists(
        &self,
        path: &str,
        preference: Option<StorageType>,
    ) -> Result<bool, ObjectStoreError> {
        let clean = Self::clean_path(path);
        let object_path = ObjectPath::parse(&clean)?;
        let storage = self.get_read_storage(preference);

        // --- Debugging Start ---
        let current_process_cwd =
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("unknown_cwd"));
        debug!(
            "[MultiStorage::file_exists DEBUG]\n  - Input Path: '{}'\n  - Clean Path: '{}'\n  - Object Path: '{}'\n  - Process CWD: {:?}\n  - Attempting storage.head...",
            path, clean, object_path, current_process_cwd
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

    pub fn list(
        &self,
        prefix: &str,
        preference: Option<StorageType>,
    ) -> Result<Vec<String>, ObjectStoreError> {
        let mut file_list = Vec::new();
        let object_store = self.get_read_storage(preference);
        let clean = Self::clean_path(prefix);
        let prefix_path = ObjectPath::parse(&clean)?;
        let mut list_stream = object_store.list(Some(&prefix_path));

        while let Some(meta) = block_on(list_stream.next()) {
            let meta = meta?;
            debug!("Name: {}, size: {}", meta.location, meta.size);
            file_list.push(meta.location.to_string());
        }

        Ok(file_list)
    }

    pub fn rename_file(&self, from: &str, to: &str) -> Result<(), ObjectStoreError> {
        // First get the contents of the original file
        let contents = self.get_file(from, None)?;

        // Save contents to new location
        self.save_file(to, &contents)?;

        // Delete the original file
        for storage in &self.storages {
            let from_path = ObjectPath::parse(Self::clean_path(from))?;
            if let Err(e) = block_on(storage.delete(&from_path)) {
                // Log error but continue if file doesn't exist or other errors
                debug!("Error deleting original file during rename: {:?}", e);
            }
        }

        Ok(())
    }

    fn get_read_storage(&self, preference: Option<StorageType>) -> Arc<dyn ObjectStore> {
        let selected = match preference {
            Some(pref) => pref,
            _ => self.default_storage.clone(),
        };

        match selected {
            StorageType::AWS => self.aws.clone().expect("aws storage not loaded"),
            StorageType::FS => self.fs.clone().expect("filesystem storage not loaded"),
            StorageType::HAI => self.hai_ai.clone().expect("hai storage not loaded"),
            StorageType::Memory => self.memory.clone().expect("memory storage not loaded"),
            #[cfg(target_arch = "wasm32")]
            StorageType::WebLocal => self
                .web_local
                .clone()
                .expect("web local storage not loaded"),
        }
    }
}

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;

/// Trait for document storage operations
/// This trait defines methods for storing, retrieving, and querying JACS documents
pub trait StorageDocumentTraits {
    // Basic document operations
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>>;
    fn get_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>>;
    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>>;
    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, Box<dyn Error>>;
    fn document_exists(&self, key: &str) -> Result<bool, Box<dyn Error>>;

    // Advanced query operations (placeholders for now)
    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>>;
    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>>;
    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>>;
    fn merge_documents(
        &self,
        doc_id: &str,
        v1: &str,
        v2: &str,
    ) -> Result<JACSDocument, Box<dyn Error>>;

    // Bulk operations
    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<Box<dyn Error>>>;
    fn get_documents(&self, keys: Vec<String>) -> Result<Vec<JACSDocument>, Vec<Box<dyn Error>>>;
}

/// Extension to MultiStorage to add document caching support
pub struct CachedMultiStorage {
    storage: MultiStorage,
    cache: Arc<Mutex<HashMap<String, JACSDocument>>>,
    cache_enabled: bool,
}

impl CachedMultiStorage {
    pub fn new(storage: MultiStorage, cache_enabled: bool) -> Self {
        Self {
            storage,
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_enabled,
        }
    }

    pub fn clear_cache(&self) {
        if self.cache_enabled
            && let Ok(mut cache) = self.cache.lock()
        {
            cache.clear();
        }
    }
}

impl StorageDocumentTraits for MultiStorage {
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>> {
        let key = doc.getkey();
        let path = format!("documents/{}.json", key);
        let json_string = serde_json::to_string_pretty(&doc.value)?;
        self.save_file(&path, json_string.as_bytes())
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    fn get_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let path = format!("documents/{}.json", key);
        let contents = self.get_file(&path, None)?;
        let json_string = String::from_utf8(contents)?;
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

    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
        // First get the document before removing
        let doc = self.get_document(key)?;

        // Archive the document
        let old_path = format!("documents/{}.json", key);
        let archive_path = format!("documents/archive/{}.json", key);

        // Read the content
        let contents = self.get_file(&old_path, None)?;

        // Save to archive
        self.save_file(&archive_path, &contents)?;

        // Note: We don't have a delete method in object_store, so we'll just move to archive
        // In a real implementation, we might want to add a delete method to MultiStorage

        Ok(doc)
    }

    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let search_prefix = if prefix.is_empty() {
            "documents/".to_string()
        } else {
            format!("documents/{}", prefix)
        };

        let files = self.list(&search_prefix, None)?;

        // Extract document keys from file paths
        let mut document_keys = Vec::new();
        for file in files {
            if file.ends_with(".json") && !file.contains("/archive/") {
                // Extract key from path like "documents/id:version.json"
                if let Some(filename) = file.strip_prefix("documents/")
                    && let Some(key) = filename.strip_suffix(".json")
                {
                    document_keys.push(key.to_string());
                }
            }
        }

        Ok(document_keys)
    }

    fn document_exists(&self, key: &str) -> Result<bool, Box<dyn Error>> {
        let path = format!("documents/{}.json", key);
        self.file_exists(&path, None)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
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

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
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

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>> {
        let versions = self.get_document_versions(document_id)?;

        if versions.is_empty() {
            return Err(JacsError::DocumentError(format!("No documents found with ID: {}", document_id)).into());
        }

        // For now, return the last one in the list
        // TODO: In the future, implement proper version tree traversal
        // by checking jacsPreviousVersion field
        let latest_key = versions.last().unwrap();
        self.get_document(latest_key)
    }

    fn merge_documents(
        &self,
        _doc_id: &str,
        _v1: &str,
        _v2: &str,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        // Placeholder implementation
        // TODO: Implement proper document merging logic
        Err("Document merging not yet implemented: feature pending".into())
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
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

    fn get_documents(&self, keys: Vec<String>) -> Result<Vec<JACSDocument>, Vec<Box<dyn Error>>> {
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
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>> {
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

    fn get_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
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

    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>> {
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
    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, Box<dyn Error>> {
        self.storage.list_documents(prefix)
    }

    fn document_exists(&self, key: &str) -> Result<bool, Box<dyn Error>> {
        // Check cache first
        if self.cache_enabled
            && let Ok(cache) = self.cache.lock()
            && cache.contains_key(key)
        {
            return Ok(true);
        }
        self.storage.document_exists(key)
    }

    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        self.storage.get_documents_by_agent(agent_id)
    }

    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>> {
        self.storage.get_document_versions(document_id)
    }

    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>> {
        self.storage.get_latest_document(document_id)
    }

    fn merge_documents(
        &self,
        doc_id: &str,
        v1: &str,
        v2: &str,
    ) -> Result<JACSDocument, Box<dyn Error>> {
        self.storage.merge_documents(doc_id, v1, v2)
    }

    fn store_documents(&self, docs: Vec<JACSDocument>) -> Result<Vec<String>, Vec<Box<dyn Error>>> {
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

    fn get_documents(&self, keys: Vec<String>) -> Result<Vec<JACSDocument>, Vec<Box<dyn Error>>> {
        self.storage.get_documents(keys)
    }
}
