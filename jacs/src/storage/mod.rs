// use futures_util::stream::stream::StreamExt;
use crate::storage::jenv::{get_env_var, get_required_env_var};
use futures_executor::block_on;
use futures_util::StreamExt;
use log::debug;
use object_store::PutPayload;
use object_store::{
    Error as ObjectStoreError, ObjectStore,
    aws::{AmazonS3, AmazonS3Builder},
    http::{HttpBuilder, HttpStore},
    local::LocalFileSystem,
    memory::InMemory,
    path::Path as ObjectPath,
};
use std::str::FromStr;
use std::sync::Arc;
use strum_macros::{AsRefStr, Display, EnumString};
use url::Url;

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
        let encoded = base64::encode(&data);
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

        let decoded = base64::decode(value).map_err(|e| ObjectStoreError::Generic {
            store: "WebLocalStorage",
            source: Box::new(e),
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
                        last_modified: chrono::Utc::now(),
                        size: value.len(),
                    }));
                }
            }
        }
        Box::pin(futures_util::stream::iter(items))
    }
}

pub mod jenv;

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
    fn clean_path(path: &str) -> String {
        // Remove any ./ and multiple slashes
        path.replace("./", "").replace("//", "/")
    }

    pub fn new(use_key_dir: Option<bool>) -> Result<Self, ObjectStoreError> {
        let storage_type = get_required_env_var("JACS_DEFAULT_STORAGE", true)
            .expect("JACS_DEFAULT_STORAGE must be set");
        let data_directory = get_required_env_var("JACS_DATA_DIRECTORY", true)
            .expect("JACS_DATA_DIRECTORY must be set");
        let key_directory = get_required_env_var("JACS_KEY_DIRECTORY", true)
            .expect("JACS_KEY_DIRECTORY must be set");
        return Self::known_new(storage_type, data_directory, key_directory, use_key_dir);
    }

    pub fn known_new(
        storage_type: String,
        data_directory: String,
        key_directory: String,
        use_key_dir: Option<bool>,
    ) -> Result<Self, ObjectStoreError> {
        let mut _s3;
        let mut _http;
        let mut _local;
        let mut _memory: Option<Arc<InMemory>>;

        let default_storage: StorageType = StorageType::from_str(&storage_type)
            .expect(&format!("storage_type {} is not known", storage_type));

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
            let local_path = if use_key_dir.unwrap_or(false) {
                key_directory
            } else {
                data_directory
            };

            // Convert to absolute path and create if needed
            let absolute_path = std::path::PathBuf::from(&local_path)
                .canonicalize()
                .unwrap_or_else(|_| {
                    std::fs::create_dir_all(&local_path).expect("Failed to create directory");
                    std::path::PathBuf::from(&local_path)
                        .canonicalize()
                        .expect("Failed to get canonical path after directory creation")
                });

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
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to save to some storages: {:?}", errors),
                )),
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

        match block_on(storage.head(&object_path)) {
            Ok(_) => Ok(true),
            Err(ObjectStoreError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
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
            let from_path = ObjectPath::parse(&Self::clean_path(from))?;
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

// #[tokio::main]
// async fn main() -> Result<(), ObjectStoreError> {
//     let storage = MultiStorage::new()?;

//     // Save a file
//     storage.save_file("example.txt", b"Hello, world!").await?;

//     // Get a file
//     let contents = storage.get_file("example.txt").await?;
//     println!("File contents: {}", String::from_utf8_lossy(&contents));

//     Ok(())
// }
