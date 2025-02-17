// use futures_util::stream::stream::StreamExt;
use futures_executor::block_on;
use futures_util::StreamExt;
use log::debug;
use object_store::PutPayload;
use object_store::{
    aws::{AmazonS3, AmazonS3Builder},
    http::{HttpBuilder, HttpStore},
    local::LocalFileSystem,
    path::Path as ObjectPath,
    Error as ObjectStoreError, ObjectStore,
};
use std::sync::Arc;
use std::{env, str::FromStr};
use strum_macros::{AsRefStr, Display, EnumString};
use url::Url;

pub struct MultiStorage {
    aws: Option<Arc<AmazonS3>>,
    fs: Option<Arc<LocalFileSystem>>,
    hai_ai: Option<Arc<HttpStore>>,
    default_storage: StorageType,
    storages: Vec<Arc<dyn ObjectStore>>,
}

#[derive(Debug, AsRefStr, Display, EnumString)]
pub enum StorageType {
    #[strum(serialize = "aws")]
    AWS,
    #[strum(serialize = "fs")]
    FS,
    #[strum(serialize = "hai")]
    HAI,
}

impl MultiStorage {
    fn clean_path(path: &str) -> String {
        // Remove any ./ and multiple slashes
        path.replace("./", "").replace("//", "/")
        // path.to_string()
    }

    pub fn new(use_key_dir: Option<bool>) -> Result<Self, ObjectStoreError> {
        let mut _s3;
        let mut _http;
        let mut _local;
        let storage_type =
            env::var("JACS_DEFAULT_STORAGE").expect("JACS_DEFAULT_STORAGE must be set");
        let default_storage: StorageType =
            StorageType::from_str(&storage_type).expect("JACS_DEFAULT_STORAGE must be set");
        let mut storages: Vec<Arc<dyn ObjectStore>> = Vec::new();

        if env::var("JACS_ENABLE_AWS_STORAGE").is_ok() {
            let s3 = AmazonS3Builder::from_env()
                .with_bucket_name(env::var("JACS_ENABLE_AWS_BUCKET_NAME").expect(
                    "JACS_ENABLE_AWS_BUCKET_NAME mustbe set when JACS_ENABLE_AWS_STORAGE is set ",
                ))
                .with_allow_http(false) // Ensure HTTPS is used
                .build()?;
            let tmps3 = Arc::new(s3);
            _s3 = Some(tmps3.clone());
            storages.push(tmps3);
        } else {
            _s3 = None;
        }

        if env::var("JACS_ENABLE_HAI_STORAGE").is_ok() {
            let http_url = env::var("HAI_STORAGE_URL")
                .expect("HAI_STORAGE_URL must be set when JACS_ENABLE_HAI_STORAGE is enabled");
            let url_obj = Url::parse(&http_url).unwrap();
            let http = HttpBuilder::new().with_url(url_obj).build()?;
            let tmphttp = Arc::new(http);
            _http = Some(tmphttp.clone());
            storages.push(tmphttp);
        } else {
            _http = None;
        }

        if env::var("JACS_USE_FILESYSTEM").is_ok() {
            let local_path = if use_key_dir.unwrap_or(false) {
                env::var("JACS_KEY_DIRECTORY")
                    .expect("JACS_KEY_DIRECTORY must be set when using key directory")
            } else {
                env::var("JACS_DATA_DIRECTORY")
                    .expect("JACS_DATA_DIRECTORY must be set when JACS_USE_FILESYSTEM is enabled")
            };
            let local: LocalFileSystem = LocalFileSystem::new_with_prefix(local_path)?;
            let tmplocal = Arc::new(local);
            _local = Some(tmplocal.clone());
            storages.push(tmplocal);
        } else {
            _local = None;
        }

        if _local.is_none() && _http.is_none() && _s3.is_none() {
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
            default_storage: default_storage,
            storages: storages,
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

    fn get_read_storage(&self, preference: Option<StorageType>) -> Arc<dyn ObjectStore> {
        let selected = match preference {
            Some(pref) => pref,
            _ => {
                let pref: StorageType = {
                    if !self.fs.is_none() {
                        StorageType::FS
                    } else if !self.aws.is_none() {
                        StorageType::AWS
                    } else {
                        StorageType::HAI
                    }
                };
                pref
            }
        };

        match selected {
            StorageType::AWS => self.aws.clone().expect("aws storage not loaded"),
            StorageType::FS => self.fs.clone().expect("fielsystem storage not loaded"),
            StorageType::HAI => self.hai_ai.clone().expect("hai storage not loaded"),
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
