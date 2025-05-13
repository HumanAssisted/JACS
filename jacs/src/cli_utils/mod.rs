pub mod create;
pub mod document;
use crate::storage::MultiStorage;
use std::error::Error;

fn set_file_list(
    storage: &MultiStorage,
    filename: Option<&String>,
    directory: Option<&String>,
    attachments: Option<&String>,
) -> Result<Vec<String>, Box<dyn Error>> {
    if let Some(file) = filename {
        // If filename is provided, return it as a single item list.
        // The caller will attempt fs::read_to_string on this local path.
        Ok(vec![file.clone()])
    } else if let Some(dir) = directory {
        // If directory is provided, list .json files within it using storage.
        let prefix = if dir.ends_with('/') {
            dir.clone()
        } else {
            format!("{}/", dir)
        };
        // Use storage.list to get files from the specified storage location
        let files = storage.list(&prefix, None)?;
        // Filter for .json files as originally intended for directory processing
        Ok(files.into_iter().filter(|f| f.ends_with(".json")).collect())
    } else if attachments.is_some() {
        // If only attachments are provided, the loop should run once without reading files.
        // Return an empty list; the calling loop handles creating "{}"
        Ok(Vec::new())
    } else {
        Err("You must specify either a filename, a directory, or attachments.".into())
    }
}

fn get_storage_default_for_cli() -> Result<MultiStorage, Box<dyn Error>> {
    let mut storage: Option<MultiStorage> =
        Some(MultiStorage::default_new().expect("Failed to initialize storage"));
    if let Some(storage) = storage {
        Ok(storage)
    } else {
        Err("Storage not initialized".into())
    }
}
