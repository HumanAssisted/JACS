pub mod create;
pub mod document;
use crate::error::JacsError;
use crate::storage::MultiStorage;
use std::path::Path;

/// Read a password from a file, checking that the file has secure permissions.
///
/// On Unix, rejects files that are group-readable or world-readable (mode must
/// be 0600 or 0400). On non-Unix platforms, reads without permission checks.
///
/// Returns the password string (with trailing newlines stripped).
pub fn read_password_file_checked(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to read password file '{}': {}", path.display(), e))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "Password file '{}' has insecure permissions (mode {:04o}). \
                File must not be group-readable or world-readable. \
                Fix with: chmod 600 '{}'",
                path.display(),
                mode,
                path.display(),
            ));
        }
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read password file '{}': {}", path.display(), e))?;
    let password = raw.trim_end_matches(|c| c == '\n' || c == '\r');
    if password.is_empty() {
        return Err(format!("Password file '{}' is empty.", path.display()));
    }
    Ok(password.to_string())
}

pub fn default_set_file_list(
    filename: Option<&String>,
    directory: Option<&String>,
    attachments: Option<&str>,
) -> Result<Vec<String>, JacsError> {
    let storage: MultiStorage = get_storage_default_for_cli()?;
    set_file_list(&storage, filename, directory, attachments)
}

fn set_file_list(
    storage: &MultiStorage,
    filename: Option<&String>,
    directory: Option<&String>,
    attachments: Option<&str>,
) -> Result<Vec<String>, JacsError> {
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

pub fn get_storage_default_for_cli() -> Result<MultiStorage, JacsError> {
    let storage: Option<MultiStorage> =
        Some(MultiStorage::default_new().expect("Failed to initialize storage"));
    if let Some(storage) = storage {
        Ok(storage)
    } else {
        Err("Storage not initialized".into())
    }
}
