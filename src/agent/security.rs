use crate::error;
use crate::storage::jenv::{get_env_var, get_required_env_var};
use log::info;

use std::env;
use std::error::Error;
use std::fs::{self, Permissions};
use std::path::Path;
use walkdir::WalkDir;

/// off by default
/// /// This environment variable determine if files are saved to the filesystem at all
/// if you are building something that passing data through to a database, you'd set this flag to 0 or False
const JACS_USE_SECURITY: &str = "JACS_USE_SECURITY";
const JACS_USE_FILESYSTEM: &str = "JACS_USE_FILESYSTEM";

/// this function attempts to detect executable files
/// if they should be there alert the user
/// /// it will move all exuctable documents in JACS_DATA_DIRECTORY a quarantine directory
pub fn check_data_directory() -> Result<(), Box<dyn Error>> {
    if !use_security() {
        info!("JACS_USE_SECURITY security is off");
        return Ok(());
    }
    if !use_fs_security() {
        info!("security is off because JACS_USE_FILESYSTEM is off");
        return Ok(());
    }
    let data_dir =
        get_required_env_var("JACS_DATA_DIRECTORY", true).expect("JACS_DATA_DIRECTORY must be set");
    let dir = Path::new(&data_dir);

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
    {
        if is_executable(entry.path()) {
            let _ = quarantine_file(entry.path());
        }
    }
    Ok(())
}

/// determine if the system is configured ot use security features
/// EXPERIMENTAL
pub fn use_security() -> bool {
    matches!(get_env_var(JACS_USE_SECURITY, true), Ok(Some(value)) if matches!(value.to_lowercase().as_str(), "true" | "1"))
}

pub fn use_fs_security() -> bool {
    matches!(get_env_var(JACS_USE_FILESYSTEM, true), Ok(Some(value)) if matches!(value.to_lowercase().as_str(), "true" | "1"))
}

#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::PermissionsExt;

#[cfg(not(target_os = "windows"))]
fn is_executable(path: &std::path::Path) -> bool {
    if !use_fs_security() {
        info!(
            "is_executable not possible because {} is off: {}",
            JACS_USE_FILESYSTEM,
            path.to_string_lossy()
        );
        return false;
    }

    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };

    // On Unix-like systems, check if any executable bits are set
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(target_os = "windows")]
fn is_executable(path: &std::path::Path) -> bool {
    if !use_fs_security() {
        info!(
            "is_executable not possible because JACS_USE_FILESYSTEM is off: {}",
            path.to_string_lossy()
        );
        return false;
    }

    // First, check the file extension
    if let Some(ext) = path.extension() {
        match ext.to_str().unwrap_or("").to_lowercase().as_str() {
            "exe" | "bat" | "cmd" | "ps1" => {
                let _ = quarantine_file(path)?;
            }
            _ => (),
        }
    }

    // check for the MZ header indicative of PE files
    // This requires reading the first two bytes of the file
    if let Ok(mut file) = std::fs::File::open(path) {
        let mut buffer = [0; 2];
        if std::io::Read::read(&mut file, &mut buffer).is_ok() {
            if buffer == [0x4D, 0x5A] {
                // MZ header in hex
                return true;
            }
        }
    }

    false
}

fn quarantine_file(file_path: &Path) -> Result<(), Box<dyn Error>> {
    if !use_fs_security() {
        info!(
            "is_executable not possible because JACS_USE_FILESYSTEM is off: {}",
            file_path.to_string_lossy()
        );
        return Ok(());
    }

    let data_dir =
        get_required_env_var("JACS_DATA_DIRECTORY", true).expect("JACS_DATA_DIRECTORY must be set");
    let mut quarantine_dir = Path::new(&data_dir);
    let binding = quarantine_dir.join("quarantine");
    quarantine_dir = &binding;

    if !quarantine_dir.exists() {
        fs::create_dir_all(quarantine_dir)?;
        let permissions = Permissions::from_mode(0o644);
        fs::set_permissions(quarantine_dir, permissions)?;
    }

    let file_name = match file_path.file_name() {
        Some(name) => name,
        None => {
            return Err(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid file path").into(),
            )
        }
    };
    let dest_path = quarantine_dir.join(file_name);
    error!(
        "security: moving {:?} to {:?} as it may be executable.",
        file_name, dest_path
    );
    // Move the file to the quarantine directory
    fs::rename(file_path, &dest_path)?;
    let file_permissions = Permissions::from_mode(0o644);
    fs::set_permissions(&dest_path, file_permissions)?;

    Ok(())
}
